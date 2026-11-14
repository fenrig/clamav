/*
 * Native-messaging bridge for the ClamAV Thunderbird/Firefox extensions.
 *
 * The browser protocol uses a little-endian uint32 length followed by a
 * UTF-8 JSON object.  ClamD scanning uses the local Unix-socket FILDES
 * protocol; clamscan is used only when the daemon is unavailable.
 */

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include "quarantine.h"
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define OUTPUT_LIMIT (1024 * 1024)

#ifndef CLAMAV_SCANNER_NO_MAIN
static int read_all(void *buffer, size_t size)
{
    size_t offset = 0;
    ssize_t count;

    while (offset < size) {
        count = fread((unsigned char *)buffer + offset, 1, size - offset, stdin);
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return 1;
}

static int write_all(const void *buffer, size_t size)
{
    size_t offset = 0;
    ssize_t count;

    while (offset < size) {
        count = fwrite((const unsigned char *)buffer + offset, 1, size - offset, stdout);
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return fflush(stdout) == 0;
}

static int send_json(struct json_object *object)
{
    const char *text = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    unsigned int length = (unsigned int)strlen(text);
    unsigned char header[4];

    if ((size_t)length != strlen(text))
        return 0;
    header[0] = (unsigned char)(length & 0xffU);
    header[1] = (unsigned char)((length >> 8) & 0xffU);
    header[2] = (unsigned char)((length >> 16) & 0xffU);
    header[3] = (unsigned char)((length >> 24) & 0xffU);
    return write_all(header, sizeof(header)) && write_all(text, length);
}
#endif

static struct json_object *failure(const char *message, const char *sha256)
{
    struct json_object *result = json_object_new_object();
    json_object_object_add(result, "success", json_object_new_boolean(0));
    json_object_object_add(result, "infected", json_object_new_boolean(0));
    json_object_object_add(result, "message", json_object_new_string(message));
    if (sha256 != NULL)
        json_object_object_add(result, "sha256", json_object_new_string(sha256));
    return result;
}

static int sha256_fd(int fd, char output[65])
{
    unsigned char buffer[65536];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    EVP_MD_CTX *context;
    FILE *file;
    size_t count;
    unsigned int i;

    if (lseek(fd, 0, SEEK_SET) < 0)
        return 0;
    file = fdopen(dup(fd), "rb");
    if (file == NULL)
        return 0;
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        if (context != NULL)
            EVP_MD_CTX_free(context);
        fclose(file);
        return 0;
    }
    while ((count = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        if (EVP_DigestUpdate(context, buffer, count) != 1) {
            EVP_MD_CTX_free(context);
            fclose(file);
            return 0;
        }
    }
    if (ferror(file) || EVP_DigestFinal_ex(context, digest, &digest_length) != 1) {
        EVP_MD_CTX_free(context);
        fclose(file);
        return 0;
    }
    EVP_MD_CTX_free(context);
    fclose(file);
    for (i = 0; i < digest_length; ++i)
        sprintf(output + (i * 2), "%02x", digest[i]);
    output[digest_length * 2] = '\0';
    if (lseek(fd, 0, SEEK_SET) < 0)
        return 0;
    return digest_length == 32;
}

static int send_socket_data(int sockfd, const void *data, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)data;
    ssize_t count;

    while (length != 0) {
        count = send(sockfd, bytes, length, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        bytes += count;
        length -= (size_t)count;
    }
    return 1;
}

static int clamd_socket_path(char path[sizeof(((struct sockaddr_un *)0)->sun_path)])
{
    const char *environment_path = getenv("CLAMAV_CLAMD_SOCKET");
    const char *config_paths[] = { "/etc/clamav/clamd.conf", "/etc/clamd.conf", NULL };
    FILE *config;
    char line[512];
    char *value;
    size_t length;
    int i;

    if (environment_path != NULL && environment_path[0] != '\0') {
        if (strlen(environment_path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
            return 0;
        strcpy(path, environment_path);
        return 1;
    }
    for (i = 0; config_paths[i] != NULL; ++i) {
        config = fopen(config_paths[i], "r");
        if (config == NULL)
            continue;
        while (fgets(line, sizeof(line), config) != NULL) {
            value = line;
            while (*value == ' ' || *value == '\t')
                ++value;
            if (strncmp(value, "LocalSocket", 11) != 0
                    || (value[11] != ' ' && value[11] != '\t'))
                continue;
            value += 11;
            while (*value == ' ' || *value == '\t')
                ++value;
            length = strcspn(value, "\r\n \t");
            if (length == 0 || length >= sizeof(((struct sockaddr_un *)0)->sun_path))
                continue;
            memcpy(path, value, length);
            path[length] = '\0';
            fclose(config);
            return 1;
        }
        fclose(config);
    }
    strcpy(path, "/run/clamav/clamd.ctl");
    return 1;
}

static int read_clamd_reply(int sockfd, char **reply)
{
    char buffer[4096];
    size_t length = 0;
    ssize_t count;

    *reply = NULL;
    while (length + 1 < sizeof(buffer)) {
        count = recv(sockfd, buffer + length, sizeof(buffer) - length - 1, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            break;
        length += (size_t)count;
        if (memchr(buffer, '\n', length) != NULL || memchr(buffer, '\0', length) != NULL)
            break;
    }
    if (length == 0)
        return 0;
    buffer[length] = '\0';
    *reply = strdup(buffer);
    return *reply != NULL;
}

static int scan_with_clamd(int fd, char **reply)
{
    struct sockaddr_un address;
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *control;
    unsigned char control_buffer[CMSG_SPACE(sizeof(int))];
    char dummy = 0;
    char command[] = "zFILDES";
    char socket_path[sizeof(address.sun_path)];
    int sockfd;
    int connect_result;

    if (!clamd_socket_path(socket_path))
        return -1;
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, socket_path);
    connect_result = connect(sockfd, (struct sockaddr *)&address, sizeof(address));
    if (connect_result != 0 || !send_socket_data(sockfd, command, sizeof(command))) {
        close(sockfd);
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(sockfd);
        return -1;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = &dummy;
    iov.iov_len = 1;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control_buffer;
    message.msg_controllen = CMSG_LEN(sizeof(int));
    control = CMSG_FIRSTHDR(&message);
    control->cmsg_len = CMSG_LEN(sizeof(int));
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(control) = fd;
    if (sendmsg(sockfd, &message, 0) < 0 || !read_clamd_reply(sockfd, reply)) {
        close(sockfd);
        return -1;
    }
    close(sockfd);
    return strstr(*reply, "FOUND") != NULL ? 1 : (strstr(*reply, "OK") != NULL ? 0 : 2);
}

static int append_output(char **output, size_t *length, const char *data, size_t count)
{
    char *replacement;
    size_t accepted = count;

    if (*length >= OUTPUT_LIMIT)
        return 1;
    if (accepted > OUTPUT_LIMIT - *length)
        accepted = OUTPUT_LIMIT - *length;
    replacement = (char *)realloc(*output, *length + accepted + 1);
    if (replacement == NULL)
        return 0;
    memcpy(replacement + *length, data, accepted);
    *length += accepted;
    replacement[*length] = '\0';
    *output = replacement;
    return 1;
}

static int run_command(char *const argv[], char **output)
{
    int pipefd[2];
    pid_t child;
    int status;
    char buffer[4096];
    ssize_t count;
    size_t length = 0;

    *output = NULL;
    if (pipe(pipefd) != 0)
        return -1;
    child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    while ((count = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
        if (!append_output(output, &length, buffer, (size_t)count)) {
            close(pipefd[0]);
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            free(*output);
            *output = NULL;
            return -1;
        }
    }
    close(pipefd[0]);
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) {
        free(*output);
        *output = NULL;
        return -1;
    }
    return WEXITSTATUS(status);
}

static char *replace_text(const char *text, const char *needle, const char *replacement)
{
    const char *position;
    char *result;
    size_t text_length, needle_length, replacement_length, count = 0;
    size_t result_length, source_offset = 0, output_offset = 0;

    if (needle[0] == '\0')
        return strdup(text);
    needle_length = strlen(needle);
    replacement_length = strlen(replacement);
    text_length = strlen(text);
    position = text;
    while ((position = strstr(position, needle)) != NULL) {
        ++count;
        position += needle_length;
    }
    if (replacement_length >= needle_length)
        result_length = text_length + count * (replacement_length - needle_length);
    else
        result_length = text_length - count * (needle_length - replacement_length);
    result = (char *)malloc(result_length + 1);
    if (result == NULL)
        return NULL;
    position = text;
    while ((position = strstr(position, needle)) != NULL) {
        size_t prefix = (size_t)(position - text) - source_offset;
        memcpy(result + output_offset, text + source_offset, prefix);
        output_offset += prefix;
        memcpy(result + output_offset, replacement, replacement_length);
        output_offset += replacement_length;
        source_offset = (size_t)(position - text) + needle_length;
        position += needle_length;
    }
    memcpy(result + output_offset, text + source_offset, text_length - source_offset);
    result[result_length] = '\0';
    return result;
}

static struct json_object *scan_file(const char *path, int quarantine)
{
    char sha256[65];
    char *output = NULL;
    int file_fd;
    char *details = NULL;
    char *message = NULL;
    const char *display_name;
    int used_clamd;
    int result;
    int quarantined = 0;
    char quarantine_path[PATH_MAX];
    char quarantine_id[CLAMAV_QUARANTINE_ID_LENGTH];
    struct clamav_quarantine_metadata quarantine_metadata;
    char *clam[] = { (char *)"clamscan", (char *)"--infected", (char *)"--alert-broken-media=no", (char *)path, NULL };
    struct json_object *response;

    display_name = strrchr(path, '/');
    display_name = display_name == NULL ? path : display_name + 1;
    file_fd = open(path, O_RDONLY);
    if (file_fd < 0 || !sha256_fd(file_fd, sha256)) {
        if (file_fd >= 0)
            close(file_fd);
        return failure("Unable to read attachment", NULL);
    }

    result = scan_with_clamd(file_fd, &output);
    close(file_fd);
    used_clamd = result >= 0;
    if (result < 0)
        result = run_command(clam, &output);
    if (result < 0)
        return failure("Unable to start ClamAV", sha256);
    if (result == 127)
        return failure("Unable to start ClamAV", sha256);
    if (output != NULL && strstr(output, "Broken.Media") != NULL && result == 1) {
        free(output);
        output = NULL;
        result = run_command(clam, &output);
        used_clamd = 0;
    }
    if (strstr(output == NULL ? "" : output, " FOUND") != NULL)
        result = 1;
    if (strstr(output == NULL ? "" : output, " OK") != NULL)
        result = 0;
    if (!used_clamd) {
        details = replace_text(output == NULL ? "none" : output, path, display_name);
        if (details == NULL)
            details = strdup("none");
        {
            size_t size = strlen(details) + strlen("\nSHA-256: ") + 64 + strlen("\nScanner: clamscan") + 1;
            char *expanded = (char *)malloc(size);
            if (expanded != NULL) {
                sprintf(expanded, "%s\nSHA-256: %s\nScanner: clamscan", details, sha256);
                free(details);
                details = expanded;
            }
        }
    } else {
        details = replace_text(output == NULL ? "none" : output, path, display_name);
        if (details == NULL)
            details = strdup("none");
        {
            size_t size = strlen(details) + strlen("\nSHA-256: ") + 64 + strlen("\nScanner: clamd (FILDES)") + 1;
            char *expanded = (char *)malloc(size);
            if (expanded != NULL) {
                sprintf(expanded, "%s\nSHA-256: %s\nScanner: clamd (FILDES)", details, sha256);
                free(details);
                details = expanded;
            }
        }
    }
    free(output);
    if (details == NULL)
        return failure("The scan could not be completed", sha256);
    message = (char *)malloc(strlen(details) + 32);
    if (message == NULL) {
        free(details);
        return failure("The scan could not be completed", sha256);
    }
    if (result == 0)
        sprintf(message, "No viruses found.\n\n%s", details);
    else if (result == 1)
        sprintf(message, "A virus was identified.\n\n%s", details);
    else {
        free(message);
        response = failure(details, sha256);
        free(details);
        return response;
    }
    if (quarantine && result == 1) {
        quarantine_metadata.original_name = display_name;
        quarantine_metadata.source = "clamav-native-host";
        quarantine_metadata.detection = details;
        quarantine_metadata.sha256 = sha256;
        quarantined = clamav_quarantine_store(path, &quarantine_metadata, 1,
                                              quarantine_id, quarantine_path);
        if (quarantined) {
            size_t old_length = strlen(message);
            char *expanded = (char *)realloc(message, old_length + strlen("\n\nQuarantined: ") + strlen(quarantine_path) + 1);
            if (expanded != NULL) {
                message = expanded;
                sprintf(message + old_length, "\n\nQuarantined: %s", quarantine_path);
            }
        } else {
            size_t old_length = strlen(message);
            char *expanded = (char *)realloc(message, old_length + strlen("\n\nQuarantine failed") + 1);
            if (expanded != NULL) {
                message = expanded;
                sprintf(message + old_length, "\n\nQuarantine failed");
            }
        }
    }
    response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(result == 0 || result == 1));
    json_object_object_add(response, "infected", json_object_new_boolean(result == 1));
    json_object_object_add(response, "message", json_object_new_string(message));
    json_object_object_add(response, "sha256", json_object_new_string(sha256));
    if (quarantine && result == 1)
        json_object_object_add(response, "quarantined", json_object_new_boolean(quarantined));
    if (quarantined)
        json_object_object_add(response, "quarantine_path", json_object_new_string(quarantine_path));
    free(message);
    free(details);
    return response;
}

#ifndef CLAMAV_SCANNER_NO_MAIN
int main(void)
{
    unsigned char header[4];
    unsigned int length;
    char *buffer;
    struct json_object *request;
    struct json_object *path_object;
    struct json_object *quarantine_object;
    struct json_object *response;
    const char *path;
    int quarantine;

    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        if (!read_all(header, sizeof(header)))
            break;
        length = (unsigned int)header[0] | ((unsigned int)header[1] << 8)
            | ((unsigned int)header[2] << 16) | ((unsigned int)header[3] << 24);
        if (length == 0 || length > OUTPUT_LIMIT) {
            response = failure("Invalid native-messaging request", NULL);
            if (!send_json(response)) {
                json_object_put(response);
                break;
            }
            json_object_put(response);
            continue;
        }
        buffer = (char *)malloc((size_t)length + 1);
        if (buffer == NULL || !read_all(buffer, length)) {
            free(buffer);
            break;
        }
        buffer[length] = '\0';
        request = json_tokener_parse(buffer);
        free(buffer);
        if (request == NULL || !json_object_object_get_ex(request, "path", &path_object)
                || !json_object_is_type(path_object, json_type_string)) {
            response = failure("Invalid scan request", NULL);
        } else {
            path = json_object_get_string(path_object);
            quarantine = 0;
            if (json_object_object_get_ex(request, "quarantine", &quarantine_object)
                    && json_object_is_type(quarantine_object, json_type_boolean))
                quarantine = json_object_get_boolean(quarantine_object);
            response = scan_file(path, quarantine);
        }
        if (request != NULL)
            json_object_put(request);
        if (!send_json(response)) {
            json_object_put(response);
            break;
        }
        json_object_put(response);
    }
    return 0;
}
#endif
