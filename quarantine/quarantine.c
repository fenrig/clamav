/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#include "quarantine.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int make_directory(const char *path)
{
    struct stat status;
    if (mkdir(path, 0700) == 0)
        return 1;
    if (errno != EEXIST || lstat(path, &status) != 0 || !S_ISDIR(status.st_mode))
        return 0;
    return status.st_uid == geteuid();
}

int clamav_quarantine_path(char path[PATH_MAX])
{
    const char *data_home = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    char base[PATH_MAX];
    char clamav[PATH_MAX];

    if (data_home != NULL && data_home[0] != '\0') {
        if (snprintf(base, sizeof(base), "%s", data_home) >= (int)sizeof(base))
            return 0;
    } else if (home != NULL && home[0] != '\0') {
        if (snprintf(base, sizeof(base), "%s/.local/share", home) >= (int)sizeof(base))
            return 0;
    } else {
        return 0;
    }
    if (!make_directory(base)
            || snprintf(clamav, sizeof(clamav), "%s/clamav", base) >= (int)sizeof(clamav)
            || !make_directory(clamav)
            || snprintf(path, PATH_MAX, "%s/quarantine", clamav) >= PATH_MAX
            || !make_directory(path))
        return 0;
    return chmod(path, 0700) == 0;
}

static int random_id(char id[CLAMAV_QUARANTINE_ID_LENGTH])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[16];
    int fd;
    ssize_t count;
    unsigned int i;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    count = read(fd, bytes, sizeof(bytes));
    close(fd);
    if (count != (ssize_t)sizeof(bytes))
        return 0;
    for (i = 0; i < sizeof(bytes); ++i) {
        id[i * 2] = hex[bytes[i] >> 4];
        id[i * 2 + 1] = hex[bytes[i] & 15];
    }
    id[CLAMAV_QUARANTINE_ID_LENGTH - 1] = '\0';
    return 1;
}

static int copy_file(int source, int destination)
{
    unsigned char buffer[65536];
    ssize_t count;
    ssize_t written;

    if (lseek(source, 0, SEEK_SET) < 0)
        return 0;
    while ((count = read(source, buffer, sizeof(buffer))) > 0) {
        written = 0;
        while (written < count) {
            ssize_t result = write(destination, buffer + written, (size_t)(count - written));
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0)
                return 0;
            written += result;
        }
    }
    return count == 0;
}

static int write_metadata(const char *path, const char *id,
                          const struct clamav_quarantine_metadata *metadata)
{
    struct json_object *object;
    const char *text;
    char temporary[PATH_MAX];
    int fd;
    size_t length;
    ssize_t written;

    if (snprintf(temporary, sizeof(temporary), "%s.%s.tmp", path, id) >= (int)sizeof(temporary))
        return 0;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return 0;
    object = json_object_new_object();
    json_object_object_add(object, "version", json_object_new_int(1));
    json_object_object_add(object, "original_name", json_object_new_string(metadata->original_name ? metadata->original_name : ""));
    json_object_object_add(object, "source", json_object_new_string(metadata->source ? metadata->source : "unknown"));
    json_object_object_add(object, "detection", json_object_new_string(metadata->detection ? metadata->detection : "unknown"));
    json_object_object_add(object, "sha256", json_object_new_string(metadata->sha256 ? metadata->sha256 : ""));
    json_object_object_add(object, "created", json_object_new_int64((int64_t)time(NULL)));
    text = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    length = strlen(text);
    written = write(fd, text, length);
    if (written == (ssize_t)length)
        written = write(fd, "\n", 1);
    if (written == 1 && fsync(fd) == 0 && close(fd) == 0
            && rename(temporary, path) == 0) {
        json_object_put(object);
        return chmod(path, 0600) == 0;
    }
    close(fd);
    unlink(temporary);
    json_object_put(object);
    return 0;
}

int clamav_quarantine_store(const char *source_path,
                            const struct clamav_quarantine_metadata *metadata,
                            int move_file,
                            char id[CLAMAV_QUARANTINE_ID_LENGTH],
                            char payload_path[PATH_MAX])
{
    char directory[PATH_MAX];
    char temporary[PATH_MAX];
    char metadata_path[PATH_MAX];
    int source;
    int destination;
    int success = 0;

    if (source_path == NULL || metadata == NULL || !clamav_quarantine_path(directory)
            || !random_id(id))
        return 0;
    if (snprintf(payload_path, PATH_MAX, "%s/%s.payload", directory, id) >= PATH_MAX
            || snprintf(temporary, PATH_MAX, "%s/%s.tmp", directory, id) >= PATH_MAX
            || snprintf(metadata_path, PATH_MAX, "%s/%s.json", directory, id) >= PATH_MAX)
        return 0;
    source = open(source_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0)
        return 0;
    destination = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (destination >= 0 && copy_file(source, destination)
            && fchmod(destination, 0600) == 0 && fsync(destination) == 0) {
        close(destination);
        destination = -1;
        if (rename(temporary, payload_path) == 0
                && write_metadata(metadata_path, id, metadata)) {
            success = 1;
            if (move_file && unlink(source_path) != 0)
                success = 0;
        }
    }
    if (destination >= 0)
        close(destination);
    close(source);
    if (!success) {
        unlink(temporary);
        unlink(payload_path);
        unlink(metadata_path);
    }
    return success;
}

static int valid_id(const char *id)
{
    size_t i;
    if (id == NULL || strlen(id) != CLAMAV_QUARANTINE_ID_LENGTH - 1)
        return 0;
    for (i = 0; i < CLAMAV_QUARANTINE_ID_LENGTH - 1; ++i) {
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
            return 0;
    }
    return 1;
}

static int entry_paths(const char *id, char payload[PATH_MAX], char metadata[PATH_MAX])
{
    char directory[PATH_MAX];
    if (!valid_id(id) || !clamav_quarantine_path(directory))
        return 0;
    return snprintf(payload, PATH_MAX, "%s/%s.payload", directory, id) < PATH_MAX
        && snprintf(metadata, PATH_MAX, "%s/%s.json", directory, id) < PATH_MAX;
}

static const char *json_string(struct json_object *object, const char *name)
{
    struct json_object *value;
    if (!json_object_object_get_ex(object, name, &value)
            || !json_object_is_type(value, json_type_string))
        return "";
    return json_object_get_string(value);
}

static int read_entry(const char *id, const char *metadata_path,
                      struct clamav_quarantine_entry *entry)
{
    struct json_object *object;
    struct json_object *value;
    struct stat status;
    char payload[PATH_MAX];
    object = json_object_from_file(metadata_path);
    if (object == NULL || !entry_paths(id, payload, entry->source)
            || lstat(payload, &status) != 0 || !S_ISREG(status.st_mode)) {
        if (object != NULL)
            json_object_put(object);
        return 0;
    }
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->id, sizeof(entry->id), "%s", id);
    snprintf(entry->original_name, sizeof(entry->original_name), "%s", json_string(object, "original_name"));
    snprintf(entry->source, sizeof(entry->source), "%s", json_string(object, "source"));
    snprintf(entry->detection, sizeof(entry->detection), "%s", json_string(object, "detection"));
    snprintf(entry->sha256, sizeof(entry->sha256), "%s", json_string(object, "sha256"));
    entry->size = (long long)status.st_size;
    if (json_object_object_get_ex(object, "created", &value)
            && json_object_is_type(value, json_type_int))
        entry->created = (long long)json_object_get_int64(value);
    json_object_put(object);
    return 1;
}

int clamav_quarantine_list(struct clamav_quarantine_entry **entries, size_t *count)
{
    char directory[PATH_MAX];
    struct dirent *item;
    struct clamav_quarantine_entry *result = NULL;
    size_t used = 0;
    DIR *stream;

    if (entries == NULL || count == NULL || !clamav_quarantine_path(directory))
        return 0;
    stream = opendir(directory);
    if (stream == NULL)
        return 0;
    while ((item = readdir(stream)) != NULL) {
        char metadata[PATH_MAX];
        struct clamav_quarantine_entry entry;
        size_t length = strlen(item->d_name);
        char id[CLAMAV_QUARANTINE_ID_LENGTH];
        if (length != 37 || strcmp(item->d_name + 32, ".json") != 0)
            continue;
        memcpy(id, item->d_name, 32);
        id[32] = '\0';
        if (!valid_id(id) || snprintf(metadata, sizeof(metadata), "%s/%s", directory, item->d_name) >= (int)sizeof(metadata)
                || !read_entry(id, metadata, &entry))
            continue;
        {
            struct clamav_quarantine_entry *grown = realloc(result, (used + 1) * sizeof(*result));
            if (grown == NULL) {
                free(result);
                closedir(stream);
                return 0;
            }
            result = grown;
            result[used++] = entry;
        }
    }
    closedir(stream);
    *entries = result;
    *count = used;
    return 1;
}

void clamav_quarantine_list_free(struct clamav_quarantine_entry *entries)
{
    free(entries);
}

int clamav_quarantine_delete(const char *id)
{
    char payload[PATH_MAX];
    char metadata[PATH_MAX];
    if (!entry_paths(id, payload, metadata))
        return 0;
    if (unlink(payload) != 0)
        return 0;
    if (unlink(metadata) != 0) {
        /* Keep the metadata if it cannot be removed; the payload is already
         * gone and will be ignored by the next list operation. */
        return 0;
    }
    return 1;
}

int clamav_quarantine_restore(const char *id, const char *destination_path)
{
    char payload[PATH_MAX];
    char metadata[PATH_MAX];
    char temporary[PATH_MAX];
    int source = -1;
    int destination = -1;
    int success = 0;

    if (destination_path == NULL || !entry_paths(id, payload, metadata)
            || snprintf(temporary, sizeof(temporary), "%s.clamav-%s.tmp", destination_path, id) >= (int)sizeof(temporary))
        return 0;
    source = open(payload, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0)
        return 0;
    destination = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (destination >= 0 && copy_file(source, destination)
            && fchmod(destination, 0600) == 0 && fsync(destination) == 0
            && close(destination) == 0) {
        destination = -1;
        if (rename(temporary, destination_path) == 0
                && unlink(payload) == 0 && unlink(metadata) == 0)
            success = 1;
    }
    if (destination >= 0)
        close(destination);
    close(source);
    if (!success)
        unlink(temporary);
    return success;
}
