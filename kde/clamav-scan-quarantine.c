/* Command-line front end for the shared native ClamD scanner. */

#define CLAMAV_SCANNER_NO_MAIN
#include "../thunderbird/native/clamav-native-host.c"

#include <ftw.h>

static int scan_status;
static int quarantine_mode;

static void scan_one(const char *path)
{
    printf("SCAN_FILE: %s\n", path);
    fflush(stdout);
    struct json_object *result = scan_file(path, quarantine_mode, "plasma", "", "{}");
    struct json_object *value;
    const char *message = "Scan failed";

    if (result == NULL) {
        scan_status = 2;
        return;
    }
    if (json_object_object_get_ex(result, "message", &value))
        message = json_object_get_string(value);
    printf("SCAN_RESULT: %s\n", json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
    fflush(stdout);
    puts(message);
    fflush(stdout);
    if (json_object_object_get_ex(result, "infected", &value)
            && json_object_get_boolean(value))
        scan_status = scan_status == 2 ? 2 : 1;
    if (!json_object_object_get_ex(result, "success", &value)
            || !json_object_get_boolean(value))
        scan_status = 2;
    json_object_put(result);
}

static int scan_tree(const char *path, const struct stat *status,
                     int type, struct FTW *info)
{
    (void)status;
    (void)info;
    if (type == FTW_F)
        scan_one(path);
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    int first_path = 1;
    quarantine_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--quarantine") == 0) {
        quarantine_mode = 1;
        first_path++;
    } else if (argc > 1 && strcmp(argv[1], "--scan-only") == 0) {
        first_path++;
    }
    if (argc <= first_path)
        return 2;
    for (i = first_path; i < argc; ++i) {
        struct stat status;
        if (stat(argv[i], &status) != 0) {
            perror(argv[i]);
            scan_status = 2;
        } else if (S_ISDIR(status.st_mode)) {
            char resolved[PATH_MAX];
            if (realpath(argv[i], resolved) == NULL
                    || nftw(resolved, scan_tree, 16, FTW_PHYS) != 0)
                scan_status = 2;
        } else if (S_ISREG(status.st_mode)) {
            scan_one(argv[i]);
        } else {
            fprintf(stderr, "%s: not a regular file or directory\n", argv[i]);
            scan_status = 2;
        }
    }
    return scan_status;
}
