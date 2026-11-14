/* Command-line front end for the shared native ClamD scanner. */

#define CLAMAV_SCANNER_NO_MAIN
#include "../thunderbird/native/clamav-native-host.c"

#include <ftw.h>

static int scan_status;

static void scan_one(const char *path)
{
    struct json_object *result = scan_file(path, 1);
    struct json_object *value;
    const char *message = "Scan failed";

    if (result == NULL) {
        scan_status = 2;
        return;
    }
    if (json_object_object_get_ex(result, "message", &value))
        message = json_object_get_string(value);
    puts(message);
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
    if (argc < 2)
        return 2;
    for (i = 1; i < argc; ++i) {
        struct stat status;
        if (lstat(argv[i], &status) != 0) {
            perror(argv[i]);
            scan_status = 2;
        } else if (S_ISDIR(status.st_mode)) {
            if (nftw(argv[i], scan_tree, 16, FTW_PHYS) != 0)
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
