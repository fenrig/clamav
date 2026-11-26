/* Command-line front end for the shared native ClamD scanner. */

#define CLAMAV_SCANNER_NO_MAIN
#include "../thunderbird/native/clamav-native-host.c"

#include <ftw.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/select.h>
#include <time.h>

static char **scan_paths;
static size_t scan_path_count;
static size_t next_scan_path;
static int scan_workers = 2;
static int scan_status;
static int scan_stop;
static int scan_cancel_requested;
static int completed_scan_files;
static int failed_scan_files;
static int infected_scan_files;
static int skipped_scan_files;
static size_t prepared_scan_files;
static char **skipped_paths;
static char **skipped_reasons;
static size_t skipped_path_count;
static pthread_mutex_t scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t scan_condition = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static char **active_paths;
static struct timespec *active_started;
static int scan_worker_capacity;

static void print_event(struct json_object *event)
{
    pthread_mutex_lock(&output_mutex);
    printf("SCAN_EVENT: %s\n", json_object_to_json_string_ext(event, JSON_C_TO_STRING_PLAIN));
    fflush(stdout);
    pthread_mutex_unlock(&output_mutex);
    json_object_put(event);
}

static void emit_scan_started(void)
{
    struct json_object *event = json_object_new_object();
    json_object_object_add(event, "event", json_object_new_string("scan_started"));
    json_object_object_add(event, "total", json_object_new_int64(
        (int64_t)(scan_path_count + skipped_path_count)));
    json_object_object_add(event, "workers", json_object_new_int(scan_workers));
    print_event(event);
}

static void emit_scan_preparing(const char *path)
{
    struct json_object *event = json_object_new_object();
    json_object_object_add(event, "event", json_object_new_string("scan_preparing"));
    json_object_object_add(event, "path", json_object_new_string(path));
    json_object_object_add(event, "discovered", json_object_new_int64((int64_t)prepared_scan_files));
    print_event(event);
}

static void record_skipped(const char *path, const char *reason)
{
    char **new_paths = malloc((skipped_path_count + 1) * sizeof(*skipped_paths));
    char **new_reasons = malloc((skipped_path_count + 1) * sizeof(*skipped_reasons));
    if (new_paths == NULL || new_reasons == NULL) {
        free(new_paths);
        free(new_reasons);
        scan_status = 2;
        return;
    }
    if (skipped_path_count != 0) {
        memcpy(new_paths, skipped_paths, skipped_path_count * sizeof(*skipped_paths));
        memcpy(new_reasons, skipped_reasons, skipped_path_count * sizeof(*skipped_reasons));
    }
    free(skipped_paths);
    free(skipped_reasons);
    skipped_paths = new_paths;
    skipped_reasons = new_reasons;
    skipped_paths[skipped_path_count] = strdup(path);
    skipped_reasons[skipped_path_count] = strdup(reason);
    if (skipped_paths[skipped_path_count] == NULL || skipped_reasons[skipped_path_count] == NULL) {
        free(skipped_paths[skipped_path_count]);
        free(skipped_reasons[skipped_path_count]);
        scan_status = 2;
        return;
    }
    ++skipped_path_count;
    scan_status = 2;
}

static void emit_skipped(const char *path, const char *reason)
{
    struct json_object *started = json_object_new_object();
    struct json_object *result = failure(reason, NULL);
    json_object_object_add(started, "event", json_object_new_string("file_started"));
    json_object_object_add(started, "path", json_object_new_string(path));
    print_event(started);
    json_object_object_add(result, "path", json_object_new_string(path));
    json_object_object_add(result, "event", json_object_new_string("file_result"));
    json_object_object_add(result, "status", json_object_new_string("skipped"));
    json_object_object_add(result, "error_code", json_object_new_string(reason));
    print_event(result);
    ++completed_scan_files;
    ++skipped_scan_files;
}

static void emit_failed(const char *path, const char *code, const char *message)
{
    struct json_object *started = json_object_new_object();
    struct json_object *result = failure(message, NULL);
    json_object_object_add(started, "event", json_object_new_string("file_started"));
    json_object_object_add(started, "path", json_object_new_string(path));
    print_event(started);
    json_object_object_add(result, "path", json_object_new_string(path));
    json_object_object_add(result, "event", json_object_new_string("file_result"));
    json_object_object_add(result, "status", json_object_new_string("error"));
    json_object_object_add(result, "error_code", json_object_new_string(code));
    json_object_object_add(result, "scanner", json_object_new_string("clamd"));
    print_event(result);
    ++completed_scan_files;
    ++failed_scan_files;
}

static int available_scan_workers(void)
{
    long processors = sysconf(_SC_NPROCESSORS_ONLN);
    int maximum = processors > 1 ? (int)(processors / 2) : 1;
    return maximum < 1 ? 1 : maximum;
}

static void emit_file_result(const char *path, struct json_object *result)
{
    if (result != NULL) {
        json_object_object_add(result, "path", json_object_new_string(path));
        json_object_object_add(result, "event", json_object_new_string("file_result"));
        print_event(result);
        return;
    } else {
        result = failure("The scan could not be completed", NULL);
        json_object_object_add(result, "path", json_object_new_string(path));
        json_object_object_add(result, "event", json_object_new_string("file_result"));
        json_object_object_add(result, "status", json_object_new_string("error"));
        json_object_object_add(result, "error_code", json_object_new_string("internal_error"));
        print_event(result);
    }
}

static int quarantine_mode;

static void scan_one(const char *path)
{
    struct json_object *started = json_object_new_object();
    json_object_object_add(started, "event", json_object_new_string("file_started"));
    json_object_object_add(started, "path", json_object_new_string(path));
    print_event(started);
    struct json_object *result = scan_file(path, quarantine_mode, "plasma", "", "{}", 0);
    struct json_object *value;
    int success = 0;
    int infected = 0;

    if (result == NULL) {
        emit_file_result(path, NULL);
        pthread_mutex_lock(&scan_mutex);
        ++completed_scan_files;
        ++failed_scan_files;
        scan_status = 2;
        pthread_mutex_unlock(&scan_mutex);
        return;
    }
    if (json_object_object_get_ex(result, "success", &value))
        success = json_object_get_boolean(value);
    if (json_object_object_get_ex(result, "infected", &value))
        infected = json_object_get_boolean(value);
    if (!json_object_object_get_ex(result, "scanner", &value))
        json_object_object_add(result, "scanner", json_object_new_string("unknown"));
    if (json_object_object_get_ex(result, "success", &value)
            && json_object_get_boolean(value)) {
        const char *status = "clean";
        if (json_object_object_get_ex(result, "infected", &value)
                && json_object_get_boolean(value))
            status = "infected";
        json_object_object_add(result, "status", json_object_new_string(status));
    } else {
        json_object_object_add(result, "status", json_object_new_string("error"));
        const char *error_code = "scan_failed";
        struct json_object *message = NULL;
        if (json_object_object_get_ex(result, "message", &message)) {
            const char *text = json_object_get_string(message);
            if (text != NULL && strstr(text, "Unable to read") != NULL)
                error_code = "read_error";
            else if (text != NULL && strstr(text, "Unable to start") != NULL)
                error_code = "scanner_unavailable";
        }
        json_object_object_add(result, "error_code", json_object_new_string(error_code));
    }
    emit_file_result(path, result);
    pthread_mutex_lock(&scan_mutex);
    ++completed_scan_files;
    if (infected)
        ++infected_scan_files;
    if (!success) {
        ++failed_scan_files;
        scan_status = 2;
    } else if (infected && scan_status != 2)
        scan_status = 1;
    pthread_mutex_unlock(&scan_mutex);
}

static void *scan_heartbeat(void *unused)
{
    (void)unused;
    for (;;) {
        struct timespec delay;
        struct timespec now;
        char **paths;
        double *elapsed;
        int count = 0;
        int i;
        paths = calloc((size_t)scan_worker_capacity, sizeof(*paths));
        elapsed = calloc((size_t)scan_worker_capacity, sizeof(*elapsed));
        if (paths == NULL || elapsed == NULL) {
            free(paths);
            free(elapsed);
            return NULL;
        }
        delay.tv_sec = 1;
        delay.tv_nsec = 0;
        nanosleep(&delay, NULL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        pthread_mutex_lock(&scan_mutex);
        if (scan_stop) {
            pthread_mutex_unlock(&scan_mutex);
            break;
        }
        for (i = 0; i < scan_worker_capacity; ++i) {
            if (active_paths[i] != NULL && (paths[count] = strdup(active_paths[i])) != NULL) {
                elapsed[count] = (double)(now.tv_sec - active_started[i].tv_sec)
                    + (double)(now.tv_nsec - active_started[i].tv_nsec) / 1000000000.0;
                ++count;
            }
        }
        pthread_mutex_unlock(&scan_mutex);
        for (i = 0; i < count; ++i) {
            struct json_object *event = json_object_new_object();
            json_object_object_add(event, "event", json_object_new_string("file_progress"));
            json_object_object_add(event, "path", json_object_new_string(paths[i]));
            json_object_object_add(event, "state", json_object_new_string("scanning"));
            json_object_object_add(event, "elapsed_seconds", json_object_new_double(elapsed[i]));
            print_event(event);
            free(paths[i]);
        }
        free(paths);
        free(elapsed);
    }
    return NULL;
}

static void *scan_worker(void *argument)
{
    const int worker_id = *(const int *)argument;
    for (;;) {
        char *path = NULL;
        pthread_mutex_lock(&scan_mutex);
        while (!scan_stop && worker_id >= scan_workers
                && next_scan_path < scan_path_count)
            pthread_cond_wait(&scan_condition, &scan_mutex);
        if (scan_stop || next_scan_path >= scan_path_count) {
            pthread_mutex_unlock(&scan_mutex);
            break;
        }
        path = strdup(scan_paths[next_scan_path++]);
        pthread_cond_broadcast(&scan_condition);
        pthread_mutex_unlock(&scan_mutex);
        if (path != NULL) {
            pthread_mutex_lock(&scan_mutex);
            active_paths[worker_id] = strdup(path);
            clock_gettime(CLOCK_MONOTONIC, &active_started[worker_id]);
            pthread_mutex_unlock(&scan_mutex);
            scan_one(path);
            pthread_mutex_lock(&scan_mutex);
            free(active_paths[worker_id]);
            active_paths[worker_id] = NULL;
            active_started[worker_id].tv_sec = 0;
            active_started[worker_id].tv_nsec = 0;
            pthread_mutex_unlock(&scan_mutex);
            free(path);
        } else {
            pthread_mutex_lock(&scan_mutex);
            scan_status = 2;
            pthread_mutex_unlock(&scan_mutex);
        }
    }
    return NULL;
}

static void *scan_control(void *unused)
{
    char line[64];
    fd_set input;
    struct timeval timeout;
    (void)unused;
    for (;;) {
        FD_ZERO(&input);
        FD_SET(STDIN_FILENO, &input);
        timeout.tv_sec = 0;
        timeout.tv_usec = 250000;
        if (select(STDIN_FILENO + 1, &input, NULL, NULL, &timeout) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        pthread_mutex_lock(&scan_mutex);
        if (scan_stop) {
            pthread_mutex_unlock(&scan_mutex);
            break;
        }
        pthread_mutex_unlock(&scan_mutex);
        if (!FD_ISSET(STDIN_FILENO, &input))
            continue;
        if (fgets(line, sizeof(line), stdin) == NULL)
            break;
        if (strncmp(line, "WORKERS ", 8) == 0) {
            int requested = atoi(line + 8);
            if (requested < 1)
                requested = 1;
            if (requested > available_scan_workers())
                requested = available_scan_workers();
            pthread_mutex_lock(&scan_mutex);
            scan_workers = requested;
            pthread_cond_broadcast(&scan_condition);
            pthread_mutex_unlock(&scan_mutex);
        } else if (strncmp(line, "CANCEL", 6) == 0) {
            pthread_mutex_lock(&scan_mutex);
            scan_cancel_requested = 1;
            scan_stop = 1;
            pthread_cond_broadcast(&scan_condition);
            pthread_mutex_unlock(&scan_mutex);
            {
                struct json_object *event = json_object_new_object();
                json_object_object_add(event, "event", json_object_new_string("scan_cancelled"));
                json_object_object_add(event, "state", json_object_new_string("cancelling"));
                print_event(event);
                kill(getpid(), SIGTERM);
            }
        }
    }
    return NULL;
}

static int scan_tree(const char *path, const struct stat *status,
                     int type, struct FTW *info)
{
    (void)status;
    (void)info;
    if (type == FTW_F) {
        char **expanded = realloc(scan_paths, (scan_path_count + 1) * sizeof(*scan_paths));
        if (expanded == NULL)
            return 1;
        scan_paths = expanded;
        scan_paths[scan_path_count] = strdup(path);
        if (scan_paths[scan_path_count] == NULL)
            return 1;
        ++scan_path_count;
        ++prepared_scan_files;
        if ((prepared_scan_files % 256) == 0)
            emit_scan_preparing(path);
    } else if (type == FTW_DNR || type == FTW_NS) {
        record_skipped(path, type == FTW_DNR ? "directory_unreadable" : "path_unavailable");
    }
    return 0;
}

static void emit_scan_finished(const char *status)
{
    struct json_object *finished = json_object_new_object();
    json_object_object_add(finished, "event", json_object_new_string("scan_finished"));
    json_object_object_add(finished, "status", json_object_new_string(status));
    json_object_object_add(finished, "scanned", json_object_new_int(completed_scan_files));
    json_object_object_add(finished, "errors", json_object_new_int(failed_scan_files));
    json_object_object_add(finished, "skipped", json_object_new_int(skipped_scan_files));
    json_object_object_add(finished, "infected", json_object_new_int(infected_scan_files));
    print_event(finished);
}

static void free_scan_plan(void)
{
    size_t i;
    for (i = 0; i < scan_path_count; ++i)
        free(scan_paths[i]);
    free(scan_paths);
    for (i = 0; i < skipped_path_count; ++i) {
        free(skipped_paths[i]);
        free(skipped_reasons[i]);
    }
    free(skipped_paths);
    free(skipped_reasons);
}

int main(int argc, char **argv)
{
    int i, first_path = 1;
    pthread_t *workers, control, heartbeat;
    int *worker_ids;
    int worker_count;
    int control_created = 0;
    int heartbeat_created = 0;
    int clamd_available;
    int worker_limit;
    quarantine_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--quarantine") == 0) {
        quarantine_mode = 1;
        first_path++;
    } else if (argc > 1 && strcmp(argv[1], "--scan-only") == 0) {
        first_path++;
    }
    if (argc > first_path + 1 && strcmp(argv[first_path], "--workers") == 0) {
        scan_workers = atoi(argv[first_path + 1]);
        if (scan_workers < 1)
            scan_workers = 1;
        if (scan_workers > available_scan_workers())
            scan_workers = available_scan_workers();
        first_path += 2;
    }
    if (scan_workers > available_scan_workers())
        scan_workers = available_scan_workers();
    if (argc <= first_path)
        return 2;
    emit_scan_preparing("Preparing scan locations");
    for (i = first_path; i < argc; ++i) {
        struct stat status;
        if (stat(argv[i], &status) != 0) {
            record_skipped(argv[i], "path_unavailable");
            scan_status = 2;
        } else if (S_ISDIR(status.st_mode)) {
            char resolved[PATH_MAX];
            if (realpath(argv[i], resolved) == NULL
                    || nftw(resolved, scan_tree, 16, FTW_PHYS) != 0) {
                record_skipped(argv[i], "directory_walk_failed");
                scan_status = 2;
            }
        } else if (S_ISREG(status.st_mode)) {
            char **expanded = realloc(scan_paths, (scan_path_count + 1) * sizeof(*scan_paths));
            if (expanded == NULL || (scan_paths = expanded,
                                     (scan_paths[scan_path_count] = strdup(argv[i])) == NULL))
                scan_status = 2;
            else
                ++scan_path_count, ++prepared_scan_files;
        } else {
            record_skipped(argv[i], "unsupported_target");
            scan_status = 2;
        }
    }
    emit_scan_started();
    for (i = 0; i < (int)skipped_path_count; ++i)
        emit_skipped(skipped_paths[i], skipped_reasons[i]);
    clamd_available = scan_path_count == 0 || clamd_ping();
    if (!clamd_available) {
        struct json_object *error = json_object_new_object();
        json_object_object_add(error, "event", json_object_new_string("scan_error"));
        json_object_object_add(error, "error_code", json_object_new_string("scanner_unavailable"));
        json_object_object_add(error, "message", json_object_new_string("ClamD is unavailable"));
        print_event(error);
        for (i = 0; i < (int)scan_path_count; ++i)
            emit_failed(scan_paths[i], "scanner_unavailable", "ClamD is unavailable");
        scan_status = 2;
    }
    if (!clamd_available) {
        emit_scan_finished("error");
        free_scan_plan();
        return scan_status;
    }
    if (scan_path_count == 0)
        scan_stop = 1;
    worker_limit = available_scan_workers();
    scan_worker_capacity = worker_limit;
    active_paths = calloc((size_t)worker_limit, sizeof(*active_paths));
    active_started = calloc((size_t)worker_limit, sizeof(*active_started));
    workers = calloc((size_t)worker_limit, sizeof(*workers));
    worker_ids = malloc((size_t)worker_limit * sizeof(*worker_ids));
    if (active_paths == NULL || active_started == NULL || workers == NULL || worker_ids == NULL) {
        free(active_paths);
        free(active_started);
        free(workers);
        free(worker_ids);
        free_scan_plan();
        return 2;
    }
    worker_count = worker_limit;
    for (i = 0; i < worker_count; ++i) {
        worker_ids[i] = i;
        if (pthread_create(&workers[i], NULL, scan_worker, &worker_ids[i]) != 0) {
            scan_status = 2;
            worker_count = i;
            break;
        }
    }
    if (pthread_create(&control, NULL, scan_control, NULL) == 0)
        control_created = 1;
    else
        scan_status = 2;
    if (pthread_create(&heartbeat, NULL, scan_heartbeat, NULL) == 0)
        heartbeat_created = 1;
    else
        scan_status = 2;
    for (i = 0; i < worker_count; ++i)
        pthread_join(workers[i], NULL);
    emit_scan_finished(scan_cancel_requested ? "cancelled"
                                               : scan_status == 2 ? "error"
                                                                   : scan_status == 1 ? "infected" : "clean");
    pthread_mutex_lock(&scan_mutex);
    scan_stop = 1;
    pthread_cond_broadcast(&scan_condition);
    pthread_mutex_unlock(&scan_mutex);
    if (control_created)
        pthread_join(control, NULL);
    if (heartbeat_created)
        pthread_join(heartbeat, NULL);
    free(active_paths);
    free(active_started);
    free(workers);
    free(worker_ids);
    free_scan_plan();
    return scan_status;
}
