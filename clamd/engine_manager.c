/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "clamav.h"
#include "output.h"

#include "engine_manager.h"

struct engine_manager_state {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_t reaper_thread;
    struct cl_engine *engine;
    struct cl_settings *settings;
    char *dbdir;
    char *cvdcertsdir;
    unsigned int dboptions;
    unsigned int active_scans;
    struct timespec last_scan_finished_at;
    bool last_scan_finished_valid;
    time_t keepalive_seconds;
    bool initialized;
    bool condition_initialized;
    bool reaper_started;
    bool shutdown_requested;
    bool loading;
    bool unloading;
    bool stale;
    bool stale_during_load;
};

static struct engine_manager_state manager = {
    .mutex     = PTHREAD_MUTEX_INITIALIZER,
};

static double elapsed_seconds(const struct timeval *start, const struct timeval *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_usec - start->tv_usec) / 1000000.0;
}

static int timespec_cmp(const struct timespec *lhs, const struct timespec *rhs)
{
    if (lhs->tv_sec < rhs->tv_sec)
        return -1;
    if (lhs->tv_sec > rhs->tv_sec)
        return 1;
    if (lhs->tv_nsec < rhs->tv_nsec)
        return -1;
    if (lhs->tv_nsec > rhs->tv_nsec)
        return 1;
    return 0;
}

static struct timespec timespec_add_seconds(const struct timespec *ts, time_t seconds)
{
    struct timespec result = *ts;

    result.tv_sec += seconds;
    return result;
}

static cl_error_t init_idle_condvar(void)
{
    pthread_condattr_t attr;

    if (manager.condition_initialized)
        return CL_SUCCESS;

    if (pthread_condattr_init(&attr) != 0)
        return CL_ECREAT;

#if defined(CLOCK_MONOTONIC)
    if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
        pthread_condattr_destroy(&attr);
        return CL_ECREAT;
    }
#endif

    if (pthread_cond_init(&manager.condition, &attr) != 0) {
        pthread_condattr_destroy(&attr);
        return CL_ECREAT;
    }

    pthread_condattr_destroy(&attr);
    manager.condition_initialized = true;
    return CL_SUCCESS;
}

static void *idle_unload_thread(void *unused)
{
    struct cl_engine *engine;

    (void)unused;
    pthread_mutex_lock(&manager.mutex);
    while (!manager.shutdown_requested) {
        struct timespec deadline;
        struct timespec now;

        while (!manager.shutdown_requested &&
               (!manager.initialized || !manager.engine || manager.loading || manager.unloading ||
                manager.active_scans != 0 || !manager.last_scan_finished_valid))
            pthread_cond_wait(&manager.condition, &manager.mutex);

        if (manager.shutdown_requested)
            break;

        deadline = timespec_add_seconds(&manager.last_scan_finished_at, manager.keepalive_seconds);
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            pthread_cond_wait(&manager.condition, &manager.mutex);
            continue;
        }

        if (timespec_cmp(&now, &deadline) < 0) {
            pthread_cond_timedwait(&manager.condition, &manager.mutex, &deadline);
            continue;
        }

        engine                        = manager.engine;
        manager.engine                = NULL;
        manager.stale                 = true;
        manager.unloading             = true;
        memset(&manager.last_scan_finished_at, 0, sizeof(manager.last_scan_finished_at));
        manager.last_scan_finished_valid = false;
        pthread_mutex_unlock(&manager.mutex);

        cl_engine_free(engine);
        logg(LOGG_INFO, "Database unloaded after idle timeout.\n");

        pthread_mutex_lock(&manager.mutex);
        manager.unloading = false;
        pthread_cond_broadcast(&manager.condition);
    }
    pthread_mutex_unlock(&manager.mutex);
    return NULL;
}

static struct cl_engine *load_engine(cl_error_t *status)
{
    struct cl_engine *engine = NULL;
    unsigned int signatures  = 0;

    engine = cl_engine_new();
    if (!engine) {
        *status = CL_EMEM;
        return NULL;
    }

    *status = cl_engine_settings_apply(engine, manager.settings);
    if (*status != CL_SUCCESS)
        goto fail;

    if (manager.cvdcertsdir) {
        *status = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, manager.cvdcertsdir);
        if (*status != CL_SUCCESS)
            goto fail;
    }

    *status = cl_load(manager.dbdir, engine, &signatures, manager.dboptions);
    if (*status != CL_SUCCESS)
        goto fail;

    *status = cl_engine_compile(engine);
    if (*status != CL_SUCCESS)
        goto fail;

    logg(LOGG_INFO, "Database loaded on demand (%u signatures).\n", signatures);
    return engine;

fail:
    cl_engine_free(engine);
    return NULL;
}

cl_error_t engine_manager_init(const struct cl_engine *template_engine,
                               const char *dbdir,
                               unsigned int dboptions,
                               time_t keepalive_seconds)
{
    const char *cvdcertsdir;
    cl_error_t cond_status;

    if (!template_engine || !dbdir || keepalive_seconds < 0)
        return CL_EARG;

    cond_status = init_idle_condvar();
    if (cond_status != CL_SUCCESS)
        return cond_status;

    manager.settings = cl_engine_settings_copy(template_engine);
    manager.dbdir    = strdup(dbdir);
    cvdcertsdir      = cl_engine_get_str(template_engine, CL_ENGINE_CVDCERTSDIR, NULL);
    if (cvdcertsdir)
        manager.cvdcertsdir = strdup(cvdcertsdir);

    if (!manager.settings || !manager.dbdir || (cvdcertsdir && !manager.cvdcertsdir)) {
        engine_manager_shutdown();
        return CL_EMEM;
    }

    manager.dboptions          = dboptions;
    manager.keepalive_seconds  = keepalive_seconds;
    manager.stale              = true;
    manager.initialized        = true;
    manager.shutdown_requested = false;

    if (pthread_create(&manager.reaper_thread, NULL, idle_unload_thread, NULL) != 0) {
        engine_manager_shutdown();
        return CL_ECREAT;
    }
    manager.reaper_started = true;

    logg(LOGG_INFO, "On-demand database mode enabled; keep-alive is %lld seconds.\n",
         (long long)keepalive_seconds);
    return CL_SUCCESS;
}

bool engine_manager_enabled(void)
{
    return manager.initialized;
}

struct cl_engine *engine_manager_get(cl_error_t *status)
{
    struct cl_engine *old_engine;
    struct cl_engine *new_engine;
    struct timeval load_started;
    struct timeval load_finished;
    cl_error_t load_status;

retry:
    old_engine = NULL;
    load_status = CL_SUCCESS;

    pthread_mutex_lock(&manager.mutex);
    if (!manager.initialized) {
        pthread_mutex_unlock(&manager.mutex);
        if (status)
            *status = CL_EARG;
        return NULL;
    }

    for (;;) {
        while (manager.loading || manager.unloading)
            pthread_cond_wait(&manager.condition, &manager.mutex);

        if (manager.engine && !manager.stale) {
            if (cl_engine_addref(manager.engine) != CL_SUCCESS) {
                pthread_mutex_unlock(&manager.mutex);
                if (status)
                    *status = CL_EMEM;
                return NULL;
            }
            manager.active_scans++;
            pthread_cond_broadcast(&manager.condition);
            new_engine = manager.engine;
            pthread_mutex_unlock(&manager.mutex);
            if (status)
                *status = CL_SUCCESS;
            return new_engine;
        }

        if (manager.active_scans != 0) {
            pthread_cond_wait(&manager.condition, &manager.mutex);
            continue;
        }

        manager.loading           = true;
        manager.stale_during_load = false;
        old_engine                = manager.engine;
        manager.engine            = NULL;
        break;
    }
    pthread_mutex_unlock(&manager.mutex);

    if (old_engine)
        cl_engine_free(old_engine);

    gettimeofday(&load_started, NULL);
    new_engine = load_engine(&load_status);
    gettimeofday(&load_finished, NULL);

    pthread_mutex_lock(&manager.mutex);
    if (new_engine) {
        if (manager.stale_during_load) {
            manager.loading = false;
            manager.stale   = true;
            pthread_cond_broadcast(&manager.condition);
            pthread_mutex_unlock(&manager.mutex);
            logg(LOGG_INFO,
                 "Database changed during on-demand load; retrying after %f seconds.\n",
                 elapsed_seconds(&load_started, &load_finished));
            cl_engine_free(new_engine);
            goto retry;
        }
        manager.engine = new_engine;
        manager.stale  = false;
        if (cl_engine_addref(new_engine) == CL_SUCCESS) {
            manager.active_scans++;
        } else {
            load_status    = CL_EMEM;
            manager.engine = NULL;
        }
    }
    manager.loading = false;
    pthread_cond_broadcast(&manager.condition);
    pthread_mutex_unlock(&manager.mutex);

    logg(load_status == CL_SUCCESS ? LOGG_INFO : LOGG_ERROR,
         "On-demand database load completed in %f seconds%s.\n",
         elapsed_seconds(&load_started, &load_finished),
         load_status == CL_SUCCESS ? "" : " with an error");

    if (load_status != CL_SUCCESS && new_engine)
        cl_engine_free(new_engine);
    if (status)
        *status = load_status;
    return load_status == CL_SUCCESS ? new_engine : NULL;
}

void engine_manager_release(struct cl_engine *engine)
{
    if (!engine)
        return;

    cl_engine_free(engine);

    pthread_mutex_lock(&manager.mutex);
    if (manager.active_scans > 0) {
        manager.active_scans--;
        if (manager.active_scans == 0) {
            clock_gettime(CLOCK_MONOTONIC, &manager.last_scan_finished_at);
            manager.last_scan_finished_valid = true;
            pthread_cond_broadcast(&manager.condition);
        }
    }
    pthread_mutex_unlock(&manager.mutex);
}

void engine_manager_mark_stale(void)
{
    pthread_mutex_lock(&manager.mutex);
    if (manager.initialized) {
        manager.stale = true;
        if (manager.loading)
            manager.stale_during_load = true;
        pthread_cond_broadcast(&manager.condition);
    }
    pthread_mutex_unlock(&manager.mutex);
}

void engine_manager_shutdown(void)
{
    struct cl_engine *engine;
    bool join_reaper;

    pthread_mutex_lock(&manager.mutex);
    manager.shutdown_requested = true;
    pthread_cond_broadcast(&manager.condition);
    join_reaper = manager.reaper_started;
    pthread_mutex_unlock(&manager.mutex);

    if (join_reaper)
        pthread_join(manager.reaper_thread, NULL);

    pthread_mutex_lock(&manager.mutex);
    while (manager.loading || manager.unloading)
        pthread_cond_wait(&manager.condition, &manager.mutex);
    engine              = manager.engine;
    manager.engine      = NULL;
    manager.initialized = false;
    pthread_mutex_unlock(&manager.mutex);

    if (engine)
        cl_engine_free(engine);
    if (manager.settings)
        cl_engine_settings_free(manager.settings);
    free(manager.dbdir);
    free(manager.cvdcertsdir);
    manager.settings              = NULL;
    manager.dbdir                 = NULL;
    manager.cvdcertsdir           = NULL;
    manager.active_scans          = 0;
    memset(&manager.last_scan_finished_at, 0, sizeof(manager.last_scan_finished_at));
    manager.last_scan_finished_valid = false;
    manager.keepalive_seconds     = 0;
    manager.reaper_started        = false;
    manager.shutdown_requested    = false;
    manager.loading               = false;
    manager.unloading             = false;
    manager.stale                 = false;
    manager.stale_during_load     = false;
    if (manager.condition_initialized) {
        pthread_cond_destroy(&manager.condition);
        manager.condition_initialized = false;
    }
}
