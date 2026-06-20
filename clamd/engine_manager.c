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
    struct cl_engine *engine;
    struct cl_settings *settings;
    char *dbdir;
    char *cvdcertsdir;
    unsigned int dboptions;
    unsigned int active_scans;
    time_t last_scan_finished_at;
    time_t keepalive_seconds;
    bool initialized;
    bool loading;
    bool stale;
    bool stale_during_load;
};

static struct engine_manager_state manager = {
    .mutex     = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER,
};

static double elapsed_seconds(const struct timeval *start, const struct timeval *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_usec - start->tv_usec) / 1000000.0;
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

    if (!template_engine || !dbdir || keepalive_seconds < 0)
        return CL_EARG;

    manager.settings = cl_engine_settings_copy(template_engine);
    manager.dbdir    = strdup(dbdir);
    cvdcertsdir      = cl_engine_get_str(template_engine, CL_ENGINE_CVDCERTSDIR, NULL);
    if (cvdcertsdir)
        manager.cvdcertsdir = strdup(cvdcertsdir);

    if (!manager.settings || !manager.dbdir || (cvdcertsdir && !manager.cvdcertsdir)) {
        engine_manager_shutdown();
        return CL_EMEM;
    }

    manager.dboptions         = dboptions;
    manager.keepalive_seconds = keepalive_seconds;
    manager.stale             = true;
    manager.initialized       = true;

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
        while (manager.loading)
            pthread_cond_wait(&manager.condition, &manager.mutex);

        if (manager.engine && !manager.stale) {
            if (cl_engine_addref(manager.engine) != CL_SUCCESS) {
                pthread_mutex_unlock(&manager.mutex);
                if (status)
                    *status = CL_EMEM;
                return NULL;
            }
            manager.active_scans++;
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
            manager.last_scan_finished_at = time(NULL);
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

void engine_manager_maybe_unload_idle(void)
{
    struct cl_engine *engine = NULL;
    time_t now               = time(NULL);

    pthread_mutex_lock(&manager.mutex);
    if (manager.initialized && manager.engine && !manager.loading &&
        manager.active_scans == 0 && manager.last_scan_finished_at != 0 &&
        now - manager.last_scan_finished_at >= manager.keepalive_seconds) {
        engine         = manager.engine;
        manager.engine = NULL;
        manager.stale  = true;
    }
    pthread_mutex_unlock(&manager.mutex);

    if (engine) {
        cl_engine_free(engine);
        logg(LOGG_INFO, "Database unloaded after idle timeout.\n");
    }
}

void engine_manager_shutdown(void)
{
    struct cl_engine *engine;

    pthread_mutex_lock(&manager.mutex);
    while (manager.loading)
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
    manager.last_scan_finished_at = 0;
    manager.keepalive_seconds     = 0;
    manager.loading               = false;
    manager.stale                 = false;
    manager.stale_during_load     = false;
}
