/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/inotify.h>

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "optparser.h"
#include "output.h"

#include "inotif.h"
#include "../misc/priv_fts.h"
#include "../scan/onas_queue.h"
#include "../scan/thread.h"

#define ONAS_DOWNLOAD_CACHE_SIZE 1024

struct onas_download_wd {
    int wd;
    char *pathname;
};

struct onas_download_seen {
    dev_t dev;
    ino_t ino;
    off_t size;
    time_t mtime;
};

static int onas_download_in_fd;
static struct onas_download_wd *download_wds;
static size_t download_wds_len;
static size_t download_wds_used;
static struct onas_download_seen download_seen[ONAS_DOWNLOAD_CACHE_SIZE];
static size_t download_seen_next;
extern pthread_t download_pid;

static void onas_download_exit(void *arg);
static cl_error_t onas_download_watch_tree(int fd, const char *pathname);
static cl_error_t onas_download_watch_dir(int fd, const char *pathname);
static const char *onas_download_path_from_wd(int wd);
static bool onas_download_has_ignored_suffix(struct onas_context *ctx, const char *pathname);
static bool onas_download_seen_before(const STATBUF *sb);
static void onas_download_queue_scan(struct onas_context *ctx, const char *pathname);
static void onas_download_handle_path(struct onas_context *ctx, const char *pathname);

cl_error_t onas_enable_download_watcher(struct onas_context **ctx)
{
    pthread_attr_t download_attr;
    int32_t thread_started = 1;

    if (!ctx || !*ctx) {
        logg(LOGG_ERROR, "ClamDownload: unable to start download watcher. (bad context)\n");
        return CL_EARG;
    }

    if (!optget((*ctx)->clamdopts, "OnAccessDownloadScanOnFinalize")->enabled ||
        !optget((*ctx)->clamdopts, "OnAccessDownloadPath")->enabled) {
        return CL_BREAK;
    }

    if (pthread_attr_init(&download_attr)) {
        return CL_BREAK;
    }
    pthread_attr_setdetachstate(&download_attr, PTHREAD_CREATE_JOINABLE);
    thread_started = pthread_create(&download_pid, &download_attr, onas_download_th, *ctx);

    if (0 != thread_started) {
        logg(LOGG_ERROR, "ClamDownload: unable to start download watcher\n");
        return CL_ECREAT;
    }

    return CL_SUCCESS;
}

void *onas_download_th(void *arg)
{
    const char thread_name[] = "clamonacc-dl";
    struct onas_context *ctx = (struct onas_context *)arg;
    const struct optstruct *pt;
    sigset_t sigset;
    fd_set rfds;
    char buf[4096];
    ssize_t bread;
    int ret;

#if defined(__linux__)
    prctl(PR_SET_NAME, thread_name);
#elif defined(__APPLE__) && defined(__MACH__)
    pthread_setname_np(thread_name);
#else
    logg(LOGG_WARNING, "ClamDownload: setting of the thread name is currently not supported on this system\n");
#endif

    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    sigdelset(&sigset, SIGUSR2);
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGINT);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);

    onas_download_in_fd = inotify_init1(IN_NONBLOCK);
    if (onas_download_in_fd == -1) {
        logg(LOGG_ERROR, "ClamDownload: could not init inotify: %s\n", strerror(errno));
        return NULL;
    }

    pthread_cleanup_push(onas_download_exit, NULL);

    pt = optget(ctx->clamdopts, "OnAccessDownloadPath");
    while (pt) {
        if (onas_download_watch_tree(onas_download_in_fd, pt->strarg) != CL_SUCCESS) {
            logg(LOGG_ERROR, "ClamDownload: failed to watch '%s'\n", pt->strarg);
        } else {
            logg(LOGG_INFO, "ClamDownload: watching '%s' for completed downloads\n", pt->strarg);
        }
        pt = (struct optstruct *)pt->nextarg;
    }

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(onas_download_in_fd, &rfds);

        do {
            ret = select(onas_download_in_fd + 1, &rfds, NULL, NULL, NULL);
        } while (ret == -1 && errno == EINTR);

        while ((bread = read(onas_download_in_fd, buf, sizeof(buf))) > 0) {
            char *p                          = buf;
            const struct inotify_event *event = NULL;

            pthread_testcancel();

            for (; p < buf + bread; p += sizeof(struct inotify_event) + event->len) {
                const char *path;
                char *child_path;
                size_t size;

                event = (const struct inotify_event *)p;

                if (event->mask & IN_Q_OVERFLOW) {
                    logg(LOGG_ERROR, "ClamDownload: inotify queue overflow; completed download events may have been missed\n");
                    continue;
                }
                if (event->mask & IN_IGNORED) {
                    continue;
                }

                path = onas_download_path_from_wd(event->wd);
                if (!path || !event->len) {
                    continue;
                }

                size       = strlen(path) + strlen(event->name) + 2;
                child_path = malloc(size);
                if (!child_path) {
                    logg(LOGG_ERROR, "ClamDownload: out of memory while handling inotify event\n");
                    continue;
                }

                if (path[strlen(path) - 1] == '/') {
                    snprintf(child_path, size, "%s%s", path, event->name);
                } else {
                    snprintf(child_path, size, "%s/%s", path, event->name);
                }

                if ((event->mask & (IN_CREATE | IN_MOVED_TO)) && (event->mask & IN_ISDIR)) {
                    if (onas_download_watch_tree(onas_download_in_fd, child_path) != CL_SUCCESS) {
                        logg(LOGG_WARNING, "ClamDownload: could not add recursive watch for new directory '%s'\n", child_path);
                    }
                } else if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) {
                    onas_download_handle_path(ctx, child_path);
                }

                free(child_path);
            }
        }
    }

    pthread_cleanup_pop(1);
    return NULL;
}

static cl_error_t onas_download_watch_tree(int fd, const char *pathname)
{
    FTS *ftsp        = NULL;
    int32_t ftspopts = FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV;
    FTSENT *curr     = NULL;
    char *const pathargv[] = {(char *)pathname, NULL};
    cl_error_t ret         = CL_SUCCESS;

    if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) {
        logg(LOGG_ERROR, "ClamDownload: could not open download path '%s': %s\n", pathname, strerror(errno));
        return CL_EOPEN;
    }

    while ((curr = _priv_fts_read(ftsp))) {
        if (curr->fts_info == FTS_D) {
            ret = onas_download_watch_dir(fd, curr->fts_path);
            if (ret != CL_SUCCESS) {
                break;
            }
        }
    }

    _priv_fts_close(ftsp);
    return ret;
}

static cl_error_t onas_download_watch_dir(int fd, const char *pathname)
{
    int wd;
    uint32_t mask = IN_ONLYDIR | IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF;

    wd = inotify_add_watch(fd, pathname, mask);
    if (wd < 0) {
        logg(LOGG_ERROR, "ClamDownload: could not watch '%s': %s\n", pathname, strerror(errno));
        if (errno == ENOSPC) {
            logg(LOGG_ERROR, "ClamDownload: inotify watch limit reached. Increase fs.inotify.max_user_watches or reduce OnAccessDownloadPath scope.\n");
        }
        return CL_EARG;
    }

    if (download_wds_used == download_wds_len) {
        size_t new_len = download_wds_len ? download_wds_len << 1 : 128;
        void *ptr      = cli_safer_realloc(download_wds, new_len * sizeof(*download_wds));
        if (!ptr) {
            return CL_EMEM;
        }
        download_wds     = ptr;
        download_wds_len = new_len;
    }

    download_wds[download_wds_used].wd       = wd;
    download_wds[download_wds_used].pathname = cli_safer_strdup(pathname);
    if (!download_wds[download_wds_used].pathname) {
        return CL_EMEM;
    }
    download_wds_used++;

    logg(LOGG_DEBUG, "ClamDownload: watching directory '%s'\n", pathname);
    return CL_SUCCESS;
}

static const char *onas_download_path_from_wd(int wd)
{
    size_t i;

    for (i = 0; i < download_wds_used; i++) {
        if (download_wds[i].wd == wd) {
            return download_wds[i].pathname;
        }
    }

    return NULL;
}

static bool onas_download_has_ignored_suffix(struct onas_context *ctx, const char *pathname)
{
    const struct optstruct *pt = optget(ctx->clamdopts, "OnAccessDownloadIgnoreExtension");

    while (pt && pt->enabled) {
        size_t path_len = strlen(pathname);
        size_t ext_len  = strlen(pt->strarg);

        if (path_len >= ext_len && 0 == strcmp(pathname + path_len - ext_len, pt->strarg)) {
            return true;
        }

        pt = (struct optstruct *)pt->nextarg;
    }

    return false;
}

static bool onas_download_seen_before(const STATBUF *sb)
{
    size_t i;

    for (i = 0; i < ONAS_DOWNLOAD_CACHE_SIZE; i++) {
        if (download_seen[i].ino == sb->st_ino &&
            download_seen[i].dev == sb->st_dev &&
            download_seen[i].size == sb->st_size &&
            download_seen[i].mtime == sb->st_mtime) {
            return true;
        }
    }

    download_seen[download_seen_next].ino   = sb->st_ino;
    download_seen[download_seen_next].dev   = sb->st_dev;
    download_seen[download_seen_next].size  = sb->st_size;
    download_seen[download_seen_next].mtime = sb->st_mtime;
    download_seen_next                      = (download_seen_next + 1) % ONAS_DOWNLOAD_CACHE_SIZE;

    return false;
}

static void onas_download_queue_scan(struct onas_context *ctx, const char *pathname)
{
    struct onas_scan_event *event_data;

    event_data = calloc(1, sizeof(struct onas_scan_event));
    if (!event_data) {
        logg(LOGG_ERROR, "ClamDownload: could not allocate memory for scan event\n");
        return;
    }

    if (onas_map_context_info_to_event_data(ctx, &event_data) != CL_SUCCESS) {
        free(event_data);
        return;
    }

    event_data->pathname = cli_safer_strdup(pathname);
    if (!event_data->pathname) {
        free(event_data);
        return;
    }

    event_data->bool_opts |= ONAS_SCTH_B_SCAN;
    event_data->bool_opts |= ONAS_SCTH_B_INOTIFY;
    event_data->bool_opts |= ONAS_SCTH_B_FILE;

    logg(LOGG_DEBUG, "ClamDownload: queueing completed download scan for '%s'\n", pathname);
    if (CL_SUCCESS != onas_queue_event(event_data)) {
        logg(LOGG_ERROR, "ClamDownload: error occurred while feeding consumer queue ... continuing ...\n");
        free(event_data->pathname);
        free(event_data);
    }
}

static void onas_download_handle_path(struct onas_context *ctx, const char *pathname)
{
    STATBUF sb;

    if (onas_download_has_ignored_suffix(ctx, pathname)) {
        logg(LOGG_DEBUG, "ClamDownload: ignoring temporary download file '%s'\n", pathname);
        return;
    }

    if (LSTAT(pathname, &sb) != 0) {
        logg(LOGG_DEBUG, "ClamDownload: could not stat finalized path '%s': %s\n", pathname, strerror(errno));
        return;
    }

    if (!S_ISREG(sb.st_mode)) {
        logg(LOGG_DEBUG, "ClamDownload: skipping non-regular finalized path '%s'\n", pathname);
        return;
    }

    if (onas_download_seen_before(&sb)) {
        logg(LOGG_DEBUG, "ClamDownload: skipping unchanged finalized path '%s'\n", pathname);
        return;
    }

    onas_download_queue_scan(ctx, pathname);
}

static void onas_download_exit(void *arg)
{
    size_t i;
    UNUSEDPARAM(arg);

    logg(LOGG_DEBUG, "ClamDownload: onas_download_exit()\n");

    if (onas_download_in_fd) {
        close(onas_download_in_fd);
    }
    onas_download_in_fd = 0;

    for (i = 0; i < download_wds_used; i++) {
        free(download_wds[i].pathname);
    }
    free(download_wds);
    download_wds      = NULL;
    download_wds_len  = 0;
    download_wds_used = 0;

    logg(LOGG_INFO, "ClamDownload: stopped\n");
}

#endif
