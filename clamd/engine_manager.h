/*
 * On-demand clamd scanning-engine lifecycle management.
 */

#ifndef __ENGINE_MANAGER_H
#define __ENGINE_MANAGER_H

#include <stdbool.h>
#include <time.h>

#include "clamav.h"

cl_error_t engine_manager_init(const struct cl_engine *template_engine,
                               const char *dbdir,
                               unsigned int dboptions,
                               time_t keepalive_seconds);
bool engine_manager_enabled(void);
struct cl_engine *engine_manager_get(cl_error_t *status);
void engine_manager_release(struct cl_engine *engine);
void engine_manager_mark_stale(void);
void engine_manager_maybe_unload_idle(void);
void engine_manager_shutdown(void);

#endif
