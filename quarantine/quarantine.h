/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#ifndef CLAMAV_QUARANTINE_H
#define CLAMAV_QUARANTINE_H

#include <limits.h>
#include <stddef.h>

#define CLAMAV_QUARANTINE_ID_LENGTH 33
#define CLAMAV_QUARANTINE_DEFAULT_RETENTION_DAYS 30
#define CLAMAV_QUARANTINE_DEFAULT_MAX_FILE_SIZE (512ULL * 1024ULL * 1024ULL)

#ifdef __cplusplus
extern "C" {
#endif

struct clamav_quarantine_metadata {
    const char *component;
    const char *original_name;
    const char *source;
    const char *detection;
    const char *sha256;
};

struct clamav_quarantine_entry {
    char id[CLAMAV_QUARANTINE_ID_LENGTH];
    char component[64];
    char original_name[PATH_MAX];
    char source[PATH_MAX];
    char detection[PATH_MAX];
    char sha256[65];
    long long size;
    long long created;
};

/* Store a file in the current user's quarantine.
 * move_file is nonzero to remove the source after a successful store. */
int clamav_quarantine_store(const char *source_path,
                            const struct clamav_quarantine_metadata *metadata,
                            int move_file,
                            char id[CLAMAV_QUARANTINE_ID_LENGTH],
                            char payload_path[PATH_MAX]);

/* Return the maximum size of one payload accepted by the quarantine store. */
unsigned long long clamav_quarantine_max_file_size(void);

/* Return the current user's quarantine directory, creating it if necessary. */
int clamav_quarantine_path(char path[PATH_MAX]);

/* List entries owned by the current user. The result must be freed with the
 * matching function. */
int clamav_quarantine_list(struct clamav_quarantine_entry **entries, size_t *count);
void clamav_quarantine_list_free(struct clamav_quarantine_entry *entries);

/* Restore refuses to overwrite an existing destination and removes the
 * quarantine entry only after a successful restore. */
int clamav_quarantine_restore(const char *id, const char *destination_path);
int clamav_quarantine_delete(const char *id);

/* Remove entries older than the configured retention period. */
int clamav_quarantine_cleanup_expired(size_t *deleted);
int clamav_quarantine_get_retention_days(unsigned int *days);
int clamav_quarantine_set_retention_days(unsigned int days);

/* Append one audit record as JSON Lines. Logging is best-effort and does not
 * affect quarantine operations. */
int clamav_quarantine_audit(const char *action, const char *id,
                            const char *component, const char *source,
                            const char *detail, int success);

#ifdef __cplusplus
}
#endif

#endif
