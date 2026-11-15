/* Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. */

#include "quarantine.h"

#include <stddef.h>

int main(void)
{
    size_t deleted = 0;
    return clamav_quarantine_cleanup_expired(&deleted) ? 0 : 1;
}
