/*
* This is an example ikgt usage driver.
* Copyright (c) 2015, Intel Corporation.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*/

#ifndef _ALLOC_H
#define _ALLOC_H

#include "policy_common.h"


bool init_in_buf(char *in_buf, uint64_t size);

bool init_out_buf(char *out_buf, uint64_t size);

bool init_log_buf(char *log_buf, uint64_t size);

char *get_alloc_info_log_addr(void);

char *allocate_in_buf(uint64_t size, uint64_t *offset);

void free_in_buf(uint64_t offset);

char *allocate_out_buf(uint64_t size, uint64_t *offset);

void free_out_buf(uint64_t offset);


#endif /* _ALLOC_H */
