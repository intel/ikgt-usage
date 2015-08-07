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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/kobject.h>
#include <linux/pagemap.h>

#include "common.h"
#include "policy_common.h"
#include "alloc.h"

static char *g_in_base_addr;
static uint64_t g_in_size;
static atomic_t g_in_lock = ATOMIC_INIT(0);

static char *g_out_base_addr;
static uint64_t g_out_size;
static atomic_t g_out_lock = ATOMIC_INIT(0);

static char *g_log_base_addr;
static uint64_t g_log_size;


bool init_in_buf(char *in_buf, uint64_t size)
{
	g_in_base_addr = in_buf;
	g_in_size = size;

	return true;
}

bool init_out_buf(char *out_buf, uint64_t size)
{
	g_out_base_addr = out_buf;
	g_out_size = size;

	return true;
}

bool init_log_buf(char *log_buf, uint64_t size)
{
	g_log_base_addr = log_buf;
	g_log_size = size;

	return true;
}

char *get_alloc_info_log_addr(void)
{
	return g_log_base_addr;
}

char *allocate_in_buf(uint64_t size, uint64_t *offset)
{
	if (atomic_inc_return(&g_in_lock) > 1) {
		/* Didn't get it */
		atomic_dec(&g_in_lock);
		return NULL;
	}

	/* Currently support only 1 buffer */
	*offset = 0;

	return g_in_base_addr;
}

void free_in_buf(uint64_t offset)
{
	atomic_dec(&g_in_lock);
}

char *allocate_out_buf(uint64_t size, uint64_t *offset)
{
	if (atomic_inc_return(&g_out_lock) > 1) {
		/* Didn't get it */
		atomic_dec(&g_out_lock);
		return NULL;
	}

	/* Currently support only 1 buffer */
	*offset = 0;

	return g_out_base_addr;
}

void free_out_buf(uint64_t offset)
{
	atomic_dec(&g_out_lock);
}


