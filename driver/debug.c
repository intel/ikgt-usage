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
#include <linux/sysctl.h>
#include <linux/pagemap.h>

#include "ikgt_api.h"
#include "common.h"
#include "debug.h"
#include "log.h"
#include "alloc.h"


#ifdef DEBUG
static int ikgt_agent_debug;

void test_hypercall(void);


static int ikgt_systl_debug(struct ctl_table *ctl, int write,
							void __user *buffer, size_t *count,
							loff_t *ppos)
{
	unsigned long val;
	int len, rc;
	char buf[32];

	if (!*count || (*ppos && !write)) {
		*count = 0;
		return 0;
	}

	if (!write) {
		len = snprintf(buf, sizeof(buf), "%d\n", ikgt_agent_debug);
		rc = copy_to_user(buffer, buf, sizeof(buf));
		if (rc != 0)
			return -EFAULT;
	} else {
		len = *count;
		rc = kstrtoul_from_user(buffer, len, 0, &val);
		if (rc)
			return rc;

		ikgt_agent_debug = val;

		switch (val) {
		case 1000:
			test_log();
			break;

		case 1001:
			test_hypercall();
			break;

		default:
			ikgt_debug(val);
			break;
		}
	}
	*count = len;
	*ppos += len;


	return 0;
}

/* sysctl -w kernel.ikgt_agent_debug=100 */
static struct ctl_table ikgt_sysctl_table[] = {
	{
		.procname	= "ikgt_agent_debug",
			.mode	= 0644,
			.proc_handler	= ikgt_systl_debug,
	},
	{}
};

static struct ctl_table kern_dir_table[] = {
	{
		.procname	= "kernel",
			.maxlen		= 0,
			.mode		= 0555,
			.child		= ikgt_sysctl_table,
	},
	{}
};

static struct ctl_table_header *ikgt_sysctl_header;


void ikgt_debug(uint64_t parameter)
{
	policy_message_t *msg;
	uint64_t ret;
	uint64_t in_offset;

	PRINTK_INFO("%s: parameter=%llu\n", __func__, parameter);

	msg = (policy_message_t *)allocate_in_buf(sizeof(policy_message_t), &in_offset);
	if (msg == NULL)
		return;

	msg->count = 1;
	msg->debug_param.parameter = parameter;

	ret = ikgt_hypercall(POLICY_DEBUG, in_offset, 0);
	if (SUCCESS != ret) {
		PRINTK_ERROR("%s: ikgt_hypercall failed, ret=%llu\n", __func__, ret);
	}

	free_in_buf(in_offset);
}

void test_hypercall(void)
{
	uint64_t out_buf;
	uint64_t out_offset;
	uint64_t ret;

	out_buf = (uint64_t)allocate_out_buf(sizeof(policy_message_t), &out_offset);

	ret = ikgt_hypercall(POLICY_GET_TEST, 0, out_offset);
	if (SUCCESS != ret) {
		PRINTK_ERROR("%s: ikgt_hypercall failed, ret=%llu\n", __func__, ret);
	}

	PRINTK_INFO("%s: *0x%llx=0x%llx\n", __func__, out_buf, *(uint64_t *)out_buf);

	free_out_buf(out_offset);
}

void init_debug(void)
{
	ikgt_sysctl_header = register_sysctl_table(kern_dir_table);
}

void uninit_debug(void)
{
	unregister_sysctl_table(ikgt_sysctl_header);
}

#endif
