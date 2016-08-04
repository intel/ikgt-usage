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
#include <linux/version.h>

#include "common.h"
#include "policy_common.h"
#include "log.h"


/* last logging data sequence number per CPU */
static uint64_t *log_record_seq_num;

/* variable used to form one log record as string for temporary */
#define MAX_LOG_RECORD_LEN 256

static uint32_t num_of_cpus;

static log_entry_t *log_data_gva;

#define MAX_SENTINEL_SIZE  64
#define MAX_ELLIPSIS_SIZE  4
#define MAX_CONFIGFS_PAGE_SIZE  (PAGE_4KB - MAX_SENTINEL_SIZE - MAX_ELLIPSIS_SIZE - 1)

static int dump_log(char *configfs_page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static ssize_t log_children_show(struct config_item *item, char *page)
#else
static ssize_t log_children_attr_show(struct config_item *item,
									  struct configfs_attribute *attr,
									  char *page)
#endif
{
	return dump_log(page);
}


static struct configfs_attribute log_children_attr_description = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "log.txt",
	.ca_mode	= S_IRUGO,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	.show		= log_children_show,
#endif
};

static struct configfs_attribute *log_children_attrs[] = {
	&log_children_attr_description,
	NULL,
};


static void log_children_release(struct config_item *item)
{
	kfree(to_node(item));
}

static struct configfs_item_operations log_children_item_ops = {
	.release	= log_children_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.show_attribute = log_children_attr_show,
#endif
};

static struct config_item_type log_children_type = {
	.ct_item_ops	= &log_children_item_ops,
	.ct_attrs	= log_children_attrs,
	.ct_owner	= THIS_MODULE,
};

struct config_item_type *get_log_children_type(void)
{
	return &log_children_type;
}

/* Return: 1=configfs_page is full, 0=configfs_page is not full */
static int log_add_msg_to_configfs(char *configfs_page, char *msg,
								   int msglen, int *offset)
{
	int copy;

	BUG_ON((*offset) >= (MAX_CONFIGFS_PAGE_SIZE - 1));

	copy = min(msglen, MAX_CONFIGFS_PAGE_SIZE - 1 - *offset);

	strncpy(configfs_page + *offset, msg, copy);
	*offset += copy;

	if (copy != msglen) {
		int n;

		n = min(4, MAX_ELLIPSIS_SIZE);
		strncpy(configfs_page + *offset, "...\n", n);
		*offset += n;
		copy += n;

		return 1;
	}

	if (*offset >= (MAX_CONFIGFS_PAGE_SIZE - 1))
		return 1;

	return 0;
}

/*
*   IN cpu_log_buffer: start of the per cpu log buffer
*   IN cpu_index: cpu index
*   OUTPUT results: event contents copy to
*   RETURN: number of logs actually copied
*/
uint32_t read_logs(log_entry_t *cpu_log_buffer, uint32_t cpu_index, log_entry_t results[])
{
	log_entry_t *entry;
	uint32_t nlogs = 0;
	int i;
	uint64_t start;

	start = log_record_seq_num[cpu_index];

	for (i = 0; i < LOGS_PER_CPU; i++) {
		entry = &cpu_log_buffer[i];
		if (entry->seq_num > start) {
			results[nlogs].seq_num = entry->seq_num;
			strncpy(results[nlogs].message, entry->message, LOG_MESSAGE_SIZE);
			nlogs++;

			if (entry->seq_num > log_record_seq_num[cpu_index])
				log_record_seq_num[cpu_index] = entry->seq_num;
		}
	}

	return nlogs;
}

static int dump_log(char *configfs_page)
{
	uint32_t cpu_index = 0;
	uint32_t log_index = 0;
	log_entry_t *cpu_log_buffer;
	int offset = 0;
	int n, full = 0;
	char *sz_log_record;
	uint32_t nlogs;
	uint32_t logs_dumped = 0;
	log_entry_t *results = NULL;
	log_entry_t *entry;

	if (!configfs_page)
		return 0;

	if (NULL == log_record_seq_num)
		return 0;

	sz_log_record = (char *)kzalloc(MAX_LOG_RECORD_LEN + 1, GFP_KERNEL);
	if (NULL == sz_log_record)
		return 0;

	results = (log_entry_t *)kzalloc(LOGS_PER_CPU * sizeof(log_entry_t), GFP_KERNEL);
	if (NULL == results) {
		kfree(sz_log_record);
		return 0;
	}

	for (cpu_index = 0; cpu_index < num_of_cpus; cpu_index++) {

		cpu_log_buffer = get_cpu_log_buffer_start(log_data_gva, cpu_index);

		nlogs = read_logs(cpu_log_buffer, cpu_index, results);

		for (log_index = 0; log_index < nlogs; log_index++) {
			entry = &results[log_index];
			n = snprintf(sz_log_record, MAX_LOG_RECORD_LEN, "cpu=%d, sequence-number=%llu, %s\n", cpu_index, entry->seq_num, entry->message);

			full = log_add_msg_to_configfs(configfs_page, sz_log_record, n, &offset);
			if (full) {
				log_record_seq_num[cpu_index] = entry->seq_num;
				break;
			}
			logs_dumped++;
		}
		if (full)
			break;
	}

	n = snprintf(sz_log_record, MAX_SENTINEL_SIZE - 1, "offset=%u, logs-dumped=%u, full=%d\nEOF\n", offset, logs_dumped, full);
	strncpy(configfs_page + offset, sz_log_record, n);
	offset += n;

	kfree(sz_log_record);
	kfree(results);

	return offset;
}

void init_log(char *log_addr)
{
	if (0 == log_addr)
		return;

	num_of_cpus = num_online_cpus();

	log_record_seq_num = kzalloc(num_of_cpus * sizeof(uint64_t), GFP_KERNEL);
	if (NULL == log_record_seq_num)
		return;

	log_data_gva = (log_entry_t *)log_addr;

	PRINTK_INFO("malloc log data pages at %p\n", log_addr);
}

#ifdef DEBUG
void test_log(void)
{
	log_entry_t *cpu_log_buffer;
	char *p = (char *)log_data_gva;
	uint32_t size ;

	cpu_log_buffer = get_cpu_log_buffer_start(log_data_gva, 0);

	size = num_of_cpus * LOG_PAGES_PER_CPU * PAGE_4KB;
	p[size - 1] = 'E';

	PRINTK_INFO("After: test_log=0x%lx, size=%u bytes\n", (unsigned long)test_log, size);
	PRINTK_INFO("After: p+size-1=%p\n", p + size - 1);
	PRINTK_INFO("After: p[size-1]=%c\n", p[size - 1]);
}
#endif
