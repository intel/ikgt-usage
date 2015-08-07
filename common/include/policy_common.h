/*******************************************************************************
* Copyright (c) 2015 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef _POLICY_COMMON_H
#define _POLICY_COMMON_H

#include "common_types.h"


typedef enum {
	POLICY_GET_CONFIG = 0,
	POLICY_ENTRY_ENABLE,
	POLICY_ENTRY_DISABLE,
	POLICY_MAKE_IMMUTABLE,
	POLICY_GET_TEST,
	POLICY_DEBUG
} message_id_t;

typedef enum {
	SUCCESS = 0,
	ERROR,
	IKGT_NOT_RUNNING,
} ikgt_result_t;

#define PERMISSION_READ  0x1

#define PERMISSION_WRITE  0x2

#define PERMISSION_EXECUTE  0x4

#define PERMISSION_READ_EXECUTE (PERMISSION_READ | PERMISSION_EXECUTE)

#define PERMISSION_READ_WRITE (PERMISSION_READ | PERMISSION_WRITE)

#define PERMISSION_RWX (PERMISSION_READ | PERMISSION_WRITE | PERMISSION_EXECUTE)

/* CR0 constants */
#define PE BIT(0)
#define MP BIT(1)
#define EM BIT(2)
#define TS BIT(3)
#define ET BIT(4)
#define NE BIT(5)
#define WP BIT(16)
#define AM BIT(18)
#define NW BIT(29)
#define CD BIT(30)
#define PG BIT(31)

/* CR4 constants */
#define VME BIT(0)
#define PVI BIT(1)
#define TSD BIT(2)
#define DE  BIT(3)
#define PSE BIT(4)
#define PAE BIT(5)
#define MCE BIT(6)
#define PGE BIT(7)
#define PCE BIT(8)
#define OSFXSR BIT(9)
#define OSXMMEXCPT BIT(10)
#define VMXE BIT(13)
#define SMXE BIT(14)
#define PCIDE BIT(17)
#define OSXSAVE BIT(18)
#define SMEP BIT(20)
#define SMAP BIT(21)

#define POLICY_ACT_LOG     BIT(0)
#define POLICY_ACT_SKIP    BIT(1)
#define POLICY_ACT_ALLOW   0
#define POLICY_ACT_STICKY  BIT(7)
#define LOG_MESSAGE_SIZE   120

#define POLICY_ACT_LOG_ALLOW   (POLICY_ACT_LOG | POLICY_ACT_ALLOW)
#define POLICY_ACT_LOG_SKIP    (POLICY_ACT_LOG | POLICY_ACT_SKIP)
#define POLICY_ACT_LOG_STICKY  (POLICY_ACT_LOG | POLICY_ACT_STICKY)

typedef enum _RESOURCE_ID {
	RESOURCE_ID_START = 1,

	RESOURCE_ID_CR0_PE = RESOURCE_ID_START,
	RESOURCE_ID_CR0_MP,
	RESOURCE_ID_CR0_EM,
	RESOURCE_ID_CR0_TS,
	RESOURCE_ID_CR0_ET,
	RESOURCE_ID_CR0_NE,
	RESOURCE_ID_CR0_WP,
	RESOURCE_ID_CR0_AM,
	RESOURCE_ID_CR0_NW,
	RESOURCE_ID_CR0_CD,
	RESOURCE_ID_CR0_PG,

	RESOURCE_ID_CR4_VME,
	RESOURCE_ID_CR4_PVI,
	RESOURCE_ID_CR4_TSD,
	RESOURCE_ID_CR4_DE,
	RESOURCE_ID_CR4_PSE,
	RESOURCE_ID_CR4_PAE,
	RESOURCE_ID_CR4_MCE,
	RESOURCE_ID_CR4_PGE,
	RESOURCE_ID_CR4_PCE,
	RESOURCE_ID_CR4_OSFXSR,
	RESOURCE_ID_CR4_OSXMMEXCPT,
	RESOURCE_ID_CR4_VMXE,
	RESOURCE_ID_CR4_SMXE,
	RESOURCE_ID_CR4_PCIDE,
	RESOURCE_ID_CR4_OSXSAVE,
	RESOURCE_ID_CR4_SMEP,
	RESOURCE_ID_CR4_SMAP,

	RESOURCE_ID_MSR_EFER,
	RESOURCE_ID_MSR_STAR,
	RESOURCE_ID_MSR_LSTAR,
	RESOURCE_ID_MSR_SYSENTER_CS,
	RESOURCE_ID_MSR_SYSENTER_ESP,
	RESOURCE_ID_MSR_SYSENTER_EIP,
	RESOURCE_ID_MSR_SYSENTER_PAT,


	RESOURCE_ID_END,
	RESOURCE_ID_UNKNOWN
} RESOURCE_ID;

typedef enum {
	POLICY_INFO_IDX_MASK = 0,
	POLICY_INFO_IDX_CPU_MASK_1,
	POLICY_INFO_IDX_CPU_MASK_2,

	POLICY_INFO_IDX_MAX /* last */
} POLICY_RESOUCE_INFO_IDX;

#define POLICY_GET_RESOURCE_ID(e) ((e)->resource_id)
#define POLICY_GET_READ_ACTION(e) ((e)->r_action)
#define POLICY_GET_WRITE_ACTION(e) ((e)->w_action)
#define POLICY_GET_EXEC_ACTION(e) ((e)->x_action)
#define POLICY_GET_STICKY_VALUE(e) ((e)->sticky_val)

#define POLICY_SET_RESOURCE_ID(e, val) ((e)->resource_id = val)
#define POLICY_SET_READ_ACTION(e, val) ((e)->r_action = val)
#define POLICY_SET_WRITE_ACTION(e, val) ((e)->w_action = val)
#define POLICY_SET_EXEC_ACTION(e, val) ((e)->x_action = val)
#define POLICY_SET_STICKY_VALUE(e, val) ((e)->sticky_val = val)

#define POLICY_INFO_SET_MASK(e, val) ((e)->resource_info[POLICY_INFO_IDX_MASK] = val)
#define POLICY_INFO_SET_CPU_MASK_1(e, val) ((e)->resource_info[POLICY_INFO_IDX_CPU_MASK_1] = val)
#define POLICY_INFO_SET_CPU_MASK_2(e, val) ((e)->resource_info[POLICY_INFO_IDX_CPU_MASK_2] = val)

#define POLICY_INFO_GET_MASK(e) ((e)->resource_info[POLICY_INFO_IDX_MASK])
#define POLICY_INFO_GET_CPU_MASK_1(e) ((e)->resource_info[POLICY_INFO_IDX_CPU_MASK_1])
#define POLICY_INFO_GET_CPU_MASK_2(e) ((e)->resource_info[POLICY_INFO_IDX_CPU_MASK_2])

typedef union {
	struct {
		uint32_t	revision_number:32;
		uint32_t	patch:8;
		uint32_t	release_candidate:8;
		uint32_t	release_status:4;
		uint32_t	minor_version:6;
		uint32_t	major_version:6;
	} bits;
	uint64_t uint64;
} version_info_t;

typedef struct {
	version_info_t       ver;
	uint64_t             in_pa;
	uint64_t             in_size;
	uint64_t             out_pa;
	uint64_t             out_size;
	uint64_t             log_pa;
	uint64_t             log_size;
} config_info_t;

typedef struct {
	uint32_t	resource_id;
	uint32_t	r_action;
	uint32_t	w_action;
	uint32_t	x_action;
	uint64_t	sticky_val;
	uint64_t	resource_info[POLICY_INFO_IDX_MAX];
} policy_update_rec_t;

typedef struct {
	char *log_addr;
	uint32_t log_size;
} log_message_t;

typedef struct {
	char *report_addr;
	uint32_t report_size;
} report_message_t;

typedef struct {
	uint64_t parameter;
} debug_message_t;

typedef struct {
	uint32_t	count;
	uint32_t	padding;
	union {
		policy_update_rec_t policy_data[1];
		log_message_t    log_param;
		report_message_t report_param;
		debug_message_t  debug_param;
	};
} policy_message_t;

typedef struct {
	uint64_t seq_num; /* sequence number of this record */
	char message[LOG_MESSAGE_SIZE];
} log_entry_t;


/* each page is 4K size */
#ifndef PAGE_4KB
#define PAGE_4KB 4096
#endif

#define PAGES_TO_BYTES(n) ((n) * PAGE_4KB)

#define MAX_CONFIG_INFO_PAGES 1
#define MAX_IN_ADDR_PAGES     1
#define MAX_OUT_ADDR_PAGES    1

/* two 4K-pages for log data per cpu */
#define LOG_PAGES_PER_CPU  2

/* # of entries per cpu: */
#define ENTRIES_PER_CPU ((LOG_PAGES_PER_CPU * PAGE_4KB) / sizeof(log_entry_t))

/* excluding the first entry (#0), as it is used as meta data instead */
#define LOGS_PER_CPU (ENTRIES_PER_CPU)

#define LOG_SEQ_NUM_TO_INDEX(seq)  (((seq) % LOGS_PER_CPU) - 1)

static inline log_entry_t *get_cpu_log_buffer_start(log_entry_t *log_buffer_base,
													uint32_t cpu_index)
{
	return &(log_buffer_base[cpu_index * ENTRIES_PER_CPU]);
}

#endif /* _POLICY_COMMON_H */
