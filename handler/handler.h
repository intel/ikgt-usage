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

#ifndef _HANDLER_H_
#define _HANDLER_H_

#define DEBUG

#include "ikgt_handler_api.h"
#include "policy_common.h"


#ifdef DEBUG
#define DPRINTF(fmt, args...)  ikgt_printf(fmt, ##args)
#else
#define DPRINTF(fmt, args...)
#endif

#define HANDLER_REV_NUM       0x1

#define IA32_MSR_EFER         0xC0000080
#define IA32_MSR_SYSENTER_CS  0x174
#define IA32_MSR_SYSENTER_ESP 0x175
#define IA32_MSR_SYSENTER_EIP 0x176
#define IA32_MSR_SYSENTER_PAT 0x277
#define IA32_MSR_INVALID      0

#define PAGE_SHIFT      12
#define ALIGN(x, a)    (((x) + (a) - 1) & ~((a) - 1))
#define PAGE_ALIGN_4K(x)    ALIGN(x, PAGE_4KB)

#define BIT(x) (1<<x)

#define min(X, Y) ((X) < (Y) ? (X) : (Y))

typedef enum {
	EXECUTE_VIOLATION,
	WRITE_VIOLATION,
	READ_VIOLATION,
	NOT_PRESENT_VIOLATION,
	UNKNOWN_VIOLATION
} violation_type_t;

void handle_memory_event(ikgt_event_info_t *event_info);
void handle_cpu_event(ikgt_event_info_t *event_info);
uint64_t handle_message_event(ikgt_event_info_t *event_info,
							  uint64_t arg1, uint64_t arg2, uint64_t arg3);

uint64_t handle_msg_debug(ikgt_event_info_t *event_info, debug_message_t *msg);

void memory_debug(uint64_t command_code);
void cpu_debug(uint64_t command_code);
void log_debug(uint64_t command_code);

boolean_t handler_get_init_status(void);

extern uint16_t g_num_of_cpus;

#endif /* _HANDLER_H_ */
