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

#ifndef _POLICY_H_
#define _POLICY_H_

#include "policy_common.h"

#define POLICY_TABLE_VER        0x1
#define POLICY_TABLE_SIGNATURE  0x1689a569

#define POLICY_MAX_ENTRIES (RESOURCE_ID_END - RESOURCE_ID_START)

typedef struct {
	uint32_t	resource_id;
	uint32_t	flags;
	uint32_t	access_count;
	uint32_t	r_action;
	uint32_t	w_action;
	uint32_t	x_action;
	uint64_t	sticky_val;
	uint64_t	resource_info[POLICY_INFO_IDX_MAX];
} policy_entry_t;

typedef struct _policy_table {
	uint64_t        version;
	uint64_t        signature;
	uint64_t        num_entries;
	policy_entry_t  policy_entry[POLICY_MAX_ENTRIES];
} policy_table_t;

#define IS_CR0_ENTRY(e) (((e)->resource_id >= RESOURCE_ID_CR0_PE) && ((e)->resource_id <= RESOURCE_ID_CR0_PG))
#define IS_CR4_ENTRY(e) (((e)->resource_id >= RESOURCE_ID_CR4_VME) && ((e)->resource_id <= RESOURCE_ID_CR4_SMAP))

#define POLICY_ENTRY_R_HAS_SKIP(e) ((e)->r_action & POLICY_ACT_SKIP)
#define POLICY_ENTRY_R_HAS_ALLOW(e) (0 == ((e)->r_action & POLICY_ACT_SKIP))
#define POLICY_ENTRY_R_HAS_LOG(e) ((e)->r_action & POLICY_ACT_LOG)

#define POLICY_ENTRY_HAS_STICKY(e) ((e)->w_action & POLICY_ACT_STICKY)

#define POLICY_ENTRY_W_HAS_SKIP(e) ((e)->w_action & POLICY_ACT_SKIP)
#define POLICY_ENTRY_W_HAS_ALLOW(e) (0 == ((e)->w_action & POLICY_ACT_SKIP))
#define POLICY_ENTRY_W_HAS_LOG(e) ((e)->w_action & POLICY_ACT_LOG)

#define POLICY_ENTRY_X_HAS_SKIP(e) ((e)->x_action & POLICY_ACT_SKIP)
#define POLICY_ENTRY_X_HAS_ALLOW(e) (0 == ((e)->x_action & POLICY_ACT_SKIP))
#define POLICY_ENTRY_X_HAS_LOG(e) ((e)->x_action & POLICY_ACT_LOG)

#define POLICY_ENTRY_INC_ACCESS_COUNT(e) ((e)->access_count++)
#define POLICY_ENTRY_INIT_ACCESS_COUNT(e) ((e)->access_count = 0)
#define POLICY_ENTRY_GET_ACCESS_COUNT(e) ((e)->access_count)

uint64_t handle_msg_policy_enable(ikgt_event_info_t *event_info, policy_update_rec_t *msg);
uint64_t handle_msg_policy_disable(ikgt_event_info_t *event_info, policy_update_rec_t *msg);
uint64_t handle_msg_policy_make_immutable(ikgt_event_info_t *event_info, policy_update_rec_t *msg);

void handle_cr0_event(ikgt_event_info_t *event_info);
void handle_cr4_event(ikgt_event_info_t *event_info);
void handle_msr_event(ikgt_event_info_t *event_info);

boolean_t policy_initialize(void);

void policy_debug(ikgt_event_info_t *event_info, debug_message_t *msg);

uint32_t res_id_to_msr(RESOURCE_ID resource_id);

policy_entry_t *policy_get_entry_by_index(int index);

#define MAX_ACCESS_BUF_SIZE 10
#define MAX_ACTION_BUF_SIZE 10
void action_to_string(ikgt_event_response_t *response, char *str);


#endif /* _POLICY_H_ */
