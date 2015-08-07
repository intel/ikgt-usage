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
#include "handler.h"
#include "utils.h"
#include "policy.h"
#include "log.h"
#include "string.h"

/* for debugging purpose */
static uint64_t g_cr4_count;
static uint64_t g_cr4_allow_count;
static uint64_t g_cr4_skip_count;
static uint64_t g_cr4_sticky_count_allow;
static uint64_t g_cr4_sticky_count_skip;


typedef struct _policy_cr4_ctx {
	ikgt_event_info_t *event_info;
	uint64_t new_cr4_value;
	uint64_t cur_cr4_value;
	uint64_t diff;
	boolean_t log;
} policy_cr4_ctx;

typedef struct _cr4_res_id_mask_map {
	uint32_t mask;
	RESOURCE_ID resource_id;
} cr4_res_id_mask_map;

static cr4_res_id_mask_map cr4_res_id_mask_table[] = {
	{VME,        RESOURCE_ID_CR4_VME},
	{PVI,        RESOURCE_ID_CR4_PVI},
	{TSD,        RESOURCE_ID_CR4_TSD},
	{DE,         RESOURCE_ID_CR4_DE},
	{PSE,        RESOURCE_ID_CR4_PSE},
	{PAE,        RESOURCE_ID_CR4_PAE},
	{MCE,        RESOURCE_ID_CR4_MCE},
	{PGE,        RESOURCE_ID_CR4_PGE},
	{PCE,        RESOURCE_ID_CR4_PCE},
	{OSFXSR,     RESOURCE_ID_CR4_OSFXSR},
	{OSXMMEXCPT, RESOURCE_ID_CR4_OSXMMEXCPT},
	{VMXE,       RESOURCE_ID_CR4_VMXE},
	{SMXE,       RESOURCE_ID_CR4_SMXE},
	{PCIDE,      RESOURCE_ID_CR4_PCIDE},
	{OSXSAVE,    RESOURCE_ID_CR4_OSXSAVE},
	{SMEP,       RESOURCE_ID_CR4_SMEP},
	{SMAP,       RESOURCE_ID_CR4_SMAP}
};


static uint64_t cr4_res_id_to_mask(RESOURCE_ID resource_id)
{
	int i;
	int num_entries;

	num_entries = ARRAY_SIZE(cr4_res_id_mask_table);

	for (i = 0; i < num_entries; i++) {
		if (cr4_res_id_mask_table[i].resource_id == resource_id) {
			return cr4_res_id_mask_table[i].mask;
		}
	}

	return 0;
}

static boolean_t process_cr4_policy(policy_entry_t *entry,
									policy_cr4_ctx *ctx)

{
	uint64_t mask;

	mask = cr4_res_id_to_mask(entry->resource_id);
	if (0 == (mask & ctx->diff))
		return FALSE;

	if (POLICY_ENTRY_W_HAS_LOG(entry))
		ctx->log = TRUE;

	if (POLICY_ENTRY_HAS_STICKY(entry)) {
		if (((ctx->new_cr4_value & mask) && (0 == (POLICY_GET_STICKY_VALUE(entry) & 1)))
			|| ((0 == (ctx->new_cr4_value & mask)) && (POLICY_GET_STICKY_VALUE(entry) & 1))
			) {
				ctx->new_cr4_value ^= mask;
				g_cr4_sticky_count_skip++;
		} else {
			g_cr4_sticky_count_allow++;
		}
	} else if (POLICY_ENTRY_W_HAS_SKIP(entry)) {
		ctx->new_cr4_value ^= mask;
		g_cr4_skip_count++;
	} else {
		g_cr4_allow_count++;
	}

	POLICY_ENTRY_INC_ACCESS_COUNT(entry);

	return TRUE;
}

void handle_cr4_event(ikgt_event_info_t *event_info)
{
	uint64_t new_cr4_value;
	uint64_t cur_cr4_value;
	uint64_t diff;
	ikgt_cpu_event_info_t *cpuinfo;
	ikgt_vmcs_guest_state_reg_id_t operand_reg_id;
	ikgt_status_t status;
	int i, tmp, str_count;
	policy_entry_t *entry;
	policy_cr4_ctx ctx;
	char log_entry_message[LOG_MESSAGE_SIZE];
	char access[MAX_ACCESS_BUF_SIZE], action[MAX_ACTION_BUF_SIZE];

	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
	g_cr4_count++;

	cpuinfo = (ikgt_cpu_event_info_t *) (event_info->event_specific_data);

	if (IKGT_CPU_REG_UNKNOWN == cpuinfo->operand_reg) {
		ikgt_printf("Error, cpuinfo->operand_reg=IKGT_CPU_REG_UNKNOWN\n");
		return;
	}

	status = read_guest_reg(VMCS_GUEST_STATE_CR4, &cur_cr4_value);
	if (IKGT_STATUS_SUCCESS != status) {
		return;
	}

	/* get the VMCS reg ID for the operand */
	status = get_vmcs_guest_reg_id(cpuinfo->operand_reg, &operand_reg_id);
	if (IKGT_STATUS_SUCCESS != status) {
		return;
	}

	/* read the guest register from VMCS
	* new_cr4_value contains the new value to be written to cr4
	*/
	status = read_guest_reg(operand_reg_id, &new_cr4_value);
	if (IKGT_STATUS_SUCCESS != status) {
		return;
	}

	diff = cur_cr4_value ^ new_cr4_value;
	if (0 == diff)
		return;

	ctx.event_info = event_info;
	ctx.new_cr4_value = new_cr4_value;
	ctx.cur_cr4_value = cur_cr4_value;
	ctx.diff = diff;
	ctx.log = FALSE;

	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		entry = policy_get_entry_by_index(i);
		if ((POLICY_GET_RESOURCE_ID(entry) == RESOURCE_ID_UNKNOWN) || !IS_CR4_ENTRY(entry))
			continue;

		process_cr4_policy(entry, &ctx);
	}

	if (ctx.new_cr4_value == cur_cr4_value) {
		event_info->response = IKGT_EVENT_RESPONSE_REDIRECT;
	}

	if (ctx.log) {
		tmp = mon_sprintf_s(access, MAX_ACCESS_BUF_SIZE, "write");
		action_to_string(&event_info->response, action);

		str_count = mon_sprintf_s(log_entry_message, LOG_MESSAGE_SIZE, "resource-name=CR4, access=%s, value=0x%016llx, RIP=0x%016llx, action=%s",
					access, new_cr4_value, event_info->vmcs_guest_state.ia32_reg_rip, action);
		log_event(log_entry_message, event_info->thread_id);
	}

	/* If response is skip then return */
	if (event_info->response == IKGT_EVENT_RESPONSE_REDIRECT)
		return;

	status = write_guest_reg(operand_reg_id, ctx.new_cr4_value);
	if (IKGT_STATUS_SUCCESS != status) {
		ikgt_printf("error, write_guest_reg(%u)=%u\n", operand_reg_id, status);
	}

	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
}

void policy_cr4_dump(void)
{
	ikgt_printf("%s:\n", __func__);

	ikgt_printf("g_cr4_count=%u\n", g_cr4_count);
	ikgt_printf("g_cr4_allow_count=%u\n", g_cr4_allow_count);
	ikgt_printf("g_cr4_skip_count=%u\n", g_cr4_skip_count);

	ikgt_printf("g_cr4_sticky_count_allow=%u\n", g_cr4_sticky_count_allow);
	ikgt_printf("g_cr4_sticky_count_skip=%u\n", g_cr4_sticky_count_skip);

	ikgt_printf("\n");
}

void policy_cr4_debug(uint64_t command_code)
{
	ikgt_printf("%s(%u)\n", __func__, command_code);

	policy_cr4_dump();
}

