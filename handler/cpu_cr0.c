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
static uint64_t g_cr0_count;
static uint64_t g_cr0_allow_count;
static uint64_t g_cr0_skip_count;
static uint64_t g_cr0_sticky_count_allow;
static uint64_t g_cr0_sticky_count_skip;


typedef struct _policy_cr0_ctx {
	ikgt_event_info_t *event_info;
	uint64_t new_cr0_value;
	uint64_t cur_cr0_value;
	uint64_t diff;
	boolean_t log;
} policy_cr0_ctx;

typedef struct _cr0_res_id_mask_map {
	uint32_t mask;
	RESOURCE_ID resource_id;
} cr0_res_id_mask_map;

static cr0_res_id_mask_map cr0_res_id_mask_table[] = {
	{PE, RESOURCE_ID_CR0_PE},
	{MP, RESOURCE_ID_CR0_MP},
	{EM, RESOURCE_ID_CR0_EM},
	{TS, RESOURCE_ID_CR0_TS},
	{ET, RESOURCE_ID_CR0_ET},
	{NE, RESOURCE_ID_CR0_NE},
	{WP, RESOURCE_ID_CR0_WP},
	{AM, RESOURCE_ID_CR0_AM},
	{NW, RESOURCE_ID_CR0_NW},
	{CD, RESOURCE_ID_CR0_CD},
	{PG, RESOURCE_ID_CR0_PG},
};


static uint64_t cr0_res_id_to_mask(RESOURCE_ID resource_id)
{
	int i;
	int num_entries;

	num_entries = ARRAY_SIZE(cr0_res_id_mask_table);

	for (i = 0; i < num_entries; i++) {
		if (cr0_res_id_mask_table[i].resource_id == resource_id) {
			return cr0_res_id_mask_table[i].mask;
		}
	}

	return 0;
}

static boolean_t process_cr0_policy(policy_entry_t *entry,
									policy_cr0_ctx *ctx)
{
	uint64_t mask;

	mask = cr0_res_id_to_mask(entry->resource_id);
	if (0 == (mask & ctx->diff))
		return FALSE;

	if (POLICY_ENTRY_W_HAS_LOG(entry))
		ctx->log = TRUE;

	if (POLICY_ENTRY_HAS_STICKY(entry)) {
		if (((ctx->new_cr0_value & mask) && (0 == (POLICY_GET_STICKY_VALUE(entry) & 1)))
			|| ((0 == (ctx->new_cr0_value & mask)) && (POLICY_GET_STICKY_VALUE(entry) & 1))
			) {
				ctx->new_cr0_value ^= mask;
				g_cr0_sticky_count_skip++;
		} else {
			g_cr0_sticky_count_allow++;
		}
	} else if (POLICY_ENTRY_W_HAS_SKIP(entry)) {
		ctx->new_cr0_value ^= mask;
		g_cr0_skip_count++;
	} else {
		g_cr0_allow_count++;
	}

	POLICY_ENTRY_INC_ACCESS_COUNT(entry);

	return TRUE;
}

void handle_cr0_event(ikgt_event_info_t *event_info)
{
	uint64_t new_cr0_value;
	uint64_t cur_cr0_value;
	uint64_t diff;
	ikgt_cpu_event_info_t *cpuinfo;
	ikgt_vmcs_guest_state_reg_id_t operand_reg_id;
	ikgt_status_t status;
	int i, tmp, str_count;
	policy_entry_t *entry;
	policy_cr0_ctx ctx;
	char log_entry_message[LOG_MESSAGE_SIZE];
	char access[MAX_ACCESS_BUF_SIZE], action[MAX_ACTION_BUF_SIZE];

	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
	g_cr0_count++;

	cpuinfo = (ikgt_cpu_event_info_t *)(event_info->event_specific_data);

	if (IKGT_CPU_REG_UNKNOWN == cpuinfo->operand_reg) {
		ikgt_printf("Error, cpuinfo->operand_reg=IKGT_CPU_REG_UNKNOWN\n");
		return;
	}

	status = read_guest_reg(VMCS_GUEST_STATE_CR0, &cur_cr0_value);
	if (IKGT_STATUS_SUCCESS != status) {
		return;
	}

	/* get the VMCS reg ID for the operand */
	status = get_vmcs_guest_reg_id(cpuinfo->operand_reg, &operand_reg_id);
	if (IKGT_STATUS_SUCCESS != status) {
		return;
	}

	/* read the guest register from VMCS
	* new_cr0_value contains the new value to be written to cr0
	*/
	status = read_guest_reg(operand_reg_id, &new_cr0_value);
	if (IKGT_STATUS_SUCCESS != status) {
		return;
	}

	diff = cur_cr0_value ^ new_cr0_value;
	if (0 == diff)
		return;

	ctx.event_info = event_info;
	ctx.new_cr0_value = new_cr0_value;
	ctx.cur_cr0_value = cur_cr0_value;
	ctx.diff = diff;
	ctx.log = FALSE;

	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		entry = policy_get_entry_by_index(i);
		if ((POLICY_GET_RESOURCE_ID(entry) == RESOURCE_ID_UNKNOWN) || !IS_CR0_ENTRY(entry))
			continue;

		process_cr0_policy(entry, &ctx);
	}

	if (ctx.new_cr0_value == cur_cr0_value) {
		event_info->response = IKGT_EVENT_RESPONSE_REDIRECT;
	}

	if (ctx.log) {
		tmp = mon_sprintf_s(access, MAX_ACCESS_BUF_SIZE, "write");
		action_to_string(&event_info->response, action);

		str_count = mon_sprintf_s(log_entry_message, LOG_MESSAGE_SIZE, "resource-name=CR0, access=%s, value=0x%016llx, RIP=0x%016llx, action=%s",
					access, new_cr0_value, event_info->vmcs_guest_state.ia32_reg_rip, action);
		log_event(log_entry_message, event_info->thread_id);
	}

	/* If response is skip then return */
	if (event_info->response == IKGT_EVENT_RESPONSE_REDIRECT)
		return;

	/* TODO: preserve the original value */
	status = write_guest_reg(operand_reg_id, ctx.new_cr0_value);
	if (IKGT_STATUS_SUCCESS != status) {
		ikgt_printf("error, write_guest_reg(%u)=%u\n", operand_reg_id, status);
	}

	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
}

void policy_cr0_dump(void)
{
	ikgt_printf("%s:\n", __func__);

	ikgt_printf("g_cr0_count=%u\n", g_cr0_count);
	ikgt_printf("g_cr0_allow_count=%u\n", g_cr0_allow_count);
	ikgt_printf("g_cr0_skip_count=%u\n", g_cr0_skip_count);

	ikgt_printf("g_cr0_sticky_count_allow=%u\n", g_cr0_sticky_count_allow);
	ikgt_printf("g_cr0_sticky_count_skip=%u\n", g_cr0_sticky_count_skip);

	ikgt_printf("\n");
}

void policy_cr0_debug(uint64_t command_code)
{
	ikgt_printf("%s(%u)\n", __func__, command_code);

	policy_cr0_dump();
}

