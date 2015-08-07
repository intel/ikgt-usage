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


static uint64_t g_msr_count;
static uint64_t g_msr_allow_count;
static uint64_t g_msr_skip_count;

static uint64_t g_msr_sticky_count_allow ;
static uint64_t g_msr_sticky_count_skip;


typedef struct _policy_msr_ctx {
	ikgt_event_info_t *event_info;
	uint64_t new_value;
	uint64_t cur_value;
	uint32_t msr_id;
	boolean_t log;
} policy_msr_ctx;

typedef struct _msr_res_id_map {
	uint64_t msr_id;
	RESOURCE_ID resource_id;
} msr_res_id_map;

static msr_res_id_map msr_res_id_table[] = {
	{IA32_MSR_EFER,         RESOURCE_ID_MSR_EFER},
	{IA32_MSR_SYSENTER_CS,  RESOURCE_ID_MSR_SYSENTER_CS},
	{IA32_MSR_SYSENTER_ESP, RESOURCE_ID_MSR_SYSENTER_ESP},
	{IA32_MSR_SYSENTER_EIP, RESOURCE_ID_MSR_SYSENTER_EIP},
	{IA32_MSR_SYSENTER_PAT, RESOURCE_ID_MSR_SYSENTER_PAT},
};


uint32_t res_id_to_msr(RESOURCE_ID resource_id)
{
	int i;
	int num_entries;

	num_entries = ARRAY_SIZE(msr_res_id_table);

	for (i = 0; i < num_entries; i++) {
		if (msr_res_id_table[i].resource_id == resource_id) {
			return msr_res_id_table[i].msr_id;
		}
	}

	return IA32_MSR_INVALID;
}

static boolean_t process_msr_policy(policy_entry_t *entry,
									policy_msr_ctx *ctx)
{
	if (POLICY_ENTRY_W_HAS_LOG(entry))
		ctx->log = TRUE;

	if (POLICY_ENTRY_HAS_STICKY(entry)) {
		if (ctx->new_value == POLICY_GET_STICKY_VALUE(entry)) {
			ctx->event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
			g_msr_sticky_count_allow++;
		} else {
			ctx->event_info->response = IKGT_EVENT_RESPONSE_REDIRECT;
			g_msr_sticky_count_skip++;
		}
	} else if (POLICY_ENTRY_W_HAS_SKIP(entry)) {
		ctx->event_info->response = IKGT_EVENT_RESPONSE_REDIRECT;
		g_msr_skip_count++;
	} else {
		ctx->event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
		g_msr_allow_count++;
	}

	POLICY_ENTRY_INC_ACCESS_COUNT(entry);

	return TRUE;
}

void handle_msr_event(ikgt_event_info_t *event_info)
{
	uint64_t rax, rcx, rdx, new_value, cur_value;
	ikgt_cpu_event_info_t *cpuinfo;
	ikgt_status_t status;
	int i, tmp, str_count;
	policy_entry_t *entry;
	policy_msr_ctx ctx;
	char log_entry_message[LOG_MESSAGE_SIZE];
	char access[MAX_ACCESS_BUF_SIZE], action[MAX_ACTION_BUF_SIZE];

	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
	g_msr_count++;

	cpuinfo = (ikgt_cpu_event_info_t *) (event_info->event_specific_data);

	status = read_guest_reg(IA32_GP_RAX, &rax);
	if (IKGT_STATUS_SUCCESS != status)
		return;

	status = read_guest_reg(IA32_GP_RCX, &rcx);
	if (IKGT_STATUS_SUCCESS != status)
		return;

	status = read_guest_reg(IA32_GP_RDX, &rdx);
	if (IKGT_STATUS_SUCCESS != status)
		return;

#define MAKE_U64(hi, lo) ((((hi) & 0xffffffff) << 32) | ((lo) & 0xffffffff))

	new_value = MAKE_U64(rdx, rax);

	/* rcx = msrid */
	switch (rcx) {
	case IA32_MSR_EFER:
		status = read_guest_reg(VMCS_GUEST_STATE_EFER, &cur_value);
		if (IKGT_STATUS_SUCCESS != status)
			return;
		break;

	case IA32_MSR_SYSENTER_CS:
		status = read_guest_reg(VMCS_GUEST_STATE_SYSENTER_CS, &cur_value);
		if (IKGT_STATUS_SUCCESS != status)
			return;
		break;

	case IA32_MSR_SYSENTER_ESP:
		status = read_guest_reg(VMCS_GUEST_STATE_SYSENTER_ESP, &cur_value);
		if (IKGT_STATUS_SUCCESS != status)
			return;
		break;

	case IA32_MSR_SYSENTER_EIP:
		status = read_guest_reg(VMCS_GUEST_STATE_SYSENTER_EIP, &cur_value);
		if (IKGT_STATUS_SUCCESS != status)
			return;
		break;

	case IA32_MSR_SYSENTER_PAT:
		status = read_guest_reg(VMCS_GUEST_STATE_PAT, &cur_value);
		if (IKGT_STATUS_SUCCESS != status)
			return;
		break;

	default:
		return;
	}

	ctx.event_info = event_info;
	ctx.new_value = new_value;
	ctx.cur_value = cur_value;
	ctx.msr_id = rcx;
	ctx.log = FALSE;

	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		entry = policy_get_entry_by_index(i);
		if ((POLICY_GET_RESOURCE_ID(entry) == RESOURCE_ID_UNKNOWN)
			|| (res_id_to_msr(entry->resource_id) != ctx.msr_id))
			continue;

		if (process_msr_policy(entry, &ctx))
			break;
	}

	if (ctx.log) {
		tmp = mon_sprintf_s(access, MAX_ACCESS_BUF_SIZE, "write");
		action_to_string(&event_info->response, action);

		str_count = mon_sprintf_s(log_entry_message, LOG_MESSAGE_SIZE, "resource-name=msr[0x%x], access=%s, value=0x%016llx, RIP=0x%016llx, action=%s",
					ctx.msr_id, access, new_value, event_info->vmcs_guest_state.ia32_reg_rip, action);
		log_event(log_entry_message, event_info->thread_id);
	}
}

void policy_msr_dump(void)
{
	ikgt_printf("g_msr_count=%u\n", g_msr_count);
	ikgt_printf("g_msr_allow_count=%u\n", g_msr_allow_count);
	ikgt_printf("g_msr_skip_count=%u\n", g_msr_skip_count);
	ikgt_printf("g_msr_sticky_count_allow=%u\n", g_msr_sticky_count_allow);
	ikgt_printf("g_msr_sticky_count_skip=%u\n", g_msr_sticky_count_skip);
}

void policy_msr_debug(uint64_t command_code)
{
	ikgt_printf("%s(%u)\n", __func__, command_code);

	policy_msr_dump();
}
