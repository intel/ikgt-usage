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
#include "policy.h"
#include "log.h"
#include "utils.h"

static uint64_t g_config_info_hva;
static uint64_t g_config_info_hpa;

static uint64_t g_in_addr_hva;
static uint64_t g_out_addr_hva;
static uint64_t g_log_addr_hva;


static uint64_t handle_msg_init(ikgt_event_info_t *event_info, uint64_t log_addr)
{
	start_log(event_info, log_addr);

	return SUCCESS;
}

uint64_t handle_msg_get_config(ikgt_event_info_t *event_info)
{
	uint32_t pages;
	uint32_t size;
	ikgt_status_t status;
	uint64_t tmp;
	config_info_t *config_info;
	uint32_t offset = 0;

	DPRINTF("%s\n", __func__);

	if (g_config_info_hva)
		return g_config_info_hpa;

	pages = MAX_CONFIG_INFO_PAGES + MAX_IN_ADDR_PAGES + MAX_OUT_ADDR_PAGES
		+ g_num_of_cpus * LOG_PAGES_PER_CPU + 1;

	size = PAGES_TO_BYTES(pages);
	DPRINTF("pages=%u, size=%u\n", pages, size);

	tmp = (uint64_t)ikgt_malloc(size);
	if (!tmp) {
		ikgt_printf("%s: Error, ikgt_malloc(%u) == NULL\n", __func__, size);
		return ERROR;
	}

	g_config_info_hva = PAGE_ALIGN_4K(tmp);
	ikgt_printf("0x%llx->0x%llx (g_config_info_hv, aligned)\n", tmp, g_config_info_hva);

	status = util_map_gpa_to_hpa_ex(DEFAULT_VIEW_HANDLE, g_config_info_hva, PERMISSION_READ,
		PAGES_TO_BYTES(MAX_CONFIG_INFO_PAGES));
	if (IKGT_STATUS_SUCCESS != status) {
		ikgt_printf("Error, util_map_gpa_to_hpa_ex failed\n");
		ikgt_free((uint64_t *)tmp);
		g_config_info_hva = 0;
		return ERROR;
	}
	/* should never fail */
	status = util_hva_to_hpa(g_config_info_hva, &g_config_info_hpa);

	DPRINTF("g_config_info_hva=0x%llx, g_config_info_hpa=0x%llx\n", g_config_info_hva, g_config_info_hpa);

	config_info = (config_info_t *)g_config_info_hva;
	config_info->ver.uint64 = HANDLER_REV_NUM;
	offset += PAGES_TO_BYTES(MAX_CONFIG_INFO_PAGES);

	g_in_addr_hva = g_config_info_hva + offset;
	config_info->in_pa = g_config_info_hpa + offset;
	util_map_gpa_to_hpa_ex(DEFAULT_VIEW_HANDLE, g_in_addr_hva, PERMISSION_READ_WRITE,
		PAGES_TO_BYTES(MAX_IN_ADDR_PAGES));
	config_info->in_size = PAGES_TO_BYTES(MAX_IN_ADDR_PAGES);
	offset += PAGES_TO_BYTES(MAX_IN_ADDR_PAGES);
	DPRINTF("in_pa=0x%llx, in_hva=0x%llx\n", config_info->in_pa, g_in_addr_hva);

	g_out_addr_hva = g_config_info_hva + offset;
	config_info->out_pa = g_config_info_hpa + offset;
	status = util_map_gpa_to_hpa_ex(DEFAULT_VIEW_HANDLE, g_out_addr_hva, PERMISSION_READ,
		PAGES_TO_BYTES(MAX_OUT_ADDR_PAGES));
	config_info->out_size = PAGES_TO_BYTES(MAX_OUT_ADDR_PAGES);
	offset += PAGES_TO_BYTES(MAX_OUT_ADDR_PAGES);
	DPRINTF("out_pa=0x%llx, out_hva=0x%llx\n", config_info->out_pa, g_out_addr_hva);

	size = PAGES_TO_BYTES(g_num_of_cpus * LOG_PAGES_PER_CPU);
	g_log_addr_hva = g_config_info_hva + offset;
	config_info->log_pa = g_config_info_hpa + offset;
	status = util_map_gpa_to_hpa_ex(DEFAULT_VIEW_HANDLE, g_log_addr_hva, PERMISSION_READ, size);
	handle_msg_init(event_info, g_log_addr_hva);
	config_info->log_size = size;
	DPRINTF("log_pa=0x%llx, log_hva=0x%llx, size=%u bytes\n", config_info->log_pa, g_log_addr_hva, size);

	/* Assumes gpa == hpa for ikgt memory */
	return g_config_info_hpa;
}

static ikgt_status_t message_sanity_check(uint32_t message_id,
										  uint64_t in_offset, uint64_t out_offset)
{
	ikgt_status_t status = IKGT_STATUS_ERROR;

	if (!g_config_info_hva && (POLICY_GET_CONFIG != message_id)) {
		ikgt_printf("Error, g_config_info_hva=0, message_id %u != POLICY_GET_CONFIG\n",
			message_id);
		return IKGT_STATUS_ERROR;
	}

	switch (message_id) {
	case POLICY_GET_CONFIG:
		status = IKGT_STATUS_SUCCESS;
		break;

	default:
		if ((in_offset < PAGES_TO_BYTES(MAX_IN_ADDR_PAGES))
			&& (out_offset < PAGES_TO_BYTES(MAX_OUT_ADDR_PAGES))
			) {
				status = IKGT_STATUS_SUCCESS;
		}
		break;
	}

	return status;
}

/* Function name: handle_message_event
*
* Purpose:
*         Contains policy to handle agent msg events
*
* Input: IKGT Event Info, arg1 (message id), offset into input and output buffer (arg2, arg3).
* RETURN   : uint64_t
*            SUCCESS (0)
*            ERROR (1)
*
*/
uint64_t handle_message_event(ikgt_event_info_t *event_info,
							  uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
	policy_message_t *in_msg = NULL;
	ikgt_status_t status = IKGT_STATUS_ERROR;
	uint64_t api_result = ERROR;
	message_id_t message_id;
	uint64_t in_offset;
	uint64_t out_offset;

	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;

	message_id = arg1;
	in_offset = arg2;
	out_offset = arg3;

	if (!handler_get_init_status())
		return api_result;

	status = message_sanity_check(message_id, in_offset, out_offset);
	if (IKGT_STATUS_SUCCESS != status) {
		return api_result;
	}

	if (in_offset < PAGES_TO_BYTES(MAX_IN_ADDR_PAGES)) {
		in_msg = (policy_message_t *)(g_in_addr_hva + in_offset);
	}

	DPRINTF("%s: message_id=%d\n", __func__, message_id);

	switch (message_id) {
	case POLICY_GET_CONFIG:
		api_result = handle_msg_get_config(event_info);
		break;

	case POLICY_ENTRY_ENABLE:
		api_result = handle_msg_policy_enable(event_info, &in_msg->policy_data[0]);
		break;

	case POLICY_ENTRY_DISABLE:
		api_result = handle_msg_policy_disable(event_info, &in_msg->policy_data[0]);
		break;

	case POLICY_MAKE_IMMUTABLE:
		api_result = handle_msg_policy_make_immutable(event_info, &in_msg->policy_data[0]);
		break;

#ifdef DEBUG
	case POLICY_GET_TEST:
		api_result = SUCCESS;
		*(uint64_t *)g_out_addr_hva = 0x12345678abcd;
		break;

	case POLICY_DEBUG:
		api_result = handle_msg_debug(event_info, &in_msg->debug_param);
		break;
#endif
	}

	return api_result;
}

#ifdef DEBUG
uint64_t handle_msg_debug(ikgt_event_info_t *event_info, debug_message_t *msg)
{
	if (g_config_info_hva) {
		DPRINTF("*%llx=0x%llx\n", (uint64_t)g_config_info_hva, *(uint64_t *)g_config_info_hva);
	}

	memory_debug(msg->parameter);

	cpu_debug(msg->parameter);

	policy_debug(event_info, msg);

	log_debug(msg->parameter);

	return SUCCESS;
}
#endif

