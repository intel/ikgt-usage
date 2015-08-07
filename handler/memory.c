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
#include "log.h"

static uint64_t g_mem_read_count;
static uint64_t g_mem_write_count;
static uint64_t g_mem_exec_count;


/* Function name: handle_memory_event
*
* Purpose:
*         Contains policy to handle Memory events
*
* Input: IKGT Event Info
* Return: None
* NOTE: By default response code is set to IKGT_EVENT_RESPONSE_UNSPECIFIED
*       Make sure to set the response code to some specific value.
*/
void handle_memory_event(ikgt_event_info_t *event_info)
{
	ikgt_mem_event_info_t *meminfo;
	violation_type_t type;

	event_info->response = IKGT_EVENT_RESPONSE_UNSPECIFIED;

	if (!handler_get_init_status())
		return;

	meminfo = (ikgt_mem_event_info_t *)(event_info->event_specific_data);

	/* determine the type of access that caused this event */
	if ((0 == meminfo->perms.bit.executable)
		&& (1 == meminfo->attempt.bit.executable)) {
		type = EXECUTE_VIOLATION;
	} else if ((0 == meminfo->perms.bit.readable)
		&& (1 == meminfo->attempt.bit.readable)) {
		type = READ_VIOLATION;
	} else if ((0 == meminfo->perms.bit.writable)
		&& (1 == meminfo->attempt.bit.writable)) {
		type = WRITE_VIOLATION;
	} else {
		type = UNKNOWN_VIOLATION;
	}

	switch (type) {
	case EXECUTE_VIOLATION:
		g_mem_exec_count++;
		break;

	case READ_VIOLATION:
		g_mem_read_count++;
		event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
		break;

	case WRITE_VIOLATION:
		g_mem_write_count++;
		event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
		break;

	case UNKNOWN_VIOLATION:
		event_info->response = IKGT_EVENT_RESPONSE_ALLOW;
		break;
	}
}

void memory_debug(uint64_t command_code)
{
	ikgt_printf("%s(%u)\n", __func__, command_code);

	ikgt_printf("g_mem_write_count=%u\n", g_mem_write_count);
}
