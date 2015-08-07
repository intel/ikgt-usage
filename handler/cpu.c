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
#include "ikgt_handler_api.h"
#include "handler.h"
#include "policy.h"
#include "log.h"


static uint64_t g_cpu_reg_count;
static uint64_t g_cpu_msr_count;


/* Function name: handle_cpu_event
*
* Purpose:
*         Contains policy to handle CPU events
*
* Input: IKGT Event Info
* Return: None
*
*/
void handle_cpu_event(ikgt_event_info_t *event_info)
{
	ikgt_cpu_event_info_t *cpuinfo;

	/* log handler only profiling so allow all other actions by default */
	event_info->response = IKGT_EVENT_RESPONSE_ALLOW;

	if (!handler_get_init_status())
		return;

	cpuinfo = (ikgt_cpu_event_info_t *)(event_info->event_specific_data);

	switch (cpuinfo->optype) {
	case IKGT_CPU_EVENT_OP_CPUID:
		event_info->response = IKGT_EVENT_RESPONSE_UNSPECIFIED;
		break;

	case IKGT_CPU_EVENT_OP_REG:
		g_cpu_reg_count++;

		switch (cpuinfo->event_reg) {
		case IKGT_CPU_REG_CR0:
			handle_cr0_event(event_info);
			break;

		case IKGT_CPU_REG_CR4:
			handle_cr4_event(event_info);
			break;

		default:
			break;
		}
		break;

	/* MSR Write */
	case IKGT_CPU_EVENT_OP_MSR:
		g_cpu_msr_count++;
		handle_msr_event(event_info);
		break;

	default:
		break;
	}
}

void cpu_debug(uint64_t command_code)
{
	ikgt_printf("%s(%u)\n", __func__, command_code);

	ikgt_printf("g_cpu_reg_count=%u\n", g_cpu_reg_count);

	ikgt_printf("g_cpu_msr_count=%u\n", g_cpu_msr_count);
}