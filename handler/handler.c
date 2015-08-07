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
#include "utils.h"
#include "string.h"

static boolean_t g_b_init_status = FALSE;
uint16_t g_num_of_cpus;

static void populate_ikgt_event_handlers(ikgt_event_handlers_t *ikgt_event_handlers)
{
	ikgt_event_handlers->memory_event_handler = handle_memory_event;
	ikgt_event_handlers->cpu_event_handler = handle_cpu_event;
	ikgt_event_handlers->message_event_handler = handle_message_event;
}

/* Function Name: handler_initialize
* Purpose: Initialize module specific handlers callback functions
*
* Input: num of cpus
* Return value: TRUE=success, FALSE=failure
*/
boolean_t handler_initialize(uint16_t num_of_cpus)
{
	ikgt_event_handlers_t ikgt_event_handlers;

	g_num_of_cpus = num_of_cpus;

	ikgt_printf("HANDLER: Initializing Handler. Num of CPUs = %d. Built on %s @ %s\n",
		num_of_cpus, __DATE__, __TIME__);

	g_b_init_status = policy_initialize();

	util_zeromem(&ikgt_event_handlers, sizeof(ikgt_event_handlers_t));

	populate_ikgt_event_handlers(&ikgt_event_handlers);

	ikgt_register_handlers(&ikgt_event_handlers);

	return g_b_init_status;
}

boolean_t handler_get_init_status(void)
{
	return g_b_init_status;
}

