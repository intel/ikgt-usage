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
#include "string.h"


/* hva to store logging data allocated by agent and passed to handler.
* It is for all CPUs and is equal to a log_entry_t array:
* g_log_data_hva[num_of_cpus][LOG_CPU_RECORD_NUM]
*/
static log_entry_t *g_log_data_hva;

/* keeps track of sequence numbers per cpu
*
*/
static uint64_t seq_count[MAX_CPUS];

/* VMEXIT log mask by VMEXIT reason: each VMEXIT reason uses a bit in the */
/* mask and set the bit means not recording it */
static uint64_t g_log_mask = 0x400;


/* Function Name: log_event
* Purpose: add event to buffer
*
* Input: IKGT Event Info
* Return value: none
*/
void log_event(char *log_msg, uint64_t cpu_id)
{
	/* per cpu log buffer */
	log_entry_t *cpu_log_buffer;
	uint64_t index;
	ikgt_vmexit_reason_t reason;

	ikgt_get_vmexit_reason(&reason);
	if ((1L << reason.reason) & g_log_mask) {
		/* not recording the VMEXIT if the mask bit for the reason is set */
		return;
	}

	if (NULL == g_log_data_hva) {
		return;
	}

	cpu_log_buffer = get_cpu_log_buffer_start(g_log_data_hva, cpu_id);

	index = LOG_SEQ_NUM_TO_INDEX(seq_count[cpu_id]);
	mon_strcpy_s(cpu_log_buffer[index].message, LOG_MESSAGE_SIZE, log_msg);
	cpu_log_buffer[index].seq_num = seq_count[cpu_id];
	seq_count[cpu_id]++;
}

static void init_cpu_log_buffer(uint64_t cpuid)
{
	/* initialize next sequence number to 1 */
	seq_count[cpuid] = 1;
}

/* Function Name: start_log
* Purpose: set log data storage addr to start profiling
*
* Input: IKGT Event Info
* Return value: none
*/
void start_log(ikgt_event_info_t *event_info, uint64_t log_addr)
{
	ikgt_gva_to_gpa_params_t gva2gpa;
	ikgt_gpa_to_hva_params_t gpa2hva;
	ikgt_status_t status = IKGT_STATUS_SUCCESS;
	int i, j;
	log_entry_t *cpu_buffer;

	DPRINTF("%s: log_addr=%llx, view=%u\n",
		__func__, log_addr, event_info->view_handle);

	DPRINTF("g_num_of_cpus=%u, ENTRIES_PER_CPU=%u\n",
		g_num_of_cpus, ENTRIES_PER_CPU);

	g_log_data_hva = (log_entry_t *)log_addr;

	/* initialize all cpu circular buffers to empty */
	for (i = 0; i < g_num_of_cpus; i++) {
		init_cpu_log_buffer(i);
		cpu_buffer = get_cpu_log_buffer_start(g_log_data_hva, i);
		for (j = 0; j < LOGS_PER_CPU; j++) {
			cpu_buffer[j].seq_num = 0;
		}
	}
}

/* Function Name: stop_log
* Purpose: clear log data storage addr to stop profiling
*
* Input: IKGT Event Info
* Return value: none
*/
void stop_log(ikgt_event_info_t *event_info)
{
	g_log_data_hva = NULL;
}

#ifdef DEBUG
void log_debug(uint64_t command_code)
{
	ikgt_printf("%s(%u)\n", __func__, command_code);

	ikgt_printf("LOGS_PER_CPU=%u\n", LOGS_PER_CPU);
}
#endif

