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
#include "utils.h"
#include "policy.h"
#include "string.h"

static ikgt_lock_t g_policy_table_lock;
static policy_table_t *g_policy_table;
static boolean_t g_policy_immutable = FALSE;

static void policy_entry_add(policy_entry_t *entry);


void add_default_policy(void)
{
	static policy_entry_t default_policy_table[] = {
		{.resource_id = RESOURCE_ID_CR0_PG, .w_action = POLICY_ACT_LOG_SKIP},
		{.resource_id = RESOURCE_ID_CR0_WP, .w_action = POLICY_ACT_LOG_ALLOW},
		{.resource_id = RESOURCE_ID_CR4_PAE, .w_action = POLICY_ACT_LOG_SKIP},
		{.resource_id = RESOURCE_ID_MSR_EFER, .w_action = POLICY_ACT_LOG_SKIP},

		/* Table terminator, must come last */
		{.resource_id = RESOURCE_ID_UNKNOWN}
	};

	int i;

	for (i = 0; default_policy_table[i].resource_id != RESOURCE_ID_UNKNOWN; i++) {
		policy_entry_add(&default_policy_table[i]);
	}
}

boolean_t policy_initialize(void)
{
	int i;

	if (g_policy_table != NULL)
		return TRUE;

	g_policy_table = (policy_table_t *) ikgt_malloc(sizeof(policy_table_t));

	if (g_policy_table == NULL) {
		ikgt_printf("Error, g_policy_table == NULL\n");

		return FALSE;
	}

	ikgt_lock_initialize(&g_policy_table_lock);

	g_policy_table->version = POLICY_TABLE_VER;
	g_policy_table->signature = POLICY_TABLE_SIGNATURE;
	g_policy_table->num_entries = 0;

	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		/* mark as free */
		POLICY_SET_RESOURCE_ID(&g_policy_table->policy_entry[i], RESOURCE_ID_UNKNOWN);
	}

	return TRUE;
}

#ifdef DEBUG
#define RES_ID_MAP_INIT(id)	[id] = #id
/* resource id to string, for debugging purpose */
static const char *res_id_to_string(uint32_t id)
{
	static const char *res_id_str_array[] = {
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_PE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_MP),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_EM),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_TS),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_ET),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_NE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_WP),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_AM),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_NW),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_CD),
		RES_ID_MAP_INIT(RESOURCE_ID_CR0_PG),

		RES_ID_MAP_INIT(RESOURCE_ID_CR4_VME),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_PVI),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_TSD),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_DE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_PSE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_PAE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_MCE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_PGE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_PCE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_OSFXSR),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_OSXMMEXCPT),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_VMXE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_SMXE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_PCIDE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_OSXSAVE),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_SMEP),
		RES_ID_MAP_INIT(RESOURCE_ID_CR4_SMAP),

		RES_ID_MAP_INIT(RESOURCE_ID_MSR_EFER),
		RES_ID_MAP_INIT(RESOURCE_ID_MSR_STAR),
		RES_ID_MAP_INIT(RESOURCE_ID_MSR_LSTAR),
		RES_ID_MAP_INIT(RESOURCE_ID_MSR_SYSENTER_CS),
		RES_ID_MAP_INIT(RESOURCE_ID_MSR_SYSENTER_ESP),
		RES_ID_MAP_INIT(RESOURCE_ID_MSR_SYSENTER_EIP),
		RES_ID_MAP_INIT(RESOURCE_ID_MSR_SYSENTER_PAT),
	};

	if ((id >= RESOURCE_ID_START) && (id < RESOURCE_ID_END))
		return res_id_str_array[id];

	return "";
}
#endif

static void policy_entry_add(policy_entry_t *entry)
{
	int i;

#ifdef DEBUG
	ikgt_printf("%s: res_id=%u (%s)\n",
		__func__,
		POLICY_GET_RESOURCE_ID(entry), res_id_to_string(POLICY_GET_RESOURCE_ID(entry)));

	ikgt_printf("(r, w, x)=(0x%x, 0x%x, 0x%x), sticky_val=0x%llx\n",
		POLICY_GET_READ_ACTION(entry),
		POLICY_GET_WRITE_ACTION(entry),
		POLICY_GET_EXEC_ACTION(entry),
		POLICY_GET_STICKY_VALUE(entry)
		);


	for (i = 0; i < POLICY_INFO_IDX_MAX; i++) {
		if (entry->resource_info[i]) {
			ikgt_printf("resource_info[%u]=0x%llx\n", i, entry->resource_info[i]);
		}
	}
#endif

	ikgt_lock_acquire(&g_policy_table_lock);

	for (i = 0; i < POLICY_MAX_ENTRIES ; i++) {
		if (POLICY_GET_RESOURCE_ID(&g_policy_table->policy_entry[i]) == POLICY_GET_RESOURCE_ID(entry)) {
			/* overwrite the existing entry */
			g_policy_table->policy_entry[i] = *entry;
			ikgt_lock_release(&g_policy_table_lock);
			return;
		}
	}

	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		if (POLICY_GET_RESOURCE_ID(&g_policy_table->policy_entry[i]) == RESOURCE_ID_UNKNOWN) {
			/* found a free slot */
			g_policy_table->policy_entry[i] = *entry;
			g_policy_table->num_entries++;
			ikgt_lock_release(&g_policy_table_lock);
			return;
		}
	}

	DPRINTF("Error, policy table is full, unable to add cpu policy entry!\n");
}

static ikgt_status_t policy_monitor_cpu_events(policy_entry_t *entry,
											   ikgt_cpu_reg_t reg,
											   boolean_t enable)
{
	ikgt_status_t status;
	uint64_t cpu_bitmap[CPU_BITMAP_MAX];

	cpu_bitmap[0] = POLICY_INFO_GET_CPU_MASK_1(entry);
	cpu_bitmap[1] = POLICY_INFO_GET_CPU_MASK_2(entry);

	status = util_monitor_cpu_events(cpu_bitmap,
		POLICY_INFO_GET_MASK(entry),
		reg,
		enable);

	DPRINTF("%s: status=%u, cpu0=%llx, cpu1=%llx, mask=%llx, enable=%u\n",
		__func__, status,
		POLICY_INFO_GET_CPU_MASK_1(entry), POLICY_INFO_GET_CPU_MASK_2(entry),
		POLICY_INFO_GET_MASK(entry), enable
		);

	return status;
}

static ikgt_status_t policy_monitor_msr(policy_entry_t *entry,
										uint32_t msr_id,
										boolean_t enable)
{
	ikgt_status_t status;

	status = util_monitor_msr(msr_id, enable);

	DPRINTF("%s: status=%d, msr_id=0x%x, enable=%u\n",
		__func__, status, msr_id, enable);

	return status;
}

static void policy_msg_to_entry(policy_update_rec_t *msg,
								policy_entry_t *policy_entry)
{
	int i;

	if ((msg == NULL) || (policy_entry == NULL))
		return;

	POLICY_SET_RESOURCE_ID(policy_entry, POLICY_GET_RESOURCE_ID(msg));
	POLICY_SET_STICKY_VALUE(policy_entry, POLICY_GET_STICKY_VALUE(msg));

	POLICY_SET_READ_ACTION(policy_entry, POLICY_GET_READ_ACTION(msg));
	POLICY_SET_WRITE_ACTION(policy_entry, POLICY_GET_WRITE_ACTION(msg));
	POLICY_SET_EXEC_ACTION(policy_entry, POLICY_GET_EXEC_ACTION(msg));

	for (i = 0; i < POLICY_INFO_IDX_MAX; i++) {
		policy_entry->resource_info[i] = msg->resource_info[i];
	}

	POLICY_ENTRY_INIT_ACCESS_COUNT(policy_entry);
}

static void policy_entry_del(policy_entry_t *entry)
{
	int i;

	DPRINTF("%s (resource_id=%u)\n", __func__, entry->resource_id);

	ikgt_lock_acquire(&g_policy_table_lock);

	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		if (POLICY_GET_RESOURCE_ID(&g_policy_table->policy_entry[i]) == POLICY_GET_RESOURCE_ID(entry)) {
			/* mark as free */
			POLICY_SET_RESOURCE_ID(&g_policy_table->policy_entry[i], RESOURCE_ID_UNKNOWN);

			POLICY_ENTRY_INIT_ACCESS_COUNT(&g_policy_table->policy_entry[i]);

			if (g_policy_table->num_entries)
				g_policy_table->num_entries--;

			break;
		}
	}

	ikgt_lock_release(&g_policy_table_lock);
}

static ikgt_status_t policy_sanity_check(policy_update_rec_t *msg)
{
	return IKGT_STATUS_SUCCESS;
}

static ikgt_status_t policy_set_monitor(policy_entry_t *entry, boolean_t enable)
{
	ikgt_status_t status = IKGT_STATUS_ERROR;
	uint32_t  msr_id;

	if (IS_CR0_ENTRY(entry)) {
		status = policy_monitor_cpu_events(entry, IKGT_CPU_REG_CR0, enable);
	} else if (IS_CR4_ENTRY(entry)) {
		status = policy_monitor_cpu_events(entry, IKGT_CPU_REG_CR4, enable);
	} else {
		msr_id = res_id_to_msr(POLICY_GET_RESOURCE_ID(entry));
		if (msr_id != IA32_MSR_INVALID)
			status = policy_monitor_msr(entry, msr_id, enable);
	}

	return status;
}

static ikgt_status_t policy_msg_add(policy_update_rec_t *msg)
{
	policy_entry_t entry;

	ikgt_status_t status = IKGT_STATUS_ERROR;

	if (g_policy_table == NULL)
		return IKGT_STATUS_ERROR;

	if (msg->resource_id == RESOURCE_ID_UNKNOWN)
		return IKGT_STATUS_ERROR;

	policy_msg_to_entry(msg, &entry);

	policy_entry_add(&entry);

	status = policy_set_monitor(&entry, TRUE);

	return status;
}

static ikgt_status_t policy_msg_del(policy_update_rec_t *msg)
{
	policy_entry_t entry;
	uint32_t  msr_id;
	ikgt_status_t status = IKGT_STATUS_ERROR;

	if (g_policy_table == NULL)
		return IKGT_STATUS_ERROR;

	if (msg->resource_id == RESOURCE_ID_UNKNOWN)
		return IKGT_STATUS_ERROR;

	policy_msg_to_entry(msg, &entry);

	status = policy_set_monitor(&entry, FALSE);

	policy_entry_del(&entry);

	return status;
}

uint64_t handle_msg_policy_enable(ikgt_event_info_t *event_info, policy_update_rec_t *msg)
{
	if (g_policy_immutable)
		return ERROR;

	if (IKGT_STATUS_SUCCESS != policy_sanity_check(msg)) {
		ikgt_printf("Error, policy_sanity_check() failed\n");
	} else {
		policy_msg_add(msg);
	}

	return SUCCESS;
}

uint64_t handle_msg_policy_disable(ikgt_event_info_t *event_info, policy_update_rec_t *msg)
{
	if (g_policy_immutable)
		return ERROR;

	if (IKGT_STATUS_SUCCESS != policy_sanity_check(msg)) {
		ikgt_printf("Error, policy_sanity_check() failed\n");
	} else {
		policy_msg_del(msg);
	}

	return SUCCESS;
}

uint64_t handle_msg_policy_make_immutable(ikgt_event_info_t *event_info, policy_update_rec_t *msg)
{
	DPRINTF("%s\n", __func__);

	if (g_policy_immutable)
		return ERROR;

	g_policy_immutable = TRUE;

	return SUCCESS;
}

policy_entry_t *policy_get_entry_by_index(int index)
{
	return &g_policy_table->policy_entry[index];
}

void policy_dump(uint64_t command_code)
{
#ifdef DEBUG
	int i, j;
	uint64_t reg_value;
	ikgt_status_t status;
	policy_entry_t *entry;
	int count;

	ikgt_printf("%s:\n", __func__);

	ikgt_printf("POLICY_MAX_ENTRIES=%u\n", POLICY_MAX_ENTRIES);

	ikgt_printf("num_entries=%u\n", g_policy_table->num_entries);
	ikgt_printf("sizeof(policy_update_rec_t)=%u\n", sizeof(policy_update_rec_t));
	ikgt_printf("sizeof(policy_entry_t)=%u\n", sizeof(policy_entry_t));
	ikgt_printf("sizeof(policy_table_t)=%u\n", sizeof(policy_table_t));
	ikgt_printf("g_policy_immutable=%u\n", g_policy_immutable);

	count = 0;
	for (i = 0; i < POLICY_MAX_ENTRIES; i++) {
		entry = &g_policy_table->policy_entry[i];
		if (POLICY_GET_RESOURCE_ID(entry) == RESOURCE_ID_UNKNOWN)
			continue;

		ikgt_printf("#%d:\n", i);

		ikgt_printf("resource_id=%u (%s)\n", POLICY_GET_RESOURCE_ID(entry), res_id_to_string(POLICY_GET_RESOURCE_ID(entry)));
		ikgt_printf("sticky_val=0x%llx\n", POLICY_GET_STICKY_VALUE(entry));
		ikgt_printf("rwx=(0x%x, 0x%x, 0x%x)\n",
			POLICY_GET_READ_ACTION(entry), POLICY_GET_WRITE_ACTION(entry), POLICY_GET_EXEC_ACTION(entry));
		ikgt_printf("access_count=%u\n", POLICY_ENTRY_GET_ACCESS_COUNT(entry));

		for (j = 0; j < POLICY_INFO_IDX_MAX; j++) {
			if (entry->resource_info[j]) {
				ikgt_printf("resource_info[%u]=0x%llx\n", j, entry->resource_info[j]);
			}
		}

		count++;
		if (count > 100) {
			ikgt_printf("count > 100\n");
			break;
		}
	}

	ikgt_printf("\n");
#endif
}

void policy_cr0_debug(uint64_t parameter);
void policy_cr4_debug(uint64_t parameter);
void policy_msr_debug(uint64_t parameter);

void policy_debug(ikgt_event_info_t *event_info, debug_message_t *msg)
{
	ikgt_printf("%s: %lu\n", __func__, msg->parameter);

	switch (msg->parameter) {
	case 400:
		handle_msg_policy_make_immutable(NULL, NULL);
		break;

	default:
		policy_dump(msg->parameter);
		policy_cr0_debug(msg->parameter);
		policy_cr4_debug(msg->parameter);
		policy_msr_debug(msg->parameter);
		break;
	}
}

/* Generate a string based on whether response=Allow/Skip. */
void action_to_string(ikgt_event_response_t *response, char *str)
{
	int tmp;

	if (*response == IKGT_EVENT_RESPONSE_ALLOW)
		tmp = mon_sprintf_s(str, MAX_ACTION_BUF_SIZE, "LOG_ALLOW");

	if (*response == IKGT_EVENT_RESPONSE_REDIRECT)
		tmp = mon_sprintf_s(str, MAX_ACTION_BUF_SIZE, "LOG_SKIP");
}
