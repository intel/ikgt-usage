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


ikgt_status_t read_guest_reg(ikgt_vmcs_guest_state_reg_id_t reg_id, uint64_t *value)
{
	ikgt_vmcs_guest_guest_register_t *reg = NULL;
	ikgt_status_t status;

	*value = 0;

	reg = (ikgt_vmcs_guest_guest_register_t *)
		ikgt_malloc(sizeof(ikgt_vmcs_guest_guest_register_t));

	if (NULL == reg) {
		ikgt_printf("[ERROR] HANDLER: Failed to allocate memory in\
					read_guest_reg()\n");
		return IKGT_STATUS_ERROR;
	}

	reg->size = sizeof(ikgt_vmcs_guest_guest_register_t);
	reg->num = 1;
	reg->reg_ids[0] = reg_id;

	status = ikgt_read_guest_registers(reg);

	if (IKGT_STATUS_SUCCESS == status) {
		*value = reg->reg_values[0];
	}

	ikgt_free((uint64_t *)reg);

	return status;
}

ikgt_status_t write_guest_reg(ikgt_vmcs_guest_state_reg_id_t reg_id, uint64_t value)
{
	ikgt_vmcs_guest_guest_register_t *reg = NULL;
	ikgt_status_t status;

	reg = (ikgt_vmcs_guest_guest_register_t *)
		ikgt_malloc(sizeof(ikgt_vmcs_guest_guest_register_t));

	if (NULL == reg) {
		ikgt_printf("[ERROR] HANDLER: Failed to allocate memory in\
					read_guest_reg()\n");
		return IKGT_STATUS_ERROR;
	}

	reg->size = sizeof(ikgt_vmcs_guest_guest_register_t);
	reg->num = 1;
	reg->reg_ids[0] = reg_id;
	reg->reg_values[0] = value;

	status = ikgt_write_guest_registers(reg);

	ikgt_free((uint64_t *)reg);

	return status;
}

static ikgt_vmcs_guest_state_reg_id_t g_cpu_reg_id_map_table[] = {
	[IKGT_CPU_REG_RAX] = IA32_GP_RAX,
	[IKGT_CPU_REG_RBX] = IA32_GP_RBX,
	[IKGT_CPU_REG_RCX] = IA32_GP_RCX,
	[IKGT_CPU_REG_RDX] = IA32_GP_RDX,
	[IKGT_CPU_REG_RDI] = IA32_GP_RDI,
	[IKGT_CPU_REG_RSI] = IA32_GP_RSI,
	[IKGT_CPU_REG_RBP] = IA32_GP_RBP,
	[IKGT_CPU_REG_RSP] = IA32_GP_RSP,
	[IKGT_CPU_REG_R8] =  IA32_GP_R8,
	[IKGT_CPU_REG_R9] =  IA32_GP_R9,
	[IKGT_CPU_REG_R10] = IA32_GP_R10,
	[IKGT_CPU_REG_R11] = IA32_GP_R11,
	[IKGT_CPU_REG_R12] = IA32_GP_R12,
	[IKGT_CPU_REG_R13] = IA32_GP_R13,
	[IKGT_CPU_REG_R14] = IA32_GP_R14,
	[IKGT_CPU_REG_R15] = IA32_GP_R15,
	[IKGT_CPU_REG_CR0] = VMCS_GUEST_STATE_CR0,
	[IKGT_CPU_REG_CR3] = VMCS_GUEST_STATE_CR3,
	[IKGT_CPU_REG_CR4] = VMCS_GUEST_STATE_CR4,
};

ikgt_status_t get_vmcs_guest_reg_id(ikgt_cpu_reg_t event_reg_id,
									ikgt_vmcs_guest_state_reg_id_t *vmcs_reg_id)
{
	ikgt_status_t status = IKGT_STATUS_SUCCESS;

	if ((event_reg_id >= IKGT_CPU_REG_RAX)
		&& (event_reg_id <= IKGT_CPU_REG_CR4)) {
			*vmcs_reg_id  = g_cpu_reg_id_map_table[event_reg_id];
	} else {
		*vmcs_reg_id    = NUM_OF_VMCS_GUEST_STATE_REGS;
		status      = IKGT_STATUS_ERROR;
	}

	return status;
}

ikgt_status_t util_monitor_memory(uint64_t start_addr, uint32_t size,
								  uint32_t permission)
{
	ikgt_update_page_permission_params_t *update_params = NULL;
	ikgt_gva_to_gpa_params_t *gva2gpa = NULL;
	ikgt_status_t status = IKGT_STATUS_ERROR;
	uint32_t pages, idx;

	/* make start_gva align to page boundary */
	start_addr &= ~((uint64_t)PAGE_4KB - 1);

	/* how many pages */
	pages = PAGE_ALIGN_4K(size) >> PAGE_SHIFT;

	DPRINTF("%s: start_addr=%llx, size=%u, pages=%u, permission=%u\n",
		__func__, start_addr, size, pages, permission);

	if (pages > IKGT_ADDRINFO_MAX_COUNT) {
		ikgt_printf("pages > IKGT_ADDRINFO_MAX_COUNT\n");
		return IKGT_STATUS_ERROR;
	}

	update_params = (ikgt_update_page_permission_params_t *)
		ikgt_malloc(sizeof(ikgt_update_page_permission_params_t));
	if (NULL == update_params) {
		ikgt_printf("failed to allocate memory for update page\n");
		status = IKGT_ALLOCATE_FAILED;
		goto out;
	}

	gva2gpa = (ikgt_gva_to_gpa_params_t *)ikgt_malloc(sizeof(ikgt_gva_to_gpa_params_t));
	if (gva2gpa == NULL) {
		ikgt_printf("failed to allocate memory for gva2gpa\n");
		status = IKGT_ALLOCATE_FAILED;
		goto out;
	}

	update_params->handle = 0;
	update_params->addr_list.count = pages;

	gva2gpa->size = sizeof(ikgt_gva_to_gpa_params_t);
	gva2gpa->cr3 = 0;
	for (idx = 0; idx < pages; idx++) {
		gva2gpa->guest_virtual_address = start_addr;
		gva2gpa->guest_physical_address = start_addr;

		status = ikgt_gva_to_gpa(gva2gpa);
		if (IKGT_STATUS_SUCCESS != status) {
			ikgt_printf("failed to translate gva to gpa\n");
			goto out;
		}

		update_params->addr_list.item[idx].perms.all_bits = permission;
		update_params->addr_list.item[idx].gva = gva2gpa->guest_virtual_address;
		update_params->addr_list.item[idx].gpa = gva2gpa->guest_physical_address;

		start_addr += PAGE_4KB;
	}

	status = ikgt_update_page_permission(update_params);

	if (IKGT_STATUS_SUCCESS != status) {
		ikgt_printf("failed to call ikgt_update_page_permission!\n");
		goto out;
	}

out:
	if (gva2gpa) {
		ikgt_free((uint64_t *)gva2gpa);
	}

	if (update_params) {
		ikgt_free((uint64_t *)update_params);
	}

	return status;
}

#define IKGT_MEMORY_MAX_BLOCK_SIZE (IKGT_ADDRINFO_MAX_COUNT * PAGE_4KB)
ikgt_status_t util_monitor_memory_ex(uint64_t start_addr, uint32_t size,
									 uint32_t permission)
{
	ikgt_status_t status = IKGT_STATUS_ERROR;

	while (size) {
		uint32_t blksize = min(size, IKGT_MEMORY_MAX_BLOCK_SIZE);

		status = util_monitor_memory(start_addr, blksize, permission);
		if (status != IKGT_STATUS_SUCCESS) {
			break;
		}

		start_addr += blksize;
		size -= blksize;
	}

	return status;
}

ikgt_status_t util_monitor_cpu_events(uint64_t cpu_bitmap[],
									  uint64_t mask,
									  ikgt_cpu_reg_t reg,
									  boolean_t enable)
{
	ikgt_status_t status;
	ikgt_cpu_event_params_t *cpu_params = NULL;
	int i;

	cpu_params = (ikgt_cpu_event_params_t *)ikgt_malloc(sizeof(ikgt_cpu_event_params_t));
	if (NULL == cpu_params)
		return IKGT_ALLOCATE_FAILED;

	cpu_params->size = sizeof(ikgt_cpu_event_params_t);

	for (i = 0; i < CPU_BITMAP_MAX; i++) {
		cpu_params->cpu_bitmap[i] = cpu_bitmap[i];
	}

	cpu_params->cpu_reg = reg;
	cpu_params->enable = enable;

	if (reg == IKGT_CPU_REG_CR0) {
		cpu_params->crx_mask.cr0.uint64 = mask;
	} else if (reg == IKGT_CPU_REG_CR4) {
		cpu_params->crx_mask.cr4.uint64 = mask;
	}

	status = ikgt_monitor_cpu_events(cpu_params);

	ikgt_free((uint64_t *)cpu_params);

	return status;
}

ikgt_status_t util_monitor_msr(uint32_t msr_id, boolean_t enable)
{
	ikgt_status_t status;
	ikgt_monitor_msr_params_t *msr_params = NULL;

	msr_params = (ikgt_monitor_msr_params_t *)ikgt_malloc(sizeof(ikgt_monitor_msr_params_t));
	if (NULL == msr_params)
		return IKGT_ALLOCATE_FAILED;

	msr_params->enable = enable;
	msr_params->num_ids = 1;
	msr_params->msr_ids[0] = msr_id;

	status = ikgt_monitor_msr_writes(msr_params);

	ikgt_free((uint64_t *)msr_params);

	return status;
}

ikgt_status_t util_hva_to_hpa(uint64_t hva, uint64_t *hpa)
{
	ikgt_hva_to_hpa_params_t *hva_hpa_params = NULL;
	ikgt_status_t status;

	if (NULL == hpa)
		return IKGT_STATUS_ERROR;

	hva_hpa_params = (ikgt_hva_to_hpa_params_t *)ikgt_malloc(sizeof(ikgt_hva_to_hpa_params_t));
	if (NULL == hva_hpa_params)
		return IKGT_ALLOCATE_FAILED;

	hva_hpa_params->size = sizeof(ikgt_hva_to_hpa_params_t);
	hva_hpa_params->host_virtual_address = hva;
	hva_hpa_params->host_physical_address = 0;

	status = ikgt_hva_to_hpa(hva_hpa_params);

	*hpa = hva_hpa_params->host_physical_address;

	ikgt_free((uint64_t *)hva_hpa_params);

	return status;
}

static ikgt_status_t util_change_page_perms(uint32_t view, uint64_t gpa, uint64_t gva, uint32_t perm)
{
	ikgt_update_page_permission_params_t *update_params = NULL;
	ikgt_status_t status;

	update_params = (ikgt_update_page_permission_params_t *)
		ikgt_malloc(sizeof(ikgt_update_page_permission_params_t));

	if (NULL == update_params) {
		ikgt_printf("failed to allocate memory for update page\n");
		return IKGT_ALLOCATE_FAILED;
	}

	update_params->handle = view;
	update_params->addr_list.count = 1;

	update_params->addr_list.item[0].perms.all_bits = perm;
	update_params->addr_list.item[0].gva = gva;
	update_params->addr_list.item[0].gpa = gpa;

	status = ikgt_update_page_permission(update_params);
	if (IKGT_STATUS_SUCCESS != status) {
		ikgt_printf("Error in updating page permissions in %s\n", __func__);
	}
	ikgt_free((uint64_t *)update_params);

	return status;
}

ikgt_status_t util_map_gpa_to_hpa(uint32_t view, uint64_t hva, uint32_t perm)
{
	uint64_t gpa, hpa;
	ikgt_status_t status = IKGT_STATUS_ERROR;

	DPRINTF("%s: view=%u, hva=%llx, perm=0x%x\n", __func__, view, hva, perm);

	status = util_hva_to_hpa(hva, &hpa);
	if (status != IKGT_STATUS_SUCCESS) {
		ikgt_printf("%s: error hva to hpa\n", __func__);
		return status;
	}

	/* Assumes gpa == hpa for ikgt memory */
	gpa = hpa;

	status = ikgt_add_gpa_to_hpa_mapping(view, gpa, hpa);
	if (status != IKGT_STATUS_SUCCESS) {
		ikgt_printf("%s: error remap\n", __func__);
		return status;
	}

	status = util_change_page_perms(view, gpa, 0, perm);
	if (status != IKGT_STATUS_SUCCESS) {
		ikgt_printf("%s: error change perm\n", __func__);
		/* TODO:remove mapping */
		return status;
	}

	return status;
}

/*
Note: size should be a multiple of 4k
*/
ikgt_status_t util_map_gpa_to_hpa_ex(uint32_t view, uint64_t hva, uint32_t perm, uint32_t size)
{
	ikgt_status_t status = IKGT_STATUS_ERROR;

	while (size) {
		uint32_t blksize = min(size, PAGE_4KB);

		status = util_map_gpa_to_hpa(view, hva, perm);
		if (status != IKGT_STATUS_SUCCESS) {
			break;
		}

		hva += blksize;
		size -= blksize;
	}

	return status;
}


