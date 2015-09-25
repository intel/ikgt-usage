/*
* This is an example ikgt usage driver.
* Copyright (c) 2015, Intel Corporation.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*/

#include <linux/module.h>
#include <linux/kernel.h>

#include "ikgt_api.h"
#include "common.h"
#include "configfs_setup.h"
#include "log.h"
#include "debug.h"
#include "alloc.h"

static char *g_in_va_base;
static char *g_out_va_base;
static char *g_log_va_base;


static void uninit_shared_regions(void);

static bool init_shared_regions(void)
{
	uint64_t config_pa;
	config_info_t *ikgt_config = NULL;

	BUILD_BUG_ON(sizeof(config_info_t) > PAGES_TO_BYTES(MAX_CONFIG_INFO_PAGES));
	BUILD_BUG_ON(sizeof(policy_message_t) > PAGES_TO_BYTES(MAX_IN_ADDR_PAGES));

	config_pa = ikgt_hypercall(POLICY_GET_CONFIG, 0, 0);
	if (IKGT_NOT_RUNNING == config_pa) {
		PRINTK_ERROR("IKGT is not running\n");
		return false;
	}

	PRINTK_INFO("%s: config_pa=0x%llx\n", __func__, config_pa);

	ikgt_config = (config_info_t *)ioremap(config_pa, PAGES_TO_BYTES(MAX_CONFIG_INFO_PAGES));
	if (NULL == ikgt_config) {
		PRINTK_ERROR("ioremap failed\n");
		return false;
	}

	PRINTK_INFO("version=0x%llx\n", ikgt_config->ver.uint64);

	g_in_va_base = (char *)ioremap(ikgt_config->in_pa, ikgt_config->in_size);
	if (0 == g_in_va_base) {
		PRINTK_ERROR("failed to ioremap in_pa 0x%llx\n", ikgt_config->in_pa);
		goto err_out;
	}

	g_out_va_base = (char *)ioremap(ikgt_config->out_pa, ikgt_config->out_size);
	if (0 == g_out_va_base) {
		PRINTK_ERROR("failed to ioremap out_pa 0x%llx\n", ikgt_config->out_pa);
		goto err_out;
	}

	g_log_va_base = (char *)ioremap(ikgt_config->log_pa, ikgt_config->log_size);
	if (0 == g_log_va_base) {
		PRINTK_ERROR("failed to ioremap log_pa 0x%llx\n", ikgt_config->log_pa);
		goto err_out;
	}

	PRINTK_INFO("in_pa=0x%llx\n", ikgt_config->in_pa);
	PRINTK_INFO("in_va=%p\n", g_in_va_base);
	PRINTK_INFO("in_size=%llu\n", ikgt_config->in_size);

	PRINTK_INFO("out_pa=0x%llx\n", ikgt_config->out_pa);
	PRINTK_INFO("out_va=%p\n", g_out_va_base);
	PRINTK_INFO("out_size=%llu\n", ikgt_config->out_size);

	PRINTK_INFO("log_pa=0x%llx\n", ikgt_config->log_pa);
	PRINTK_INFO("log_va=%p\n", g_log_va_base);
	PRINTK_INFO("log_size=%llu\n", ikgt_config->log_size);

	init_in_buf(g_in_va_base, ikgt_config->in_size);
	init_out_buf(g_out_va_base, ikgt_config->out_size);
	init_log_buf(g_log_va_base, ikgt_config->log_size);

	iounmap((void __iomem *)ikgt_config);

	return true;

err_out:
	uninit_shared_regions();

	if (ikgt_config) {
		iounmap((void __iomem *)ikgt_config);
	}

	return false;
}

static void uninit_shared_regions(void)
{
	if (g_in_va_base)
		iounmap((void __iomem *)g_in_va_base);
	g_in_va_base = NULL;

	if (g_out_va_base)
		iounmap((void __iomem *)g_out_va_base);
	g_out_va_base = NULL;

	if (g_log_va_base)
		iounmap((void __iomem *)g_log_va_base);
	g_log_va_base = NULL;
}

static int __init init_agent(void)
{
	PRINTK_INFO("%s\n", __func__);

	if (!init_shared_regions()) {
		PRINTK_ERROR("init_shared_regions failed\n");
		return 1;
	}

	init_log(get_alloc_info_log_addr());

#ifdef DEBUG
	init_debug();
#endif

	init_configfs_setup();

	return 0;
}

static void __exit exit_agent(void)
{
	uninit_shared_regions();

#ifdef DEBUG
	uninit_debug();
#endif

	uninit_configfs_setup();
}


MODULE_LICENSE("GPL");
module_init(init_agent);
module_exit(exit_agent);
