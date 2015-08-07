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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "common.h"


extern struct configfs_subsystem *create_log_node(void);
extern struct config_item_type *get_cr0_children_type(void);
extern struct config_item_type *get_cr4_children_type(void);
extern struct config_item_type *get_msr_children_type(void);
extern struct config_item_type *get_log_children_type(void);

/* ----------------------------------------------------------------- */
/* Creates configfs nodes for various cpu assets to enable
* monitoring.
* e.g.
* /configfs/ikgt_agent/cr0/PE/
*					/MP/
* /configfs/ikgt_agent/cr4/SMEP/
*                   /SMAP/
*                   /VMXE/
*/

#define GROUP_NAME_CR0       "cr0"
#define GROUP_NAME_CR4       "cr4"
#define GROUP_NAME_MSR       "msr"
#define GROUP_NAME_LOG       "log"

static struct config_group *group_children_make_group(struct config_group *group,
													  const char *name)
{
	struct group_node *cfg;

	PRINTK_INFO("Creating configfs node for %s\n", name);

	cfg = kzalloc(sizeof(struct group_node), GFP_KERNEL);
	if (!cfg) {
		return ERR_PTR(-ENOMEM);
	}

	if (strcasecmp(name, GROUP_NAME_CR0) == 0) {
		config_group_init_type_name(&cfg->group, name,
			get_cr0_children_type());
	} else if (strcasecmp(name, GROUP_NAME_CR4) == 0) {
		config_group_init_type_name(&cfg->group, name,
			get_cr4_children_type());
	} else if (strcasecmp(name, GROUP_NAME_MSR) == 0) {
		config_group_init_type_name(&cfg->group, name,
			get_msr_children_type());
	} else if (strcasecmp(name, GROUP_NAME_LOG) == 0) {
		config_group_init_type_name(&cfg->group, name,
			get_log_children_type());
	}

	return &cfg->group;
}

static struct configfs_attribute group_children_attr_description = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "description",
	.ca_mode	= S_IRUGO,
};

static struct configfs_attribute *group_children_attrs[] = {
	&group_children_attr_description,
	NULL,
};

static ssize_t group_children_attr_show(struct config_item *item,
struct configfs_attribute *attr,
	char *page)
{
	return sprintf(page,
		DRIVER_NAME"\n"
		"These file subsystem allows to create groups for various cpu assets.\n"
		"These groups can be cr0, cr4, msr, log, etc.\n");
}

static struct configfs_item_operations group_children_item_ops = {
	.show_attribute = group_children_attr_show,
};


static struct configfs_group_operations group_children_group_ops = {
	.make_group	= group_children_make_group,
};

static struct config_item_type group_children_type = {
	.ct_item_ops	= &group_children_item_ops,
	.ct_group_ops	= &group_children_group_ops,
	.ct_attrs	= group_children_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem group_children_subsys = {
	.su_group			= {
		.cg_item		= {
			.ci_namebuf	= DRIVER_NAME,
			.ci_type	= &group_children_type,
		},
	},
};

/*
* Entry point for configfs setup
*/
static struct configfs_subsystem *configfs_subsys[] = {
	&group_children_subsys,
	NULL,
};

void init_configfs_setup(void)
{
	int ret;
	int i;
	struct configfs_subsystem *subsys;

	for (i = 0; configfs_subsys[i]; i++) {
		subsys = configfs_subsys[i];
		config_group_init(&subsys->su_group);
		mutex_init(&subsys->su_mutex);
		ret = configfs_register_subsystem(subsys);
		if (ret) {
			PRINTK_ERROR("Error %d while registering subsystem %s\n",
				ret,
				subsys->su_group.cg_item.ci_namebuf);
			goto out_unregister;
		}
	}

	return;

out_unregister:
	for (i--; i >= 0; i--)
		configfs_unregister_subsystem(configfs_subsys[i]);
}

void uninit_configfs_setup(void)
{
	int i;

	for (i = 0; configfs_subsys[i]; i++)
		configfs_unregister_subsystem(configfs_subsys[i]);
}

