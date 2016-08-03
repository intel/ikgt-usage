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
#include <linux/version.h>

#include "ikgt_api.h"
#include "common.h"
#include "alloc.h"

static name_value_map cr4_bits[] = {
	{"VME",        VME,        RESOURCE_ID_CR4_VME},
	{"PVI",        PVI,        RESOURCE_ID_CR4_PVI},
	{"TSD",        TSD,        RESOURCE_ID_CR4_TSD},
	{"DE",         DE,         RESOURCE_ID_CR4_DE},
	{"PSE",        PSE,        RESOURCE_ID_CR4_PSE},
	{"PAE",        PAE,        RESOURCE_ID_CR4_PAE},
	{"MCE",        MCE,        RESOURCE_ID_CR4_MCE},
	{"PGE",        PGE,        RESOURCE_ID_CR4_PGE},
	{"PCE",        PCE,        RESOURCE_ID_CR4_PCE},
	{"OSFXSR",     OSFXSR,     RESOURCE_ID_CR4_OSFXSR},
	{"OSXMMEXCPT", OSXMMEXCPT, RESOURCE_ID_CR4_OSXMMEXCPT},
	{"VMXE",       VMXE,       RESOURCE_ID_CR4_VMXE},
	{"SMXE",       SMXE,       RESOURCE_ID_CR4_SMXE},
	{"PCIDE",      PCIDE,      RESOURCE_ID_CR4_PCIDE},
	{"OSXSAVE",    OSXSAVE,    RESOURCE_ID_CR4_OSXSAVE},
	{"SMEP",       SMEP,       RESOURCE_ID_CR4_SMEP},
	{"SMAP",       SMAP,       RESOURCE_ID_CR4_SMAP},

	/* Table terminator */
	{}
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static ssize_t cr4_cfg_enable_store(struct config_item *item,
									const char *page,
									size_t count);

static ssize_t cr4_cfg_write_store(struct config_item *item,
								   const char *page,
								   size_t count);

static ssize_t cr4_cfg_sticky_value_store(struct config_item *item,
										  const char *page,
										  size_t count);
#else
static ssize_t cr4_cfg_store_enable(struct cr4_cfg *cr4_cfg,
									const char *page,
									size_t count);

static ssize_t cr4_cfg_store_write(struct cr4_cfg *cr4_cfg,
								   const char *page,
								   size_t count);

static ssize_t cr4_cfg_store_sticky_value(struct cr4_cfg *cr4_cfg,
										  const char *page,
										  size_t count);
#endif

/* to_cr4_cfg() function */
IKGT_CONFIGFS_TO_CONTAINER(cr4_cfg);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
/* define attribute structure */
CONFIGFS_ATTR_STRUCT(cr4_cfg);
#endif

/* item operations */
IKGT_UINT32_SHOW(cr4_cfg, enable);
IKGT_UINT32_HEX_SHOW(cr4_cfg, write);
IKGT_ULONG_HEX_SHOW(cr4_cfg, sticky_value);

/* attributes */
IKGT_CONFIGFS_ATTR_RW(cr4_cfg, enable);
IKGT_CONFIGFS_ATTR_RW(cr4_cfg, write);
IKGT_CONFIGFS_ATTR_RW(cr4_cfg, sticky_value);

static struct configfs_attribute *cr4_cfg_attrs[] = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	&cr4_cfg_attr_enable,
	&cr4_cfg_attr_write,
	&cr4_cfg_attr_sticky_value,
#else
	&cr4_cfg_attr_enable.attr,
	&cr4_cfg_attr_write.attr,
	&cr4_cfg_attr_sticky_value.attr,
#endif
	NULL,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
CONFIGFS_ATTR_OPS(cr4_cfg);
#endif

static int valid_cr4_attr(const char *name)
{
	int i;

	for (i = 0; cr4_bits[i].name; i++) {
		if (strcasecmp(cr4_bits[i].name, name) == 0) {
			return i;
		}
	}

	return -1;
}

static bool policy_set_cr4(struct cr4_cfg *cr4_cfg, bool enable)
{
	policy_message_t *msg = NULL;
	policy_update_rec_t *entry = NULL;
	uint64_t ret;
	message_id_t msg_id;
	uint64_t in_offset;
	int idx = valid_cr4_attr(cr4_cfg->item.ci_name);

	if (idx < 0)
		return false;

	msg = (policy_message_t *)allocate_in_buf(sizeof(policy_message_t), &in_offset);
	if (msg == NULL)
		return false;

	msg_id = enable?POLICY_ENTRY_ENABLE:POLICY_ENTRY_DISABLE;
	msg->count = 1;

	entry = &msg->policy_data[0];

	POLICY_SET_RESOURCE_ID(entry, cr4_bits[idx].res_id);
	POLICY_SET_WRITE_ACTION(entry, cr4_cfg->write);

	POLICY_SET_STICKY_VALUE(entry, cr4_cfg->sticky_value);

	POLICY_INFO_SET_MASK(entry, cr4_bits[idx].value);

	POLICY_INFO_SET_CPU_MASK_1(entry, -1);
	POLICY_INFO_SET_CPU_MASK_2(entry, -1);

	PRINTK_INFO("cpumask: %llx, %llx\n",
		POLICY_INFO_GET_CPU_MASK_1(entry), POLICY_INFO_GET_CPU_MASK_2(entry));

	ret = ikgt_hypercall(msg_id, in_offset, 0);
	if (SUCCESS != ret) {
		PRINTK_ERROR("%s: ikgt_hypercall failed, ret=%llu\n", __func__, ret);
	}

	free_in_buf(in_offset);

	return (ret == SUCCESS)?true:false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)

static ssize_t cr4_cfg_write_store(struct config_item *item,
								   const char *page,
								   size_t count)
{
	struct cr4_cfg *cr4_cfg = to_cr4_cfg(item);
#else
static ssize_t cr4_cfg_store_write(struct cr4_cfg *cr4_cfg,
								   const char *page,
								   size_t count)
{
#endif
	unsigned long value;

	if (cr4_cfg->locked)
		return -EPERM;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	cr4_cfg->write = value;

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static ssize_t cr4_cfg_sticky_value_store(struct config_item *item,
										  const char *page,
										  size_t count)
{
	struct cr4_cfg *cr4_cfg = to_cr4_cfg(item);
#else
static ssize_t cr4_cfg_store_sticky_value(struct cr4_cfg *cr4_cfg,
										  const char *page,
										  size_t count)
{
#endif
	unsigned long value;

	if (cr4_cfg->locked)
		return -EPERM;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	cr4_cfg->sticky_value = value;

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static ssize_t cr4_cfg_enable_store(struct config_item *item,
											const char *page,
											size_t count)
{

	struct cr4_cfg *cr4_cfg = to_cr4_cfg(item);
#else
static ssize_t cr4_cfg_store_enable(struct cr4_cfg *cr4_cfg,
									const char *page,
									size_t count)
{
#endif
	unsigned long value;
	bool ret = false;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	if (cr4_cfg->locked) {
		return -EPERM;
	}

	ret = policy_set_cr4(cr4_cfg, value);

	if (ret) {
		cr4_cfg->enable = value;
	}

	if (ret && (cr4_cfg->write & POLICY_ACT_STICKY))
		cr4_cfg->locked = true;

	return count;
}


static void cr4_cfg_release(struct config_item *item)
{
	kfree(to_cr4_cfg(item));
}

static struct configfs_item_operations cr4_cfg_ops = {
	.release = cr4_cfg_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.show_attribute	 = cr4_cfg_attr_show,
	.store_attribute = cr4_cfg_attr_store,
#endif
};

static struct config_item_type cr4_cfg_type = {
	.ct_item_ops = &cr4_cfg_ops,
	.ct_attrs = cr4_cfg_attrs,
	.ct_owner = THIS_MODULE,
};


static struct config_item *cr4_make_item(struct config_group *group,
										 const char *name)
{
	struct cr4_cfg *cr4_cfg;

	PRINTK_INFO("CR4 create attribute file %s\n", name);

	if (valid_cr4_attr(name) == -1) {
		PRINTK_ERROR("Invalid CR4 bit name\n");
		return ERR_PTR(-EINVAL);
	}

	cr4_cfg = kzalloc(sizeof(struct cr4_cfg), GFP_KERNEL);
	if (!cr4_cfg) {
		return ERR_PTR(-ENOMEM);
	}

	config_item_init_type_name(&cr4_cfg->item, name,
		&cr4_cfg_type);

	return &cr4_cfg->item;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static ssize_t cr4_children_description_show(struct config_item *item,
											 char *page)
#else

static ssize_t cr4_children_attr_show(struct config_item *item,
									  struct configfs_attribute *attr,
									  char *page)
#endif
{
	return sprintf(page,
			"CR4\n"
			"\n"
			"Used in protected mode to control operations .	\n"
			"items are readable and writable.\n");
}

static struct configfs_attribute cr4_children_attr_description = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "description",
	.ca_mode	= S_IRUGO,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	.show		= cr4_children_description_show,
#endif
};

static struct configfs_attribute *cr4_children_attrs[] = {
	&cr4_children_attr_description,
	NULL,
};

static void cr4_children_release(struct config_item *item)
{
	kfree(to_node(item));
}

static struct configfs_item_operations cr4_children_item_ops = {
	.release	= cr4_children_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.show_attribute = cr4_children_attr_show,
#endif
};

static struct configfs_group_operations cr4_children_group_ops = {
	.make_item	= cr4_make_item,
};

static struct config_item_type cr4_children_type = {
	.ct_item_ops	= &cr4_children_item_ops,
	.ct_group_ops	= &cr4_children_group_ops,
	.ct_attrs	= cr4_children_attrs,
	.ct_owner	= THIS_MODULE,
};

struct config_item_type *get_cr4_children_type(void)
{
	return &cr4_children_type;
}
