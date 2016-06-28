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

#include "ikgt_api.h"
#include "common.h"
#include "alloc.h"


name_value_map msr_regs[] = {
	{ "EFER",         0xC0000080, RESOURCE_ID_MSR_EFER},
	{ "STAR",         0xC0000081, RESOURCE_ID_MSR_STAR},
	{ "LSTAR",        0xC0000082, RESOURCE_ID_MSR_LSTAR},
	{ "SYSENTER_CS",  0x174,      RESOURCE_ID_MSR_SYSENTER_CS},
	{ "SYSENTER_ESP", 0x175,      RESOURCE_ID_MSR_SYSENTER_ESP},
	{ "SYSENTER_EIP", 0x176,      RESOURCE_ID_MSR_SYSENTER_EIP},
	{ "SYSENTER_PAT", 0x277,      RESOURCE_ID_MSR_SYSENTER_PAT},

	/* Table terminator */
	{}
};

static int valid_msr_attr(const char *name)
{
	int i;

	for (i = 0; msr_regs[i].name; i++) {
		if (strcasecmp(msr_regs[i].name, name) == 0) {
			return i;
		}
	}

	return -1;
}


static ssize_t msr_cfg_enable_store(struct config_item *item,
									const char *page,
									size_t count);

static ssize_t msr_cfg_write_store(struct config_item *item,
								   const char *page,
								   size_t count);

static ssize_t msr_cfg_sticky_value_store(struct config_item *item,
										  const char *page,
										  size_t count);

/* to_msr_cfg() function */
IKGT_CONFIGFS_TO_CONTAINER(msr_cfg);

/* item operations */
IKGT_UINT32_SHOW(msr_cfg, enable);
IKGT_UINT32_HEX_SHOW(msr_cfg, write);
IKGT_ULONG_HEX_SHOW(msr_cfg, sticky_value);

/* attributes */
IKGT_CONFIGFS_ATTR_RW(msr_cfg, enable);
IKGT_CONFIGFS_ATTR_RW(msr_cfg, write);
IKGT_CONFIGFS_ATTR_RW(msr_cfg, sticky_value);

static struct configfs_attribute *msr_cfg_attrs[] = {
	&msr_cfg_attr_enable,
	&msr_cfg_attr_write,
	&msr_cfg_attr_sticky_value,
	NULL,
};


static bool policy_set_msr(struct msr_cfg *msr_cfg, bool enable)
{
	policy_message_t *msg = NULL;
	policy_update_rec_t *entry = NULL;
	uint64_t ret;
	message_id_t msg_id;
	uint64_t in_offset;
	int idx = valid_msr_attr(msr_cfg->item.ci_name);

	if (idx < 0)
		return false;

	msg = (policy_message_t *)allocate_in_buf(sizeof(policy_message_t), &in_offset);
	if (msg == NULL)
		return false;

	msg_id = enable?POLICY_ENTRY_ENABLE:POLICY_ENTRY_DISABLE;

	entry = &msg->policy_data[0];

	POLICY_SET_RESOURCE_ID(entry, msr_regs[idx].res_id);
	POLICY_SET_WRITE_ACTION(entry, msr_cfg->write);

	POLICY_SET_STICKY_VALUE(entry, msr_cfg->sticky_value);

	ret = ikgt_hypercall(msg_id, in_offset, 0);
	if (SUCCESS != ret) {
		PRINTK_ERROR("%s: ikgt_hypercall failed, ret=%llu\n", __func__, ret);
	}

	free_in_buf(in_offset);

	return (ret == SUCCESS)?true:false;
}

static ssize_t msr_cfg_write_store(struct config_item *item,
								   const char *page,
								   size_t count)
{
	unsigned long value;

	struct msr_cfg *msr_cfg = to_msr_cfg(item);

	if (msr_cfg->locked)
		return -EPERM;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	msr_cfg->write = value;

	return count;
}

static ssize_t msr_cfg_sticky_value_store(struct config_item *item,
										  const char *page,
										  size_t count)
{
	unsigned long value;

	struct msr_cfg *msr_cfg = to_msr_cfg(item);

	if (msr_cfg->locked)
		return -EPERM;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	msr_cfg->sticky_value = value;

	return count;
}

static ssize_t msr_cfg_enable_store(struct config_item *item,
									const char *page,
									size_t count)
{
	unsigned long value;
	bool ret = false;

	struct msr_cfg *msr_cfg = to_msr_cfg(item);

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	if (msr_cfg->locked) {
		return -EPERM;
	}

	ret = policy_set_msr(msr_cfg, value);

	if (ret) {
		msr_cfg->enable = value;
	}

	if (ret && (msr_cfg->write & POLICY_ACT_STICKY))
		msr_cfg->locked = true;

	return count;
}


static void msr_cfg_release(struct config_item *item)
{
	kfree(to_msr_cfg(item));
}

static struct configfs_item_operations msr_cfg_ops = {
	.release		= msr_cfg_release,
};

static struct config_item_type msr_cfg_type = {
	.ct_item_ops	= &msr_cfg_ops,
	.ct_attrs	= msr_cfg_attrs,
	.ct_owner	= THIS_MODULE,
};


static struct config_item *msr_make_item(struct config_group *group,
										 const char *name)
{
	struct msr_cfg *msr_cfg;

	if (valid_msr_attr(name) == -1) {
		PRINTK_ERROR("Invalid MSR bit name\n");
		return NULL;
	}

	msr_cfg = kzalloc(sizeof(struct msr_cfg), GFP_KERNEL);
	if (!msr_cfg) {
		return ERR_PTR(-ENOMEM);
	}

	config_item_init_type_name(&msr_cfg->item, name,
		&msr_cfg_type);

	return &msr_cfg->item;
}

static ssize_t msr_children_description_show(struct config_item *item,
									  char *page)
{
		return sprintf(page,
					   "MSR\n"
					   "\n"
					   "Used in protected mode to control operations .  \n"
					   "items are readable and writable.\n");
}

static struct configfs_attribute msr_children_attr_description = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "description",
	.ca_mode	= S_IRUGO,
	.show       = msr_children_description_show
};

static struct configfs_attribute *msr_children_attrs[] = {
	&msr_children_attr_description,
	NULL,
};

static void msr_children_release(struct config_item *item)
{
	kfree(to_node(item));
}

static struct configfs_item_operations msr_children_item_ops = {
	.release	= msr_children_release,
};

static struct configfs_group_operations msr_children_group_ops = {
	.make_item	= msr_make_item,
};

static struct config_item_type msr_children_type = {
	.ct_item_ops	= &msr_children_item_ops,
	.ct_group_ops	= &msr_children_group_ops,
	.ct_attrs	= msr_children_attrs,
	.ct_owner	= THIS_MODULE,
};

struct config_item_type *get_msr_children_type(void)
{
	return &msr_children_type;
}
