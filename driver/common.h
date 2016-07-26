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

#ifndef _COMMON_H
#define _COMMON_H

#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/version.h>

#define DEBUG

#define DRIVER_NAME "ikgt_agent"
#define PREFIX "iKGT: "

#define PRINTK_INFO(fmt, args...)     printk(KERN_INFO PREFIX fmt, ##args)
#define PRINTK_ERROR(fmt, args...)    printk(KERN_ERR PREFIX fmt, ##args)
#define PRINTK_WARNING(fmt, args...)  printk(KERN_WARNING PREFIX fmt, ##args)


struct group_node {
    struct config_group group;
};

static inline struct group_node *to_node(struct config_item *item)
{
    return item ? container_of(to_config_group(item), struct group_node,
        group) : NULL;
}

#define IKGT_CONFIGFS_TO_CONTAINER(__s)  \
    static inline struct __s  *to_##__s(struct config_item *item) \
{ \
    return item ? container_of(item, struct __s, item) : NULL; \
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)

#define IKGT_CONFIGFS_ATTR_RO(__s, __name)      \
    CONFIGFS_ATTR_RO(__s##_, __name);

#define IKGT_CONFIGFS_ATTR_RW(__s, __name)              \
    CONFIGFS_ATTR(__s##_, __name);

#define IKGT_UINT32_SHOW(__s, __name)   \
    static ssize_t __s##_##__name##_show(struct config_item *item,  \
    char *page) \
{   \
    return sprintf(page, "%u\n", to_##__s(item)->__name);   \
}

#define IKGT_UINT32_HEX_SHOW(__s, __name)   \
    static ssize_t __s##_##__name##_show(struct config_item *item, \
    char *page) \
{   \
    return sprintf(page, "0x%X\n", to_##__s(item)->__name); \
}

#define IKGT_UINT32_STORE(__s, __name)  \
    static ssize_t __s##_##__name##_store(struct config_item *item, \
    const char *page, \
    size_t count) \
{ \
    unsigned long value;\
    \
    if (kstrtoul(page, 0, &value)) \
    return -EINVAL; \
    to_##__s(item)->__name = value;             \
    \
    return count; \
}

#define IKGT_ULONG_HEX_SHOW(__s, __name)    \
    static ssize_t __s##_##__name##_show(struct config_item *item,  \
    char *page) \
{   \
    return sprintf(page, "0x%lX\n", to_##__s(item)->__name);    \
}

#define IKGT_ULONG_HEX_STORE(__s, __name)   \
    static ssize_t __s##_##__name##_store(struct config_item *item, \
    const char *page, \
    size_t count) \
{ \
    unsigned long value;\
    \
    if (kstrtoul(page, 16, &value)) \
    return -EINVAL; \
    to_##__s(item)->__name = value;             \
    \
    return count; \
}

#else

#define IKGT_CONFIGFS_ATTR_RO(__s, __name)				\
	static struct __s##_attribute __s##_attr_##__name =	\
		__CONFIGFS_ATTR_RO(_name, __s##_show_##__name);

#define IKGT_CONFIGFS_ATTR_RW(__s, __name)								\
	static struct __s##_attribute __s##_attr_##__name =					\
		__CONFIGFS_ATTR(__name, S_IRUGO | S_IWUSR, __s##_show_##__name, \
						__s##_store_##__name)

#define IKGT_UINT32_SHOW(__s, __name)						\
	static ssize_t __s##_show_##__name(struct __s *item,    \
									   char *page)			\
	{														\
		return sprintf(page, "%u\n", item->__name);			\
	}

#define IKGT_UINT32_HEX_SHOW(__s, __name)					\
	static ssize_t __s##_show_##__name(struct __s *item,    \
									   char *page)          \
	{                                                       \
		return sprintf(page, "0x%X\n", item->__name);		\
	}

#define IKGT_UINT32_STORE(__s, __name)						\
	static ssize_t __s##_store_##__name(struct __s *item,   \
										const char *page,   \
										size_t count)       \
	{                                                       \
		unsigned long value;								\
															\
		if (kstrtoul(page, 0, &value))						\
			return -EINVAL;									\
		item->__name = value;								\
															\
		return count;										\
	}

#define IKGT_ULONG_HEX_SHOW(__s, __name)					\
	static ssize_t __s##_show_##__name(struct __s *item,    \
									   char *page)          \
	{                                                       \
		return sprintf(page, "0x%lX\n", item->__name);		\
	}

#define IKGT_ULONG_HEX_STORE(__s, __name)					\
	static ssize_t __s##_store_##__name(struct __s *item,   \
										const char *page,   \
										size_t count)       \
	{                                                       \
		unsigned long value;								\
															\
		if (kstrtoul(page, 16, &value))						\
			return -EINVAL;									\
		item->__name = value;								\
															\
		return count;										\
	}
#endif


typedef uint8_t policy_action_r;
typedef uint8_t policy_action_w;
typedef uint8_t policy_action_x;

struct cr0_cfg {
    struct config_item item;
    bool enable;
    bool locked;
    policy_action_w write;
    unsigned long sticky_value;
};

struct cr4_cfg {
    struct config_item item;
    bool enable;
    bool locked;
    policy_action_w write;
    unsigned long sticky_value;
};

struct msr_cfg {
    struct config_item item;
    bool enable;
    bool locked;
    policy_action_w write;
    unsigned long sticky_value;
};

typedef struct _name_value_map {
    const char *name;
    unsigned long value;
    uint32_t res_id;
} name_value_map;


void ikgt_debug(uint64_t parameter);

#endif /* _COMMON_H */
