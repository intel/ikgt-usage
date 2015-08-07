################################################################################
#
# This is an example ikgt usage driver.
# Copyright (c) 2015, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
################################################################################

KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)
LIBRARY=$(PWD)/../../../xmon/plugins/ikgt-plugin/lib/

EXTRA_CFLAGS=-I$(src)/../../../xmon/plugins/ikgt-plugin/common/include \
             -I$(src)/../../../xmon/common/include \
             -I$(src)/../common/include

LDFLAGS=-L$(src) \
        -z muldefs

obj-m=ikgt_agent.o
ikgt_agent-objs:=main.o ikgt_api.o em64t/ikgt_api.o \
	configfs_setup.o cr0.o cr4.o msr.o log.o debug.o \
	alloc.o

all:
	-cp -rf $(LIBRARY)/* .
	$(MAKE) -C $(KERNELDIR) M=$(PWD)
	-rm -rf em64t
	-rm ikgt_api.*

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
