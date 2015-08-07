################################################################################
# Copyright (c) 2015 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

PWD=$(shell pwd)
export PROJS = $(PWD)/../../xmon

XMON_CMPL_OPT_FLAGS = -DHANDLER_EXISTS

ifeq ($(debug), 1)
XMON_CMPL_OPT_FLAGS += -DDEBUG
export OUTPUTTYPE = debug
else
export OUTPUTTYPE = release
endif

export BINDIR = $(PROJS)/bin/linux/$(OUTPUTTYPE)/
export OUTDIR = $(PROJS)/build/linux/$(OUTPUTTYPE)/

$(shell mkdir -p $(OUTDIR))
$(shell mkdir -p $(BINDIR))

export XMON_CMPL_OPT_FLAGS

all:
	$(MAKE) -C $(PWD)/handler
	$(MAKE) -C $(PROJS)
	$(MAKE) -C $(PWD)/driver

clean:
	$(MAKE) -C $(PWD)/driver clean
	$(MAKE) -C $(PROJS) clean
	$(MAKE) -C $(PWD)/handler clean


install:
	$(MAKE) -C $(PWD)/driver install
	$(MAKE) -C $(PROJS) install

uninstall:
	$(MAKE) -C $(PROJS) uninstall
