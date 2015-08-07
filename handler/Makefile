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
ifndef PROJS
PWD=$(shell pwd)
export PROJS=$(PWD)/../../../xmon

export CC = gcc
export AS = gcc
export AR = ar

debug ?= 0
ifeq ($(debug), 1)
export XMON_CMPL_OPT_FLAGS = -DDEBUG
export OUTPUTTYPE = debug
else
export XMON_CMPL_OPT_FLAGS =
export OUTPUTTYPE = release
endif

export BINDIR = $(PROJS)/bin/linux/$(OUTPUTTYPE)/
export OUTDIR = $(PROJS)/build/linux/$(OUTPUTTYPE)/

$(shell mkdir -p $(OUTDIR))
$(shell mkdir -p $(BINDIR))
endif # PROJS

$(shell mkdir -p $(OUTDIR)handler)

TARGET = handler.a

CSOURCES = $(wildcard *.c)

INCLUDES = -I. \
           -I../common/include \
           -I$(PROJS)/common/include \
           -I$(PROJS)/plugins/ikgt-plugin/vmx/include \
           -I$(PROJS)/plugins/ikgt-plugin/common/include

CFLAGS = -c $(XMON_CMPL_OPT_FLAGS) \
         -O2 -std=gnu99 -fPIC -nostdinc -fno-stack-protector \
         -fdiagnostics-show-option -funsigned-bitfields \
         -m64 -march=nocona -D ARCH_ADDRESS_WIDTH=8 \
         -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow \
         -fno-hosted -fomit-frame-pointer

CFLAGS += $(INCLUDES)

.PHONY: all

COBJS = $(addprefix $(OUTDIR)handler/, $(notdir $(patsubst %.c, %.o, $(CSOURCES))))

all: $(COBJS) $(TARGET)

$(COBJS): $(CSOURCES)
	$(CC) $(CFLAGS) -o $@ $(filter $(*F).c, $(CSOURCES))

$(TARGET):
	$(AR) rcs $(BINDIR)$@ $(wildcard $(OUTDIR)handler/*.o)

clean:
	rm -rf $(OUTDIR)handler
	rm -f $(BINDIR)$(TARGET)

