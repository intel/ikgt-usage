################################################################################
# This is an example usage of iKGT.
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
################################################################################

import sys
import subprocess
import argparse
import os.path
import shutil

#Strings from CSV File
log_val = sys.argv[1]
kallsyms_val = '/proc/kallsyms'
modules_val = '/proc/modules'
kernel_text_low = int('0xffffffff80000000', 16)
kernel_text_high = int('0xffffffffa0000000', 16)
kernel_vmalloc_low = int('0xffffc90000000000', 16)
kernel_vmalloc_high = int('0xffffe8ffffffffff', 16)
module_low = int('0xffffffffa0000000', 16)
module_high = int('0xffffffffff5fffff', 16)

with open(log_val, "r") as f1:
    array1 = []
    array2 = []
    log_array = []
    i1 = 0
    i2 = 0
    for line1 in f1:
	if 'EOF' not in line1:
		array1.append(line1)
		D1 = dict(item.split("=") for item in array1[i1].split(", "))
		D1 = {key.strip(): value.strip() for key, value in D1.items()}
		#print D1 
		if len(D1) == 7:
			rip = int(D1['RIP'], 16)
			location = 'Unknown'
			name = 'Unknown'
			if (rip >= kernel_vmalloc_low and rip <= kernel_vmalloc_high):
				location = 'kernel_vmalloc'
				#print location
				array1[i1] = array1[i1].rstrip('\n')
				output = array1[i1] + ', caller_type=' + location
			elif (rip >= kernel_text_low and rip <= kernel_text_high):
				location = 'kernel_text'
				#print location
				with open(kallsyms_val, "r") as f2:
					array2 = []
					i2 = 0
					fg = 0
                                        for line2 in f2:
                                                array2.append(line2)
                                                L2 = array2[i2].split(" ")
						L2 = [item.rstrip('\n') for item in L2]
						if ((L2[1] == 't' or L2[1] == 'T') and rip <= int(L2[0], 16)):
							if rip == int(L2[0], 16):
								name = L2[2]
								fg = 1
								break
							try:
								tempL2 = array2[i2-1].split(" ")
								tempL2 = [item.rstrip('\n') for item in tempL2]
								if ((tempL2[1] == 't' or tempL2[1] == 'T') and rip >= int(tempL2[0], 16)):
									name = tempL2[2]
									fg = 1
							except IOError as e:
								print 'Cannot find an entry in ' + kallsyms_val + '.'
							break
                                                #print L2[1]
                                                i2 += 1
					tempL2 = array2[i2-1].split(" ")
                                        tempL2 = [item.rstrip('\n') for item in tempL2]
					if (fg==0 and ((tempL2[1] == 't' or tempL2[1] == 'T') and rip >= int(tempL2[0], 16))):
                                                name = tempL2[2]
				array1[i1] = array1[i1].rstrip('\n')
				output = array1[i1] + ', caller_type=' + location + ', function-name=' + name
			elif (rip >= module_low and rip <= module_high):
				location = 'module'
				#print location
				with open(modules_val, "r") as f2:
                                        array2 = []
					arrayL2 = []
                                        i2 = 0
                                        for line2 in f2:
                                                array2.append(line2)
                                                L2 = array2[i2].split(" ")
                                                L2 = [item.rstrip('\n') for item in L2]
						arrayL2.append(L2)
						i2 += 1
					arrayL2.sort(key=lambda x: int(x[5], 16))
					#print arrayL2
					i2 = 0
					fg = 0;
					for L2 in arrayL2:
                                                if (rip <= int(L2[5], 16)):
                                                        if rip == int(L2[5], 16):
                                                                name = L2[0]
								fg = 1
                                                                break
                                                        try:
                                                                tempL2 = arrayL2[i2-1]
                                                                if (rip >= int(tempL2[5], 16)):
                                                                        name = tempL2[0]
									fg = 1
                                                        except IOError as e:
                                                                print 'Cannot find an entry in ' + modules_val + '.'
                                                        break
                                                #print L2[1]
                                                i2 += 1
					if (fg==0 and rip >= int(arrayL2[i2-1][5], 16)):
						name = arrayL2[i2-1][0]
				array1[i1] = array1[i1].rstrip('\n')
				output = array1[i1] + ', caller_type=' + location + ', module-name=' + name
			else:
				print 'Rest of the kernel'
		else:
			array1[i1] = array1[i1].rstrip('\n')
			output = array1[i1]
                print output
		i1 += 1

