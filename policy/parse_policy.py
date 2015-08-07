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
import json

#Strings from JSON file
log_val = 'log.txt'

#Command strings
echo_cmd = 'echo '
touch_cmd = 'touch '

def execute_shell_command(command):
	try:
		subprocess.check_call(command, shell=True)
	except subprocess.CalledProcessError as e:
		print "Shell command error: %s" % str(e)
		sys.exit()

def parse_and_create_dir_structure(policy_data):
	for key, value in policy_data.iteritems():
		try:
			if isinstance(value, dict):
				#Save cwd
				prev_dir = os.getcwd()

				#Create this dir
				os.mkdir(key)

				#Change to this dir
				os.chdir(key)

				#Create sub directories
				parse_and_create_dir_structure(value)

				#Change back to original dir
				os.chdir(prev_dir)
			else:
				if key == log_val:
					#Create log file
					touch_command = touch_cmd + value
					execute_shell_command(touch_command)
				else:
					if os.path.exists(key):
						#Echo value to file
						echo_command = echo_cmd + str(value) + " > " + key
						execute_shell_command(echo_command)
		except OSError as e:
			#Ignore all errors
			continue

def parse_and_remove_dir_structure(policy_data):
	for key, value in policy_data.iteritems():
		try:
			shutil.rmtree(key, ignore_errors=True)
		except OSError as e:
			print "Error removing directory: %s" % str(e)
			sys.exit()

def parse_policy():
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--policy_file", help="JSON file defining evmm hardening policy", required=True)
	parser.add_argument("-b", "--base_dir", help="Base directory to start from (eg. /configfs)", required=True)
	parser.add_argument("-r", "--remove_dir", action="store_true", help="Remove directory structure in policy file")
	args = parser.parse_args()

	try:
		policy_file = open(args.policy_file)
		policy_data = json.load(policy_file)
	except IOError as e:
		print "I/O error({0}): {1}".format(e.errno, e.strerror)
	except ValueError:
		print "Error loading policy data, invalid JSON file!"
	else:
		#Save cwd
		prev_dir = os.getcwd()

		#Change to base dir
		os.chdir(args.base_dir)

		#Create/remove sub directories
		if args.remove_dir:
			parse_and_remove_dir_structure(policy_data)
		else:
			parse_and_create_dir_structure(policy_data)

		#Change back to original dir
		os.chdir(prev_dir)

		if args.remove_dir:
			print "Successfully parsed policy file and directory entries!"
		else:
			print "Successfully parsed policy file and setup entries!"

		policy_file.close()

parse_policy()
