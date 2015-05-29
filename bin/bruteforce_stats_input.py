#!/usr/bin/env python

# William Showalter
# Honeynet Challenge 5 Splunk App

# Based on wh1sk3yj4ck's submission to the Honeynet challenge 5
# https://www.honeynet.org/files/william_soderberg_Forensic_Challenge_2010_-_Challenge_5_-_Submission.pdf
# By William 'wh1sk3yj4ck' Soderberg
# E-mail: william.soderberg@gmail.com

# Looks for SSH bruteforce attempts in auth.log data provided by the Honeynet Challenge 5 Splunk App.

import sys
import csv

# Logging
import os
import logging, logging.handlers

# Global variable setup
sshdInfo = dict() 
ip = 0
time = 0
index = 12 # index in list where IP is stored

def setup_logger():
	logger = logging.getLogger('brute')
	logger.setLevel(logging.DEBUG)
	
	file_handler = logging.handlers.RotatingFileHandler('/Users/William/Desktop/brute.log')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	file_handler.setFormatter(formatter)
	logger.addHandler(file_handler)

	return logger

#### DEBUGGING ####
logger = setup_logger()


def checkRatio():
	# Checks success/failed ratio in order to remove false positives
	tmpLst = []
	
	for k, v in sshdInfo.iteritems():
		if v[4] > 0:
			# Adjust tolerance here.
			# Default tolerance is 1 success of 10
			if (v[4]/float(v[2])) > float(0.1):
				tmpLst.append(k)
				
	# Removing keys with a good ratio
	for keys in tmpLst:
		del sshdInfo[keys]

def check(row):
	# Function that will check for failed entries in the logfile
	line = row["_raw"].strip().split()
	
	if 'Failed' in line:
		if 'invalid' in line:
			storeFailed(line, index, row["_time"], row)
		else:
			storeFailed(line, index - 2, row["_time"], row)		
	elif 'Accepted' in line:
		storeSuccessful(line, row["_time"], row)
		
def storeFailed(line, index, time, row):	
	attempts = 0
	success = 0
	ip = line[index]
			
	# IP-addr. resides at index 12
	if ip not in sshdInfo:
		# Adds initial values to IP key
		sshdInfo[ip] = [time, time, attempts, [], success, row]

	# If IP key already exist, then renew end time and add one to attempts
	sshdInfo[ip][1] = time
	sshdInfo[ip][2] += 1		

def storeSuccessful(line, time, row):
	ip = line[10]
	user = line[8]

	if ip not in sshdInfo:
		# We don't need to add successful attempts that's not considered
		# a brute force attempt.
		return
		
	sshdInfo[ip][3].append(time) # adds when the acc was compromised
	sshdInfo[ip][3].append(user) # adds user

	sshdInfo[ip][1] = time # adds newest timestamp
	sshdInfo[ip][4] += 1 # adds success
	sshdInfo[ip][5] = row
	
def writeReport():
	# Writes a detailed report of the findings to a file
	
	for k, v in sshdInfo.iteritems():
		row = v[5]
		row["attacker"] = k
		row["_time"] = v[0]
		row["success_count"] = v[4]
		row["failure_count"] = int(v[2])-int(v[4])
		row["duration"] = int(v[1])-int(v[0])
		# Only supplying first account successfully compromised
		if len(v[3]) > 0:
			row["account"] = v[3][1]
		csv_out.writerow(row)
	#for row in input_data:
	#	csv_out.writerow(row)

def main():
	# Checks for failed and successful login attempts, rest is discarded
	for row in csv_in:
		input_data.append(row)
		if 'sshd' and 'Failed' in row["_raw"].strip().split():
			check(row)
		elif 'sshd' and 'Accepted' in row["_raw"].strip().split():
			check(row)

csv_out.writerow(dict(zip(header,header))) # write header

main()
checkRatio()
writeReport()