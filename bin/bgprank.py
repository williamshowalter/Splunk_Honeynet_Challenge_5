#!/usr/bin/env python

import csv
import sys
import os
import logging
import logging.handlers
import time

from bgprank_web import bgpranking_web

# Global/static like cache
results = {}

def setup_logger():
	"""
	Setup a logger for our lookup
	"""

	logger = logging.getLogger('bgprank')
	logger.setLevel(logging.DEBUG)

	file_handler = logging.handlers.RotatingFileHandler(os.environ['SPLUNK_HOME'] + '/var/log/splunk/bgprank.log' )
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	file_handler.setFormatter(formatter)

	logger.addHandler(file_handler)

	return logger

def run_bgprank(logger, ip_value, dates = None):
	retval = {}
	asn_rank = {}
	try:
		lookup_result = results.get(ip_value)

		if lookup_result == None:
			ip_lookup = bgpranking_web.ip_lookup(ip_value, 1)

			retval = {'ip': ip_value, 'ip_ASN': '', 'ip_block': '', 'ip_AS_description': '', 'ip_AS_rank': '', 'ip_rank_date': ''}
			try:
				retval['ip_ASN'] = ip_lookup['history'][0]['asn']
				retval['ip_block'] = ip_lookup['history'][0]['block']
			except KeyError:
				logger.debug("KeyError caught for ip %s" % ip_value)
				retval['ip_ASN'] = None
				retval['ip_block'] = None
			if retval['ip_ASN'] != None and retval['ip_block'] != None:
				asn_rank = bgpranking_web.all_ranks_single_asn(retval['ip_ASN'], timeframe=1, dates_sources=dates)
			else:
				asn_rank = {}

			results[ip_value] = {'ip_info':retval,'rank':asn_rank}

		else:
			retval = results[ip_value]['ip_info']
			asn_rank = results[ip_value]['rank']

		for k, v in asn_rank.iteritems():
			retval['ip_rank_date'] = k
			retval['ip_AS_description'] = v['description']
			retval['ip_AS_rank'] = v['total']
	except:
		logger.debug("Unhandled exception in bgpranking_web api handler for %s" % ip_value)

	return retval

def main():
	logger = setup_logger()
	time_lookup = False
	header  = []

	if (len(sys.argv) == 2):
		header  = ['ip', 'ip_ASN', 'ip_block', 'ip_AS_description', 'ip_AS_rank', 'ip_rank_date']
	elif (len(sys.argv) == 3):
		header  = ['ip', 'time', 'ip_ASN', 'ip_block', 'ip_AS_description', 'ip_AS_rank', 'ip_rank_date']
		time_lookup = True
	else:
		print "Usage: python bgprank.py ip"
		logger.error("Incorrect Arguments")
		sys.exit(0)

	csv_in  = csv.DictReader(sys.stdin) # automatically use the first line as header
	csv_out = csv.DictWriter(sys.stdout, header)

	# write header
	csv_out.writerow(dict(zip(header, header)))

	for row in csv_in:
		if time_lookup:
			date_obj = time.strftime('%Y-%m-%d', time.gmtime(float(row['time'])))
			dates = {date_obj:['SshblBase']}
			json_res = run_bgprank(logger, row['ip'], dates)
		else:
			json_res = run_bgprank(logger, row['ip'])

		if json_res:
			row.update(json_res)

		csv_out.writerow(row)

if __name__ == "__main__":
	main()
