#!/usr/bin/env python

import csv
import sys
import os
import json
import pprint, StringIO
import bgpranking_web


def run_bgprank(ip_value):
    if ip_value == "-":
        return None

    retval = {'ip': ip_value, 'ip_ASN': '', 'ip_block': '', 'ip_AS_description': '', 'ip_AS_rank': '', 'ip_rank_date': ''}
    ip_lookup = bgpranking_web.ip_lookup(ip_value, 1)
    retval['ip_ASN'] = ip_lookup['history'][0]['asn']
    retval['ip_block'] = ip_lookup['history'][0]['block']

    asn_rank = bgpranking_web.all_ranks_single_asn(retval['ip_ASN'], timeframe=1)
    rank_date = bgpranking_web.cached_daily_rank(retval['ip_ASN'])
#    print "daily:::::    "+str(daily)

    for k, v in asn_rank.iteritems():
        retval['ip_rank_date'] = rank_date[2]
        retval['ip_AS_description'] = v['description']
        retval['ip_AS_rank'] = v['total']

    return retval
#    return ip_lookup


def main():
    if(len(sys.argv) != 2):
        print "Usage: python bgprank.py ip"
        sys.exit(0)

#    header = ['ip', 'ip_ASN', 'ip_block', 'ip_AS_description', 'ip_AS_rank']

#    csv_in  = csv.DictReader(sys.stdin) # automatically use the first line as header
#    csv_out = csv.DictWriter(sys.stdout, header)

    # write header
#    csv_out.writerow(dict(zip(header, header)))

#    for row in csv_in:
#    	json_res = run_bgprank(row['ip'])
    json_res = run_bgprank(sys.argv[1])
#    if json_res:
#    row.update(json_res)
    print json_res
#    csv_out.writerow(row)

if __name__ == "__main__":
    main()