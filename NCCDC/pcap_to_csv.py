#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Parse PCAP data from a file using the scapy python library

This script parses PCAP data from a specified pcap file and extracts IP (v4) packet details,
printing them to STDOUT in CSV format.

Example:
	$ python __file__ -i pcap_sample_data -n 5

Author: chris.sampson@naimuri.com
'''
from datetime import datetime
import logging.config, yaml
import sys, getopt, os.path, struct, socket, pprint
from timeit import default_timer as timer

# import scapy library, ignoring IPv6 warnings (as we're only interested in IPv4 for this script)
scapy_rt_logger = logging.getLogger("scapy.runtime")
scapy_rt_orig_level = scapy_rt_logger.level
scapy_rt_logger.setLevel(logging.ERROR)
from scapy.all import PcapReader
scapy_rt_logger.setLevel(scapy_rt_orig_level)

DEFAULT_NUM_RECORDS = -1
'''int:	Default value for number of records to be output, -1 = output all records'''

# setup logging config
logging.config.dictConfig(yaml.load(open(os.path.join('config', 'logging.yaml'))))
logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])


def _print_usage(exit_code=0):
	'''Print usage and exit

	Args:
		exit_code (int):	The exit code to use when terminating the script

	'''
	f = sys.stderr if exit_code > 0 else sys.stdout

	print(__file__ + " [-i <input file>] [-n <number of records to parse>] [-d]", file=f)
	print("-i <input file>: PCAP format data file to be parsed")
	print("-n <num_records>: (optional) number of packets to be output from <input file>; default to output all packets")

	sys.exit(exit_code)

def ipv4_to_int(ip_address):
	'''Convert an Ipv4 Address to its decimal representation

	Args:
		ip_address (str):	IP (v4) Address in standard decimal-dot format

	Returns:
		int:	Decimal representation of all IP (v4) Address bytes

	'''
	return struct.unpack('>L', socket.inet_aton(ip_address))[0]

def parse_pcap_ipv4(pcap_file, num_records=DEFAULT_NUM_RECORDS):
	'''Parse pcap file content, extracting details of IP (v4) records and output details to STDOUT

	Fields included in output:
		protocol (IP)
		time
		source (IP Address)
		destination (IP Address)
		source port
		destination port
		time to live (IP)
		length (IP)
		fragment (IP)
		flags (TCP)

	Packets not containing an IP (version = 4) layer are ignored.

	Protocols processed for output:
		1:	ICMP
		6:	TCP
		17:	UDP

	Flags bit field indicating:
		1:	FIN
		2:	SYN
		4:	RST
		8:	PSH
		16:	ACK
		32:	URG

	Args:
		pcap_file (str):	Filename of PCAP file data to be read
		num_records (int):	Number of records to be output from parsed PCAP file (not including ignored records)

	'''
	protocols = {}
	input_index = 1
	output_index = 1

	# parse the pcap file, one packet at a time
	with PcapReader(pcap_file) as pcap_reader:
		for pkt in pcap_reader:
			# count number of PCAP records read from file
			input_index += 1

			# check the packet contains IP (v4) details and is using one of the wanted protocols
			if 'IP' in pkt and pkt['IP'].version == 4 and pkt['IP'].proto in (1, 6, 17):
				try:
					# extract time, source IP, destination IP, source port, destination port, time to live, length, fragment, protocol
					t = pkt.time
					src = pkt.sprintf("%IP.src%")
					dst = pkt.sprintf("%IP.dst%")
					ipproto = pkt.sprintf("%r,IP.proto%")

					# debug out in more human-readable format
					if logger.isEnabledFor(logging.DEBUG):
						ipproto_name = pkt.sprintf("%IP.proto%")

						logger.debug(','.join(
									(
										str(output_index),
										ipproto_name,
										datetime.utcfromtimestamp(t).strftime('%d/%m/%Y %H:%M:%S.%f'),
										src,
										dst,
										pkt.sprintf("%sport%,%dport%,%IP.ttl%,%IP.len%,%IP.frag%,{TCP:%TCP.flags%}")
									)
								))

						if ipproto_name in protocols:
							protocols[ipproto_name] += 1
						else:
							protocols[ipproto_name] = 1

					# print decimalised field format
					print(','.join(
									(
										str(output_index),
										str(ipproto),
										str(t),
										str(ipv4_to_int(src)),
										str(ipv4_to_int(dst)),
										# flags = 0 if no TCP layer present
										pkt.sprintf("%r,sport%,%r,dport%,%IP.ttl%,%IP.len%,%IP.frag%,{TCP:%r,TCP.flags%}")
									)
								)
							)

					# stop parsing if reached requested limit
					if num_records != DEFAULT_NUM_RECORDS and output_index >= num_records:
						break

					output_index += 1
					if logger.isEnabledFor(logging.DEBUG) and output_index % 100000 == 0:
						logger.debug(str(output_index) + ": " + datetime.now().strftime('%d/%m/%Y %H:%M:%S.%f'))
				except AttributeError as ae:
					logger.warn("Problem parsing record %d, skipping: %s", output_index, ae)
					pass

	# log summaries of records processes
	logger.info("Processed %d PCAP records to %d CSV records", input_index, output_index)
	if logger.isEnabledFor(logging.DEBUG) and len(protocols) > 0:
		logger.debug("Protocols in output: %s", pprint.pformat(protocols))

def main(argv):
	'''Parse input args and run the PCAP parser on specified inputfile (-i)

	Args:
		argv (list):	List of command line arguments

	'''
	inputfile = ''
	num_records = DEFAULT_NUM_RECORDS

	try:
		opts, _ = getopt.getopt(argv, "hi:n:")
	except getopt.GetoptError:
		_print_usage(1)

	for opt, arg in opts:
		if opt == '-h':
			_print_usage(0)
		elif opt == '-i':
			inputfile = arg
			if not os.path.isfile(inputfile):
				logger.error("Invalid input file (-i), file (%s) does not exist", inputfile)
				sys.exit(2)
		elif opt == '-n':
			try:
				num_records = int(arg)
				if num_records < 1:
					logger.error("Number of records (-n) must be greater than 0, got %d", num_records)
					sys.exit(3)
			except:
				logger.exception("Unable to parse number of records (-n), must be numeric, got %s", num_records)
				sys.exit(4)

	start = timer()
	logger.info('Input file: %s', inputfile)
	logger.info('Record limit: %d', num_records)

	parse_pcap_ipv4(inputfile, num_records)

	end = timer()
	logger.info("Time Taken (seconds): %f", end - start)

if __name__ == "__main__":
	try:
		main(sys.argv[1:])
	except:
		logger.exception('Problem executing program')
		raise
