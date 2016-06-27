#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Scan for open ports on remote host(s)

This program uses nmap to scan for open ports on remote host(s)

Example:
    $ python __file__ -t 192.168.0.1 -s -r -n "-e <wifi_device_id>"

Author: chris.sampson@naimuri.com
'''
from builtins import range
import logging.config, yaml
import sys, getopt, os.path, random
from time import sleep
from timeit import default_timer as timer
import pprint

import nmap


# setup logging config
logging.config.dictConfig(yaml.load(open(os.path.join('config', 'logging.yaml'))))
logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])


PORT_MAX = 65535


def _print_usage(exit_code=0):
    '''Print usage and exit

    Args:
        exit_code (int):    The exit code to use when terminating the script

    '''
    f = sys.stderr if exit_code > 0 else sys.stdout

    print(__file__ + " [--min-port=<min port>] [--max-port=<max port>] [--port-inc=<port_range_increment>] [--min-time=<min time>] [--max-time=<max time>] [--num-scans=<num scans>] [-n <nmap options>|--nmap-ops=<nmap options>] [-r|--randomise] -t|--target-host=<target host>", file=f)
    # TODO: elaborate on args

    sys.exit(exit_code)

def scan_ports(target_host, min_port, max_port, port_range_increment, min_time, max_time, num_scans, randomised, nmap_opts, sudo):
    '''Scan ports as defined by input args

    Args:
        

    '''
    # TODO: complete function documentation
    
    logger.info("Setting up %d scans of host(s) %s between ports %d and %d (port range increment=%d, randomised=%s, sudo=%s, nmap_opts=%s)", num_scans, target_host, min_port, max_port, port_range_increment, str(randomised), str(sudo), nmap_opts)
    
    # get handle on nmap
    nm = nmap.PortScanner()
    
    # setup range of ports that could be scanned
    all_ports = range(min_port, max_port)
    
    # run through configured number of scans
    for s in range(0, num_scans):
        logger.debug("Scan %d of %d", (s+1), num_scans)
        
        # determine ports to be scanned in this iteration
        num_ports = min(port_range_increment * (s+1), len(all_ports))
        
        # TODO: when get over ~20k ports, need to batch up nmap calls due to OS arg limitations
        if randomised:
            scan_ports = ','.join(str(i) for i in random.sample(all_ports, num_ports))
        else:
            scan_ports = str(min_port) + '-' + str(min_port + num_ports)
        logger.debug("Ports to scan: %s", scan_ports)
        
        # execute the scan
        nm.scan(hosts=target_host, ports=scan_ports, arguments=nmap_opts, sudo=sudo)
        
        # log nmap command and some results
        logger.debug("nmap command line: %s", nm.command_line())
        logger.debug("nmap scan info: %s", nm.scaninfo())

	# TODO: output meaningful results
        logger.debug("nmap result: %s", pprint.pformat(nm.csv()))
        
        # wait before next scan if there are scans left to perform
        if (s+1) < num_scans:
            if min_time < max_time:
                wait_time = random.randint(min_time, max_time)
            else:
                wait_time = min_time
                
            logger.debug("Waiting %d seconds until next scan", wait_time)
            sleep(wait_time)
        

def main(argv):
    '''Parse input args and run the Port Scanner against specified target host(s) (-t|--target-host)

    Args:
        argv (list):    List of command line arguments

    '''
    # expect one or more hosts to be targeted
    target_host = None
    
    # whether sudo needs to be used
    sudo = False
    
    # allow port boundaries and scan ranges to be configured
    min_port = 1
    max_port = PORT_MAX
    port_range_increment = 50
    
    # allow times between port scans to be configured
    min_time = 10
    max_time = 60
    
    # allow ports and times to be randomised
    randomised = False

    # number scans
    num_scans = 1
    
    # nmap command-line args
    nmap_opts = ''

    try:
        logger.info('Args: %s', argv)
        opts, _ = getopt.getopt(argv, "hrst:n:", ["help", "randomise", "sudo", "min-port=", "max-port=", "port-inc=", "min-time=", "max-time=", "num-scans=", "nmap-opts=", "target-host="])
    except getopt.GetoptError:
        _print_usage(1)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            _print_usage(0)
        elif opt in ('-t', "--target-host"):
            target_host = arg
        elif opt in ('-s', "--sudo"):
            sudo = True
        elif opt in ('-r', "--randomise"):
            randomised = True
        elif opt in ("-n", "--nmap-opts"):
            nmap_opts = arg
        elif opt == '--min-port':
            try:
                min_port = int(arg)
                if min_port < 1 or min_port > PORT_MAX:
                    logger.error("Min Port (--min-port) must be between 1 and %d, got %d", PORT_MAX, min_port)
                    sys.exit(3)
            except:
                logger.exception("Unable to parse min port (--min-port), must be numeric, got %s", min_port)
                sys.exit(4)
        elif opt == '--max-port':
            try:
                max_port = int(arg)
                if max_port < 1 or max_port > PORT_MAX:
                    logger.error("Max Port (--max-port) must be between 1 and %d, got %d", PORT_MAX, max_port)
                    sys.exit(5)
                elif max_port < min_port:
                    logger.error("Max Port (--max-port) must be greater than Min Port (--min-port, default 1), got %d", max_port)
                    sys.exit(6)
            except:
                logger.exception("Unable to parse max port (--max-port), must be numeric, got %s", max_port)
                sys.exit(7)
        elif opt == '--min-time':
            try:
                min_time = int(arg)
                if min_time < 1:
                    logger.error("Min Time (--min-time) must be greater than 0, got %d", min_time)
                    sys.exit(8)
            except:
                logger.exception("Unable to parse min time (--min-time), must be numeric, got %s", min_time)
                sys.exit(9)
        elif opt == '--max-time':
            try:
                max_time = int(arg)
                if max_time < 1:
                    logger.error("Max Time (--max-time) must be greater than 0, got %d", max_time)
                    sys.exit(10)
                elif max_time < min_time:
                    logger.error("Max Time (--max-time) must be greater than Min Time (--min-time, default 10), got %d", max_time)
                    sys.exit(11)
            except:
                logger.exception("Unable to parse max time (--max-time), must be numeric, got %s", max_time)
                sys.exit(12)
        elif opt == '--port-inc':
            try:
                port_range_increment = int(arg)
                if port_range_increment < 1 or port_range_increment > PORT_MAX:
                    logger.error("Port Range Increment (--port-inc) must be between 0 and %d, got %d", PORT_MAX, port_range_increment)
                    sys.exit(13)
            except:
                logger.exception("Unable to parse port range increment (--port-inc), must be numeric, got %s", port_range_increment)
                sys.exit(14)
        elif opt == '--num-scans':
            try:
                num_scans = int(arg)
                if num_scans < 1:
                    logger.error("Number of Scans (--num-scans) must be greater than 0, got %d", num_scans)
                    sys.exit(15)
            except:
                logger.exception("Unable to parse number of scans (--num-scans), must be numeric, got %s", num_scans)
                sys.exit(16)
    
    if target_host is None or len(target_host) == 0:
        logger.exception("Target Host(s) (-t | --target-host) must be specified")
        sys.exit(1)

    start = timer()

    scan_ports(target_host, min_port, max_port, port_range_increment, min_time, max_time, num_scans, randomised, nmap_opts, sudo)

    end = timer()
    logger.info("Time Taken (seconds): %f", end - start)

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except:
        logger.exception('Problem executing program')
        raise
