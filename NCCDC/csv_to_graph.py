#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Parse CSV data from a file and plot features in a graph

This script parses PCAP data from a specified CSV file (pre-processed using pcap_to_csv.py),
plotting features against known packet type.

Example:
    $ python __file__ -i csv_file_data -o /tmp -n 1000000 -d

Author: chris.sampson@naimuri.com
'''
from datetime import datetime
import logging.config, yaml
import sys, getopt, os.path, struct, socket
from timeit import default_timer as timer

import matplotlib.pyplot as plt
import numpy as np

'''int:    Bits representing TCP Flags'''
# FLAG_FIN = 1
FLAG_SYN = 2
# FLAG_RST = 4
# FLAG_PSH = 8
FLAG_ACK = 16
# FLAG_URG = 32

'''string:    Column names used to access array data from ingested CSV'''
COL_ROWNUM = 'rownum'
COL_PROTOCOL = 'protocol'
COL_TIME = 'time'
COL_SOURCE_IP = 'src'
COL_DEST_IP = 'dst'
COL_SOURCE_PORT = 'src_port'
COL_DEST_PORT = 'dst_port'
COL_TTL = 'ttl'
COL_LENGTH = 'length'
COL_FRAGMENT = 'fragment'
COL_FLAGS = 'flags'

'''int:    Default lower bounds limit'''
DEFAULT_LOWER_BOUNDS = 200

start = timer()

# setup logging config
logging.config.dictConfig(yaml.load(open(os.path.join('config', 'logging.yaml'))))
logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])

def _print_usage(exit_code=0):
    '''Print usage and exit

    Args:
        exit_code (int):    The exit code to use when terminating the script

    '''
    f = sys.stderr if exit_code > 0 else sys.stdout

    print(__file__ + " -i <input file> [-o <output dir>] [-n <num records>] [-l <lower bounds> [-d]", file=f)
    print("-i <input file>: CSV format data file to be parsed")
    print("-n <num records>: Number of CSV rows to read as records for input")
    print("-i <output dir>: Directory for output of graph images (if unspecified, images will be shown but not saved)")
    print("-l <lower bounds>: Lower bounds for number of points before plotting a destination IP's incoming sources (default = 200)")

    sys.exit(exit_code)

def _ipv4_int_to_dotted(ip_address):
    '''Convert a decimalised Ipv4 Address to its dotted representation

    Args:
        ip_address (int):       IP (v4) Address in decimalised format

    Returns:
        str:    Decimal-dot representation of all IP (v4) Address bytes

    '''
    return socket.inet_ntoa(struct.pack("!L", int(ip_address)))

def _draw_graph(x_points, y_points, point_labels, x_title, y_title, title=None, output_dir=None, output_file=None, cmap_name='Paired'):
    '''
    Draw a 2D graph using matplotlib and either save to output_dir or display to user
    '''
    # create a new figure
    plt.figure(figsize=(8, 6))
    plt.clf()

    # plot the points
    plt.scatter(x_points, y_points, c=point_labels, cmap=plt.cm.get_cmap(cmap_name))

    # add axis labels
    plt.xlabel(x_title)
    plt.ylabel(y_title)

    # add title
    plt.title(title)

    # scale to axes
    plt.autoscale(tight=False)

    if output_dir is None or output_file is None:
        # display the graph
        plt.show()
    else:
        # save image to output dir
        plt.savefig(os.path.join(output_dir, output_file))
    plt.close()

def _plot_feature_graphs(csv_data, output_dir=None):
    '''
    Plot several 2D graphs comparing standard features of the data
    '''

    # TODO: get distinct points for graphs rather than re-plotting the same points lots of times
    # TODO: plot multiple graphs at the same time (multiprocessing? multi-threading?)

    # get known protocol values
    protocols = csv_data[COL_PROTOCOL]
    logger.debug("Protocol extracted (seconds): " + str(timer() - start))

    # plot source/destination IPs
    _draw_graph(csv_data[COL_SOURCE_IP], csv_data[COL_DEST_IP], protocols, 'Source IP', 'Destination IP', 'Source vs. Destination IP', output_dir, 'dest_source_ip_analysis.png')
    logger.debug("Src/Dest IP plotted (seconds): " + str(timer() - start))

    # plot source/destination ports
    _draw_graph(csv_data[COL_SOURCE_PORT], csv_data[COL_DEST_PORT], protocols, 'Source Port', 'Destination Port', 'Source vs. Destination Port', output_dir, 'dest_source_port_analysis.png')
    logger.debug("Src/Dest Port plotted (seconds): " + str(timer() - start))

    # plot time to live/length
    _draw_graph(csv_data[COL_TTL], csv_data[COL_LENGTH], protocols, 'Time to Live', 'Packet Length', 'TTL vs. Packet Length', output_dir, 'length_ttl_analysis.png')
    logger.debug("TTL/Length IP plotted (seconds): " + str(timer() - start))

    # plot length/fragment
    _draw_graph(csv_data[COL_LENGTH], csv_data[COL_FRAGMENT], protocols, 'Packet Length', 'Fragment', 'Packet Length vs. Fragment', output_dir, 'fragment_length_analysis.png')
    logger.debug("Length/Fragment IP plotted (seconds): " + str(timer() - start))

    # src port/flags
    _draw_graph(csv_data[COL_SOURCE_PORT], csv_data[COL_FLAGS], protocols, 'Source Port', 'Flags', 'Source Port vs. TCP Flags', output_dir, 'tcpflags_source_port_analysis.png')
    logger.debug("Src Port/Flags plotted (seconds): " + str(timer() - start))

def plot_csv_features(csv_file, lower_bounds, output_dir=None, num_records=None):
    '''Parse PCAP data CSV file content and plot graphs of features vs. known packet type

    Fields expected in input:
        row#
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

    Args:
        csv_file (str):    Filename of CSV file data to be read
        lower_bounds (int): Lower bounds for number of points before plotting a destination IP's incoming sources
        output_dir (str):  Directory for saving graph images (if None, images will be displayed but not saved)
        num_records (int): Maximum number of records to read from input CSV (default: None - all lines)
    '''
    # read CSV file into Numpy multi-dimensional arrays
    csv_data = np.genfromtxt(csv_file,
                            delimiter=',',
                            autostrip=True,
                            dtype=None,
                            names=[COL_ROWNUM,
                                   COL_PROTOCOL,
                                   COL_TIME,
                                   COL_SOURCE_IP,
                                   COL_DEST_IP,
                                   COL_SOURCE_PORT,
                                   COL_DEST_PORT,
                                   COL_TTL,
                                   COL_LENGTH,
                                   COL_FRAGMENT,
                                   COL_FLAGS],
                            missing_values='?',
                            filling_values='0',
                            invalid_raise=False,
                            max_rows=num_records)
    logger.debug("CSV to array (seconds): " + str(timer() - start))

    # plot feature graphs from data
    feature_graphs_dir = os.path.join(output_dir, "feature_graphs")
    os.makedirs(feature_graphs_dir, exist_ok=True)
    _plot_feature_graphs(csv_data, feature_graphs_dir)
    logger.debug("Graphs plotted (seconds): " + str(timer() - start))

    # sort data by Destination IP and Timestamp
    sorted_dst_data = np.sort(csv_data, order=[COL_DEST_IP, COL_TIME])

    # Split data into sub-arrays based on Destination IP
    dst_ips = np.split(sorted_dst_data, np.where(np.diff(sorted_dst_data[COL_DEST_IP]))[0] + 1)
    logger.debug("Destination IPs (seconds): " + str(timer() - start))

    # track number of sources for each Destination IP if in debug mode
    if logger.isEnabledFor(logging.DEBUG):
        sources = np.zeros([len(dst_ips), 1])
        d = 0

    # TODO: graph IPs individually, including sub-plots:
    #    1 graph file per IP (dst or src), with sub-plots of:
    #        * (scatter) source IP vs. dst port
    #        * (scatter) dst port time series plot
    #        * (bar) #connections over time (5 minute intervals?)
    #        * (bar) bytes received over time (5 minute intervals?)
    #        * (pie chart) total connections received/sent
    #        * (pie chart) total bytes received/sent
    # TODO: plot multiple graphs at the same time (multiprocessing? multi-threading?)

    # iterate through collections of Destination IP data and output analysis (if applicable)
    ips = {}
    for dst_data in dst_ips:
        # determine current Destination IP and number of connection records
        dst_ip = dst_data[0][COL_DEST_IP]
        num_connections = len(dst_data)

        # log received data stats for the IP
        ips[str(dst_ip)] = dict(bytes_received=np.sum(dst_data[COL_LENGTH]),
                                received_connections=num_connections,
                                dst_details=dst_data,
                                bytes_sent=0,
                                sent_connections=0,
                                src_details=list())

        # plot graphs if sufficient data to be of interest
        if num_connections >= lower_bounds:
            # plot Destination Ports vs. Source IP (indicating protocols used)
            dst_src_graphs_dir = os.path.join(output_dir, "dst_src_graphs")
            os.makedirs(dst_src_graphs_dir, exist_ok=True)
            _draw_graph(dst_data[COL_DEST_PORT], dst_data[COL_SOURCE_IP], dst_data[COL_PROTOCOL], 'Destination Port', 'Source IP', _ipv4_int_to_dotted(dst_ip), dst_src_graphs_dir, _ipv4_int_to_dotted(dst_ip) + '_destination_ports_and_source_ips.png')

            # timeline plot of single Destination IP
            dst_time_graphs_dir = os.path.join(output_dir, "dst_time_graphs")
            os.makedirs(dst_time_graphs_dir, exist_ok=True)
            _draw_graph(dst_data[COL_TIME], dst_data[COL_DEST_PORT], dst_data[COL_SOURCE_IP], 'Time', 'Destination Port', _ipv4_int_to_dotted(dst_ip), dst_time_graphs_dir, _ipv4_int_to_dotted(dst_ip) + '_time_and_destination_ports.png')

        # debug output of the source characteristics for all destinations
        if logger.isEnabledFor(logging.DEBUG):
            sources[d] = len(dst_data)
            d += 1

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Num: " + str(len(sources)) + ", Min: " + str(min(sources)) + ", Max: " + str(max(sources)) + ", Avg: " + str(sum(sources) / len(sources)))
        sources = None
        logger.debug("Destination Graphs (seconds): " + str(timer() - start))

    # obtain "sent" details for each IP
    sorted_src_data = np.sort(csv_data, order=[COL_SOURCE_IP, COL_TIME])
    src_ips = np.split(sorted_src_data, np.where(np.diff(sorted_src_data[COL_SOURCE_IP]))[0] + 1)
    for src_data in src_ips:
        # determine current Destination IP and number of connection records
        src_ip = src_data[0][COL_SOURCE_IP]
        num_connections = len(src_data)

        # log received data stats for the IP
        if not src_ip in src_data:
            ips[str(src_ip)] = dict(bytes_received=0,
                                    received_connections=0,
                                    dst_details=list(),
                                    bytes_sent=np.sum(src_data[COL_LENGTH]),
                                    sent_connections=num_connections,
                                    src_details=src_data)
        else:
            ips[str(src_ip)]["bytes_sent"] = np.sum(src_data[COL_LENGTH])
            ips[str(src_ip)]["sent_connections"] = num_connections
            ips[str(src_ip)]["dst_details"] = list()
            ips[str(src_ip)]["src_details"] = src_data

    for ip in ips.keys():
        # TODO: "bowtie" plot each IP's incoming/outgoing data/connections *** pie charts??
        recv_sent_data_graphs_dir = os.path.join(output_dir, "recv_sent_graphs")
        os.makedirs(recv_sent_data_graphs_dir, exist_ok=True)
#         _draw_graph([ips[ip]["bytes_received"]], [ips[ip]["bytes_sent"]], [ip], 'Bytes Received', 'Bytes Sent', _ipv4_int_to_dotted(ip), recv_sent_data_graphs_dir, _ipv4_int_to_dotted(ip) + '_bytes_received_and_sent.png')

    logger.debug("IP Details (seconds): " + str(timer() - start))

def main(argv):
    '''Parse input args and run the PCAP data CSV parser on specified inputfile (-i)

    Args:
        argv (list):    List of command line arguments

    '''
    logger.info("Start: " + datetime.now().strftime('%d/%m/%Y %H:%M:%S.%f'))
    start = timer()

    inputfile = ''
    outputdir = None
    num_records = None
    lower_bounds = DEFAULT_LOWER_BOUNDS

    try:
        opts, _ = getopt.getopt(argv, "hi:o:n:l:")
    except getopt.GetoptError:
        _print_usage(1)

    for opt, arg in opts:
        if opt == '-h':
            _print_usage(0)
        elif opt == '-i':
            inputfile = arg
            if not os.path.isfile(inputfile):
                logger.error("Invalid inputfile (-i), file does not exist")
                sys.exit(2)
        elif opt == '-o':
            outputdir = arg
            if not os.path.isdir(outputdir):
                logger.error("Invalid outputdir (-o), directory does not exist")
                sys.exit(2)
        elif opt == '-n':
            try:
                num_records = int(arg)
                if num_records < 1:
                    logger.error("Number of records (-n) must be greater than 0")
                    sys.exit(3)
            except Exception:
                logger.error("Unable to parse number of records (-n), must be numeric")
                sys.exit(4)
        elif opt == '-l':
            try:
                lower_bounds = int(arg)
                if lower_bounds < 1:
                    logger.error("Lower bounds (-l) must be greater than 0")
                    sys.exit(5)
            except Exception:
                logger.error("Unable to parse lower bounds (-l), must be numeric")
                sys.exit(6)

    logger.info('Input file is: ' + inputfile)
    if not outputdir is None:
        logger.info('Output directory is: ' + outputdir)
    if not num_records is None:
        logger.info('Number of records is: ' + str(num_records))
    if not lower_bounds is None:
        logger.info('Lower bounds is: ' + str(lower_bounds))

    plot_csv_features(inputfile, lower_bounds, outputdir, num_records)

    end = timer()
    logger.info("End: " + datetime.now().strftime('%d/%m/%Y %H:%M:%S.%f'))
    logger.info("Execution time (seconds):" + str(end - start))


if __name__ == "__main__":
    main(sys.argv[1:])
