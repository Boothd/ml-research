#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Parse CSV data from a file and plot features in a graph

This script parses PCAP data from a specified CSV file (pre-processed using pcap_to_csv.py),
plotting features against known packet type.

Example:
    $ python __file__ -i csv_file_data -o /tmp -n 1000000 -l 200 -f

Author: chris.sampson@naimuri.com
'''
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

# setup logging config
logging.config.dictConfig(yaml.load(open(os.path.join('config', 'logging.yaml'))))
logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])

def _print_usage(exit_code=0):
    '''Print usage and exit

    Args:
        exit_code (int):    The exit code to use when terminating the script

    '''
    f = sys.stderr if exit_code > 0 else sys.stdout

    print(__file__ + " -i <input file> [-o <output dir>] [-n <num records>] [-l <lower bounds> [-f]", file=f)
    print("-i <input file>: CSV format data file to be parsed")
    print("-n <num records>: Number of CSV rows to read as records for input")
    print("-o <output dir>: Directory for output of graph images (if unspecified, images will be shown but not saved)")
    print("-l <lower bounds>: Lower bounds for number of points before plotting a destination IP's incoming sources (default = 200)")
    print("-f: output feature graphs (otherwise omitted)")

    sys.exit(exit_code)

def _ipv4_int_to_dotted(ip_address):
    '''Convert a decimalised Ipv4 Address to its dotted representation

    Args:
        ip_address (int):       IP (v4) Address in decimalised format

    Returns:
        str:    Decimal-dot representation of all IP (v4) Address bytes

    '''
    return socket.inet_ntoa(struct.pack("!L", int(ip_address)))

def _start_plot():
    # create a new figure
    fig = plt.figure(figsize=(8, 6))
    plt.clf()

    return fig

def _finish_plot(title, output_dir=None, output_file=None):

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

def _draw_scatter_graph(x_points, y_points, point_labels, x_title, y_title, title, output_dir=None, output_file=None, cmap_name='Paired'):
    '''
    Draw a 2D scatter graph using matplotlib and either save to output_dir or display to user
    '''
    step_start = timer()

    # create a new figure
    _start_plot()

    # plot the points
    plt.scatter(x_points, y_points, c=point_labels, cmap=plt.cm.get_cmap(cmap_name))

    # add axis labels
    plt.xlabel(x_title)
    plt.ylabel(y_title)

    # complete and save/show the plot
    _finish_plot(title, output_dir, output_file)

    logger.debug("%s plotted %d points (seconds): %f", title, len(x_points), timer() - step_start)

def _draw_line_graph(x_points, y_points, x_title, y_title, title, output_dir=None, output_file=None):
    '''
    Draw a 2D line graph using matplotlib and either save to output_dir or display to user
    '''
    step_start = timer()

    # create a new figure
    _start_plot()

    # plot the points
    plt.plot(x_points, y_points, linestyle='-', marker='o', color='r')

    # add axis labels
    plt.xlabel(x_title)
    plt.ylabel(y_title)

    # complete and save/show the plot
    _finish_plot(title, output_dir, output_file)

    logger.debug("%s plotted %d points (seconds): %f", title, len(x_points), timer() - step_start)

def _draw_pie_chart(sizes, labels, colours, title, explode=None, output_dir=None, output_file=None):
    '''
    Draw a 2D pie chart using matplotlib and either save to output_dir or display to user
    '''
    step_start = timer()

    # create a new figure
    _start_plot()

    # plot the areas
    plt.pie(sizes, explode=explode, labels=labels, colors=colours, autopct='%1.1f%%', shadow=True, startangle=90)

    # set aspect ratio to be equal so that pie is drawn as a circle.
    plt.axis('equal')

    # complete and save/show the plot
    _finish_plot(title, output_dir, output_file)

    logger.debug("%s plotted %d areas (seconds): %f", title, len(sizes), timer() - step_start)

def _get_unique_rows(data_arr, fields_arr):
    '''
    Extract unique rows of data from array based on a set of fields
    '''
    return np.unique(data_arr[fields_arr])

def _plot_feature_graphs(csv_data, output_dir=None):
    '''
    Plot several 2D graphs comparing standard features of the data
    '''

    num_graphs = 0

    # plot source/destination IPs
    unique_data = _get_unique_rows(csv_data, [COL_SOURCE_IP, COL_DEST_IP, COL_PROTOCOL])
    _draw_scatter_graph(unique_data[COL_SOURCE_IP], unique_data[COL_DEST_IP], unique_data[COL_PROTOCOL], 'Source IP', 'Destination IP', 'Source vs. Destination IP', output_dir, 'dest_source_ip_analysis.png')
    num_graphs += 1

    # plot source/destination ports
    unique_data = _get_unique_rows(csv_data, [COL_SOURCE_PORT, COL_DEST_PORT, COL_PROTOCOL])
    _draw_scatter_graph(unique_data[COL_SOURCE_PORT], unique_data[COL_DEST_PORT], unique_data[COL_PROTOCOL], 'Source Port', 'Destination Port', 'Source vs. Destination Port', output_dir, 'dest_source_port_analysis.png')
    num_graphs += 1

    # plot time to live/length
    unique_data = _get_unique_rows(csv_data, [COL_TTL, COL_LENGTH, COL_PROTOCOL])
    _draw_scatter_graph(unique_data[COL_TTL], unique_data[COL_LENGTH], unique_data[COL_PROTOCOL], 'Time to Live', 'Packet Length', 'TTL vs. Packet Length', output_dir, 'length_ttl_analysis.png')
    num_graphs += 1

    # plot length/fragment
    unique_data = _get_unique_rows(csv_data, [COL_LENGTH, COL_FRAGMENT, COL_PROTOCOL])
    _draw_scatter_graph(unique_data[COL_LENGTH], unique_data[COL_FRAGMENT], unique_data[COL_PROTOCOL], 'Packet Length', 'Fragment', 'Packet Length vs. Fragment', output_dir, 'fragment_length_analysis.png')
    num_graphs += 1

    # src port/flags
    unique_data = _get_unique_rows(csv_data, [COL_SOURCE_PORT, COL_FLAGS, COL_PROTOCOL])
    _draw_scatter_graph(unique_data[COL_SOURCE_PORT], unique_data[COL_FLAGS], unique_data[COL_PROTOCOL], 'Source Port', 'Flags', 'Source Port vs. TCP Flags', output_dir, 'tcpflags_source_port_analysis.png')
    num_graphs += 1

    return num_graphs

def plot_csv_features(csv_file, lower_bounds, output_dir=None, num_records=None, draw_feature_graphs=False):
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
        draw_feature_graphs (boolean): Whether to draw the feature graphs for the data (default: False)
    '''
    # read CSV file into Numpy multi-dimensional arrays
    step_start = timer()
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
                            missing_values='??',
                            filling_values=0,
                            invalid_raise=False,
                            max_rows=num_records)
    logger.debug("CSV to array (%d) (seconds): %f", len(csv_data), timer() - step_start)

    # plot feature graphs from data
    if draw_feature_graphs:
        step_start = timer()
        feature_graphs_dir = os.path.join(output_dir, "feature_graphs")
        os.makedirs(feature_graphs_dir, exist_ok=True)
        num_graphs = _plot_feature_graphs(csv_data, feature_graphs_dir)
        logger.debug("Feature Graphs plotted (%d) (seconds): %f", num_graphs, timer() - step_start)

    # build up sent/received details about all IPs
    ips = {}

    # iterate through collections of Source IP and record details for IP as a sender
    step_start = timer()
    sorted_src_data = np.sort(csv_data, order=[COL_SOURCE_IP, COL_TIME])
    src_ips = np.split(sorted_src_data, np.where(np.diff(sorted_src_data[COL_SOURCE_IP]))[0] + 1)
    logger.debug("Source IPs sorted and unique (%d) (seconds): %f", len(src_ips), timer() - step_start)

    # track number of destinations for each Source IP if in debug mode
    if logger.isEnabledFor(logging.DEBUG):
        dests = np.zeros([len(src_ips), 1])
        s = 0

    for src_data in src_ips:
        # determine current Destination IP and number of connection records
        src_ip = str(src_data[0][COL_SOURCE_IP])
        num_connections = len(src_data)

        # log received data stats for the IP
        ips[src_ip] = dict(received_bytes=0,
                            received_connections=0,
                            dst_details=list(),
                            sent_bytes=np.sum(src_data[COL_LENGTH]),
                            sent_connections=num_connections,
                            src_details=src_data)

        # debug output of the destination characteristics for all sources
        if logger.isEnabledFor(logging.DEBUG):
            dests[s] = len(src_data)
            s += 1

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Source Destinations - Num: %d, , Min: %d, Max: %d, Avg: %f", len(dests), min(dests), max(dests), sum(dests) / len(dests))
        dests = None


    # iterate through collections of Destination IP and record details for IP as a receiver
    step_start = timer()
    sorted_dst_data = np.sort(csv_data, order=[COL_DEST_IP, COL_TIME])
    dst_ips = np.split(sorted_dst_data, np.where(np.diff(sorted_dst_data[COL_DEST_IP]))[0] + 1)
    logger.debug("Destination IPs sorted and unique (%d) (seconds): %f", len(dst_ips), timer() - step_start)

    # track number of sources for each Destination IP if in debug mode
    if logger.isEnabledFor(logging.DEBUG):
        sources = np.zeros([len(dst_ips), 1])
        d = 0

    num_graphs = 0
    num_ips = 0

    # iterate through collections of Destination IP and record details for IP as a receiver and output analysis
    dst_analysis_dir = os.path.join(output_dir, "dst_analysis")
    for dst_data in dst_ips:
        # determine current Destination IP and number of connection records
        dst_ip = str(dst_data[0][COL_DEST_IP])
        num_connections = len(dst_data)
        total_bytes = np.sum(dst_data[COL_LENGTH])

        # log received data stats for the IP
        if not dst_ip in ips:
            ips[dst_ip] = dict(received_bytes=total_bytes,
                                received_connections=num_connections,
                                dst_details=dst_data,
                                sent_bytes=0,
                                sent_connections=0,
                                src_details=list())
        else:
            ip_rec = ips[dst_ip]
            ip_rec["received_bytes"] = total_bytes
            ip_rec["received_connections"] = num_connections
            ip_rec["src_details"] = list()
            ip_rec["dst_details"] = dst_data

        # debug output of the source characteristics for all destinations
        if logger.isEnabledFor(logging.DEBUG):
            sources[d] = len(dst_data)
            d += 1

        # output IP destination graphs (if there are enough incoming connections to make it seem like we'd care...)
        recv_conns = num_connections
        if len(dst_data) > 0 and recv_conns > lower_bounds:
            # create directory for Destination IP's graphs
            dst_str = _ipv4_int_to_dotted(int(dst_ip))
            dst_dir = os.path.join(dst_analysis_dir, dst_str)
            os.makedirs(dst_dir, exist_ok=True)

            # graph each Destination IP for:
            #    * (scatter) dst port vs. Source IP
            # subplots for:
            #    * (pie chart) total connections received/sent
            #    * (pie chart) total bytes received/sent
            # subplots for:
            #    * (scatter) dst port time series plot
            #    * (bar) #connections over time (5 minute intervals?)
            #    * (bar) bytes received over time (5 minute intervals?)

            # plot Destination Ports vs. Source IP (indicating protocols used)
            unique_data = _get_unique_rows(dst_data, [COL_DEST_PORT, COL_SOURCE_IP, COL_PROTOCOL])
            _draw_scatter_graph(unique_data[COL_DEST_PORT], unique_data[COL_SOURCE_IP], unique_data[COL_PROTOCOL], 'Destination Port', 'Source IP', _ipv4_int_to_dotted(dst_ip), dst_dir, 'ports_and_sources.png')
            num_graphs += 1

            # plot total Received vs. Sent connections
            dst_rec = ips[dst_ip]
            sent_conns = dst_rec['sent_connections']
            # sizes, labels, colours, title, explode=None, output_dir=None, output_file=None
            _draw_pie_chart([recv_conns, sent_conns], ['#Received', '#Sent'], ['r', 'g'], 'IP Connections', [0.1, 0], dst_dir, 'ip_connections.png')
            num_graphs += 1

            # plot total Received vs. Sent bytes
            recv_bytes = total_bytes
            sent_bytes = dst_rec['sent_bytes']
            _draw_pie_chart([recv_bytes, sent_bytes], ['Received', 'Sent'], ['r', 'g'], 'IP Data (Bytes)', [0.1, 0], dst_dir, 'ip_bytes.png')
            num_graphs += 1

            # time-series plot of single Destination IP (indicating Source IPs)
            # unlikely there will be many duplicates when time being considered
            _draw_scatter_graph(dst_data[COL_TIME], dst_data[COL_DEST_PORT], dst_data[COL_SOURCE_IP], 'Time / ms', 'Destination Port', _ipv4_int_to_dotted(dst_ip), dst_dir, 'ports_over_time.png')
            num_graphs += 1

            # plot received #connections over time (cumulative sum of connections along the time-sorted array)
            # get the times from the packet data
            t = np.array(dst_data[COL_TIME])
            # create a 2S array of 1s, the same length as the number of connections (times)
            a = np.ones([len(t), 2])
            # insert the connection times at index 0, then use the additional column of 1s for the cumsum operation
            a[:, 0] = t
            _draw_line_graph(a[:, 0], np.cumsum(a[:, 1]), 'Time/ms', '#Connections', 'Connections Received / Time', dst_dir, 'connections_over_time.png')
            num_graphs += 1

            # get the times from the packet data
            syn_connections = dst_data[np.where(dst_data[COL_FLAGS] & FLAG_SYN == FLAG_SYN)]
            if len(syn_connections) > 0:
                t = np.array(syn_connections[COL_TIME])
                # create a 2S array of 1s, the same length as the number of connections (times)
                a = np.ones([len(t), 2])
                # insert the connection times at index 0, then use the additional column of 1s for the cumsum operation
                a[:, 0] = t
                _draw_line_graph(a[:, 0], np.cumsum(a[:, 1]), 'Time/ms', '#Connections', 'SYN Connections Received / Time', dst_dir, 'syn_connections_over_time.png')
                num_graphs += 1

            # plot bytes received over time (cumulative sum of packet lengths along the time-sorted array)
            _draw_line_graph(dst_data[COL_TIME], np.cumsum(dst_data[COL_LENGTH]), 'Time / ms', 'Bytes Received', 'Bytes Received / Time', dst_dir, 'bytes_over_time.png')
            num_graphs += 1

        num_ips += 1

    logger.debug("IP analysis (%d), graphs (%d) (seconds): %f", num_ips, num_graphs, timer() - step_start)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Destination Sources - Num: %d, , Min: %d, Max: %d, Avg: %f", len(sources), min(sources), max(sources), sum(sources) / len(sources))
        sources = None

def main(argv):
    '''Parse input args and run the PCAP data CSV parser on specified inputfile (-i)

    Args:
        argv (list):    List of command line arguments

    '''
    inputfile = ''
    outputdir = None
    num_records = None
    lower_bounds = DEFAULT_LOWER_BOUNDS
    draw_feature_graphs = False

    try:
        opts, _ = getopt.getopt(argv, "hfi:o:n:l:")
    except getopt.GetoptError:
        _print_usage(1)

    for opt, arg in opts:
        if opt == '-h':
            _print_usage(0)
        elif opt == '-f':
            draw_feature_graphs = True
        elif opt == '-i':
            inputfile = arg
            if not os.path.isfile(inputfile):
                logger.error("Invalid input file (-i), file does not exist (%s)", inputfile)
                sys.exit(2)
        elif opt == '-o':
            outputdir = arg
            if not os.path.isdir(outputdir):
                logger.info("Output directory (-o) does not exist (%s), creating", outputdir)
                try:
                    os.makedirs(outputdir)
                except:
                    logger.exception("Could not create output directory (-o) (%s)", outputdir)
                    sys.exit(2)
        elif opt == '-n':
            try:
                num_records = int(arg)
                if num_records < 1:
                    logger.error("Number of records (-n) must be greater than 0, got (%d)", num_records)
                    sys.exit(3)
            except:
                logger.exception("Unable to parse number of records (-n), must be numeric, got (%s)", num_records)
                sys.exit(4)
        elif opt == '-l':
            try:
                lower_bounds = int(arg)
                if lower_bounds < 1:
                    logger.error("Lower bounds (-l) must be greater than 0, got (%d)", num_records)
                    sys.exit(5)
            except:
                logger.exception("Unable to parse lower bounds (-l), must be numeric, got (%s)", num_records)
                sys.exit(6)

    logger.info('Input file: %s', inputfile)
    logger.info('Draw feature graphs? %s', draw_feature_graphs)
    if not outputdir is None:
        logger.info('Output directory: %s', outputdir)
    if not num_records is None:
        logger.info('Record limit: %d', num_records)
    if not lower_bounds is None:
        logger.info('Lower bounds: %d', lower_bounds)

    start = timer()
    plot_csv_features(inputfile, lower_bounds, outputdir, num_records, draw_feature_graphs)

    end = timer()
    logger.info("Execution time (seconds): %f", end - start)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except:
        logger.exception('Problem executing program')
        raise
