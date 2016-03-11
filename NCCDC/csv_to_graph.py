# -*- coding: utf-8 -*-
'''Parse CSV data from a file and plot features in a graph

This script parses PCAP data from a specified CSV file (pre-processed using pcap_to_csv.py),
plotting features against known packet type.

Example:
    $ python __file__ -i csv_file_data -o /tmp -n 1000000 -d

Author: chris.sampson@naimuri.com
'''
import sys, getopt, os.path, struct, socket

import matplotlib.pyplot as plt
import numpy as np

'''int:    Bits representing TCP Flags'''
# FLAG_FIN = 1
FLAG_SYN = 2
# FLAG_RST = 4
# FLAG_PSH = 8
FLAG_ACK = 16
# FLAG_URG = 32

'''int:    Indices used to locate data in parsed CSV data arrays'''
# IND_ROW_NUM = 0
IND_PROTOCOL = 1
IND_TIME = 2
IND_SOURCE_IP = 3
IND_DEST_IP = 4
IND_SOURCE_PORT = 5
IND_DEST_PORT = 6
IND_TTL = 7
IND_LENGTH = 8
IND_FRAGMENT = 9
IND_FLAGS = 10

'''int:    Default lower bounds limit'''
DEFAULT_LOWER_BOUNDS = 200

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
    print("-d: debug output")

    sys.exit(exit_code)

def _draw_graph(x_points, y_points, point_labels, x_title, y_title, output_dir=None, output_file=None, cmap_name='Paired'):
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
    # get known protocol values
    protocols = csv_data[:, IND_PROTOCOL]

    # plot source/destination IPs
    _draw_graph(csv_data[:, IND_SOURCE_IP], csv_data[:, IND_DEST_IP], protocols, 'Source IP', 'Destination IP', output_dir, 'dest_source_ip_analysis.png')

    # plot source/destination ports
    _draw_graph(csv_data[:, IND_SOURCE_PORT], csv_data[:, IND_DEST_PORT], protocols, 'Source Port', 'Destination Port', output_dir, 'dest_source_port_analysis.png')

    # plot time to live/length
    _draw_graph(csv_data[:, IND_TTL], csv_data[:, IND_LENGTH], protocols, 'Time to Live', 'Packet Length', output_dir, 'length_ttl_analysis.png')

    # plot length/fragment
    _draw_graph(csv_data[:, IND_LENGTH], csv_data[:, IND_FRAGMENT], protocols, 'Packet Length', 'Fragment', output_dir, 'fragment_length_analysis.png')

    # src port/flags
    _draw_graph(csv_data[:, IND_SOURCE_PORT], csv_data[:, IND_FLAGS], protocols, 'Source Port', 'Flags', output_dir, 'tcpflags_source_port_analysis.png')

def _construct_destination_records(csv_data):
    '''
    Construct a collection of details about Destination IPs in for format:
        dst_ip {
            total_bytes (received by dst_ip), num_connections (incoming to dst_ip), port_sources ([dst_port, src_ip, src_port, protocol]),
            dst_port {
                total_bytes (received by dst_ip/dst_port), num_connections (incoming to dst_ip/dst_port),
                src_ip {
                    total_bytes (from src_ip), num_connections (from src_ip),
                    src_port {
                        total_bytes (from src_ip/src_port), num_connections (from src_ip/src_port),
                        earliest (connection time from src_ip/src_port), latest (connection time from src_ip/src_port),
                        connections (
                            {
                                conn_time, packet_length, protocol, ack, syn
                            }
                        )
                    }
                }
            }
        }

    '''
    dst_data = {}
    for rec in csv_data:
        src_ip = str(rec[IND_SOURCE_IP])
        src_port = str(rec[IND_SOURCE_PORT])
        dst_ip = str(rec[IND_DEST_IP])
        dst_port = str(rec[IND_DEST_PORT])
#        t = rec[IND_TIME]
        data_len = rec[IND_LENGTH]
        proto = rec[IND_PROTOCOL]
#        flags = rec[IND_FLAGS]

        # Destination IP
        if not dst_ip in dst_data:
            dst_data[dst_ip] = dict(total_bytes=0, num_connections=0, port_sources=list())
        dst_ip_rec = dst_data[dst_ip]

        # summarise received data on Destination IP
        dst_ip_rec['total_bytes'] += data_len
        dst_ip_rec['num_connections'] += 1
        dst_ip_rec['port_sources'].append([dst_port, src_ip, src_port, proto])

#         # Destination Port
#         if not dst_port in dst_ip_rec:
#             dst_ip_rec[dst_port] = dict(total_bytes=0, num_connections=0)
#         dst_port_rec = dst_ip_rec[dst_port]
#
#         # summarise received data on Destination Port
#         dst_port_rec['total_bytes'] += data_len
#         dst_port_rec['num_connections'] += 1
#
#         # Connected Source IP
#         if not src_ip in dst_port_rec:
#             dst_port_rec[src_ip] = dict(total_bytes=0, num_connections=0)
#         src_ip_rec = dst_port_rec[src_ip]
#
#         # summarise received data from source IP
#         src_ip_rec['total_bytes'] += data_len
#         src_ip_rec['num_connections'] += 1
#
#         # Connected Source Port
#         if not src_port in src_ip_rec:
#             src_ip_rec[src_port] = dict(total_bytes=0, num_connections=0, earliest=-1, latest=-1, connections=list())
#         src_port_rec = src_ip_rec[src_port]
#
#         # add connection details
#         src_port_rec['total_bytes'] += data_len
#         src_port_rec['num_connections'] += 1
#
#         earliest = src_port_rec['earliest']
#         if earliest == -1 or t < earliest:
#             src_port_rec['earliest'] = t
#
#         latest = src_port_rec['latest']
#         if latest == -1 or t > latest:
#             src_port_rec['latest'] = t
#
#         src_port_rec['connections'].append(
#                                            dict(
#                                                 conn_time=t,
#                                                 packet_length=data_len,
#                                                 protocol=proto,
#                                                 ack=flags & FLAG_ACK != 0,
#                                                 syn=flags & FLAG_SYN != 0
#                                             )
#                                         )

    return dst_data

def _construct_source_records(csv_data):
    '''
    Construct a collection of details about Source IPs in for format:
        src_ip {
            total_bytes (sent from src_ip), num_connections (sent from src_ip), port_destinations ([src_port, dst_ip, dst_port, protocol]),
            src_port {
                total_bytes (sent from src_ip/src_port), num_connections (sent from src_ip/src_port),
                dst_ip {
                    total_bytes (to dst_ip), num_connections (to dst_ip),
                    dst_port {
                        total_bytes (to dst_ip/dst_port), num_connections (to dst_ip/dst_port),
                        earliest (connection time to dst_ip/dst_port), latest (connection time to dst_ip/dst_port),
                        connections (
                            {
                                conn_time, packet_length, protocol, ack, syn
                            }
                        )
                    }
                }
            }
        }

    '''
    src_data = {}
    for rec in csv_data:
        src_ip = str(rec[IND_SOURCE_IP])
        src_port = str(rec[IND_SOURCE_PORT])
        dst_ip = str(rec[IND_DEST_IP])
        dst_port = str(rec[IND_DEST_PORT])
#        t = rec[IND_TIME]
        data_len = rec[IND_LENGTH]
        proto = rec[IND_PROTOCOL]
#        flags = rec[IND_FLAGS]

        # Source IP
        if not src_ip in src_data:
            src_data[src_ip] = dict(total_bytes=0, num_connections=0, port_destinations=list())
        src_ip_rec = src_data[src_ip]

        # summarise sent data from Source IP
        src_ip_rec['total_bytes'] += data_len
        src_ip_rec['num_connections'] += 1
        src_ip_rec['port_destinations'].append([src_port, dst_ip, dst_port, proto])

#         # Source Port
#         if not src_port in src_ip_rec:
#             src_ip_rec[src_port] = dict(total_bytes=0, num_connections=0)
#         src_port_rec = src_ip_rec[src_port]
#
#         # summarise sent data from Source Port
#         src_port_rec['total_bytes'] += data_len
#         src_port_rec['num_connections'] += 1
#
#         # Connected Destination IP
#         if not dst_ip in src_port_rec:
#             src_port_rec[dst_ip] = dict(total_bytes=0, num_connections=0)
#         dst_ip_rec = srd_port_rec[dst_ip]
#
#         # summarise received data to Destination IP
#         dst_ip_rec['total_bytes'] += data_len
#         dst_ip_rec['num_connections'] += 1
#
#         # Connected Destination Port
#         if not dst_port in dst_ip_rec:
#             dst_ip_rec[dst_port] = dict(total_bytes=0, num_connections=0, earliest=-1, latest=-1, connections=list())
#         dst_port_rec = dst_ip_rec[dst_port]
#
#         # add connection details
#         dst_port_rec['total_bytes'] += data_len
#         dst_port_rec['num_connections'] += 1
#
#         earliest = dst_port_rec['earliest']
#         if earliest == -1 or t < earliest:
#             dst_port_rec['earliest'] = t
#
#         latest = dst_port_rec['latest']
#         if latest == -1 or t > latest:
#             dst_port_rec['latest'] = t
#
#         dst_port_rec['connections'].append(
#                                            dict(
#                                                 conn_time=t,
#                                                 packet_length=data_len,
#                                                 protocol=proto,
#                                                 ack=flags & FLAG_ACK != 0,
#                                                 syn=flags & FLAG_SYN != 0
#                                             )
#                                         )

    return src_data

def plot_csv_features(csv_file, lower_bounds, output_dir=None, num_records=None, debug=False):
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
        debug (bool):      Whether to output debug information while parsing packets (default: False)
    '''
    # read CSV file into Numpy multi-dimensional arrays
    csv_data = np.genfromtxt(csv_file, delimiter=',', dtype=None, max_rows=num_records)

    # plot feature graphs from data
    _plot_feature_graphs(csv_data, output_dir)

    # parse data into structures for further analysis
    dst_data = _construct_destination_records(csv_data)
    src_data = _construct_source_records(csv_data)

    # create list of IPs (source & dest) with:
    # [received bytes, incoming connections, sent bytes, outgoing connections]
    ips = dict()

    # iterate through Destination IPs, record details of IP connections and plot information about connected sources
    sources = list()
    for dst in dst_data:
        dst_port_srcs = dst_data[dst]['port_sources']

        # add destination to IP list
        if not dst in ips:
            ips[dst] = [dst_data[dst]['total_bytes'], dst_data[dst]['num_connections'], 0, 0]

        # plot the graph if there is a reasonable amount of data to put in the graph (reduce output)
        if len(dst_port_srcs) >= lower_bounds:
            # plot destination port vs. source ip, indicating protocols used
            arr = np.asarray(dst_port_srcs)
            _draw_graph(arr[:, 0], arr[:, 1], arr[:, 3], 'Destination Port', 'Source IP', output_dir, socket.inet_ntoa(struct.pack("!L", int(dst))) + '_destination_ports_and_source_ips.png')

        # debug output of the source characteristics for all destinations
        if debug:
            sources.append(len(dst_port_srcs))
    if debug:
        print("Num: " + str(len(sources)) + ", Min: " + str(min(sources)) + ", Max: " + str(max(sources)) + ", Avg: " + str(sum(sources) / len(sources)), file=sys.stderr)
        sources = None

    # iterate through Source IPs, record details of IP connections
    for src in src_data:
        if not src in ips:
            ips[src] = [0, 0, src_data[src]['total_bytes'], src_data[src]['num_connections']]
        else:
            ips[src][2] = src_data[src]['total_bytes']
            ips[src][3] = src_data[src]['num_connections']

    # TODO: "bowtie" plot each IP's incoming/outgoing data/connections *** pie charts??
#     from pprint import pprint
#     pprint(ips)

def main(argv):
    '''Parse input args and run the PCAP data CSV parser on specified inputfile (-i)

    Args:
        argv (list):    List of command line arguments

    '''
    inputfile = ''
    outputdir = None
    num_records = None
    lower_bounds = DEFAULT_LOWER_BOUNDS
    debug = False

    try:
        opts, _ = getopt.getopt(argv, "hdi:o:n:l:")
    except getopt.GetoptError:
        _print_usage(1)

    for opt, arg in opts:
        if opt == '-h':
            _print_usage(0)
        elif opt == '-i':
            inputfile = arg
            if not os.path.isfile(inputfile):
                print("Invalid inputfile (-i), file does not exist", file=sys.stderr)
                sys.exit(2)
        elif opt == '-o':
            outputdir = arg
            if not os.path.isdir(outputdir):
                print("Invalid outputdir (-o), directory does not exist", file=sys.stderr)
                sys.exit(2)
        elif opt == '-d':
            debug = True
        elif opt == '-n':
            try:
                num_records = int(arg)
                if num_records < 1:
                    print("Number of records (-n) must be greater than 0", file=sys.stderr)
                    sys.exit(3)
            except Exception:
                print("Unable to parse number of records (-n), must be numeric", file=sys.stderr)
                sys.exit(4)
        elif opt == '-l':
            try:
                lower_bounds = int(arg)
                if lower_bounds < 1:
                    print("Lower bounds (-l) must be greater than 0", file=sys.stderr)
                    sys.exit(5)
            except Exception:
                print("Unable to parse lower bounds (-l), must be numeric", file=sys.stderr)
                sys.exit(6)

    if debug:
        print('Input file is: ' + inputfile, file=sys.stderr)
        if not outputdir is None:
            print('Output directory is: ' + outputdir, file=sys.stderr)
        if not num_records is None:
            print('Number of records is: ' + str(num_records), file=sys.stderr)
        if not lower_bounds is None:
            print('Lower bounds is: ' + str(lower_bounds), file=sys.stderr)

    plot_csv_features(inputfile, lower_bounds, outputdir, num_records, debug)



if __name__ == "__main__":
    main(sys.argv[1:])
