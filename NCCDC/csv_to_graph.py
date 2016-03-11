# -*- coding: utf-8 -*-
'''Parse CSV data from a file and plot features in a graph

This script parses PCAP data from a specified CSV file (pre-processed using pcap_to_csv.py),
plotting features against known packet type.

Example:
    $ python __file__ -i csv_file_data -n 1000000 -d

Author: chris.sampson@naimuri.com
'''
import sys, getopt, os.path

import matplotlib.pyplot as plt
import numpy as np

# FLAG_FIN = 1
FLAG_SYN = 2
# FLAG_RST = 4
# FLAG_PSH = 8
FLAG_ACK = 16
# FLAG_URG = 32

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

def _print_usage(exit_code=0):
    '''Print usage and exit

    Args:
        exit_code (int):    The exit code to use when terminating the script

    '''
    f = sys.stderr if exit_code > 0 else sys.stdout

    print(__file__ + " -i <input file> [-o <output dir>] [-n <num records>] [-d]", file=f)
    print("-i <input file>: CSV format data file to be parsed")
    print("-n <num records>: Number of CSV rows to read as records for input")
    print("-i <output dir>: Directory for output of graph images (if unspecified, images will be shown but not saved)")
    print("-d: debug output")

    sys.exit(exit_code)

def _draw_graph(x_points, y_points, point_labels, x_title, y_title, output_dir=None, output_file=None, cmap_name='Paired'):
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

    # plt.xticks(())
    # plt.yticks(())

    if output_dir is None or output_file is None:
        # display the graph
        plt.show()
    else:
        # save image to output dir
        plt.savefig(os.path.join(output_dir, output_file))

def plot_feature_graphs(csv_data, output_dir=None):
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

def construct_destination_records(csv_data):
    dst_data = {}
    for rec in csv_data:
        src_ip = str(rec[IND_SOURCE_IP])
        src_port = str(rec[IND_SOURCE_PORT])
        dst_ip = str(rec[IND_DEST_IP])
        dst_port = str(rec[IND_DEST_PORT])
        t = rec[IND_TIME]
        data_len = rec[IND_LENGTH]
        proto = rec[IND_PROTOCOL]
        flags = rec[IND_FLAGS]

        # Destination IP
        if not dst_ip in dst_data:
            dst_data[dst_ip] = dict(total_bytes=0, num_connections=0)
        dst_ip_rec = dst_data[dst_ip]

        # summarise received data on Destination IP
        dst_ip_rec['total_bytes'] += data_len
        dst_ip_rec['num_connections'] += 1

        # Destination Port
        if not dst_port in dst_ip_rec:
            dst_ip_rec[dst_port] = dict(total_bytes=0, num_connections=0)
        dst_port_rec = dst_ip_rec[dst_port]

        # summarise received data on Destination Port
        dst_port_rec['total_bytes'] += data_len
        dst_port_rec['num_connections'] += 1

        # Connected Source IP
        if not src_ip in dst_port_rec:
            dst_port_rec[src_ip] = dict(total_bytes=0, num_connections=0)
        src_ip_rec = dst_port_rec[src_ip]

        # summarise received data from source IP
        src_ip_rec['total_bytes'] += data_len
        src_ip_rec['num_connections'] += 1

        # Connected Source Port
        if not src_port in src_ip_rec:
            src_ip_rec[src_port] = dict(total_bytes=0, num_connections=0, earliest=-1, latest=-1, connections=list())
        src_port_rec = src_ip_rec[src_port]

        # add connection details
        src_port_rec['total_bytes'] += data_len
        src_port_rec['num_connections'] += 1

        earliest = src_port_rec['earliest']
        if earliest == -1 or t < earliest:
            src_port_rec['earliest'] = t

        latest = src_port_rec['latest']
        if latest == -1 or t > latest:
            src_port_rec['latest'] = t

        src_port_rec['connections'].append(
                                           dict(
                                                conn_time=t,
                                                packet_length=data_len,
                                                protocol=proto,
                                                ack=flags & FLAG_ACK != 0,
                                                syn=flags & FLAG_SYN != 0
                                            )
                                        )

    return dst_data

def plot_csv_features(csv_file, output_dir=None, num_records=None, debug=False):
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
        output_dir (str):  Directory for saving graph images (if None, images will be displayed but not saved)
        num_records (int): Maximum number of records to read from input CSV (default: None - all lines)
        debug (bool):      Whether to output debug information while parsing packets (default: False)
    '''
    # read CSV file into Numpy multi-dimensional arrays
    csv_data = np.genfromtxt(csv_file, delimiter=',', dtype=None, max_rows=num_records)

    # plot feature graphs from data
#    plot_feature_graphs(csv_data, output_dir)

    # parse data into structure for further analysis
    dst_data = construct_destination_records(csv_data)

    from pprint import pprint
    pprint(dst_data)

def main(argv):
    '''Parse input args and run the PCAP parser on specified inputfile (-i)

    Args:
        argv (list):    List of command line arguments

    '''
    inputfile = ''
    outputdir = None
    num_records = None
    debug = False

    try:
        opts, _ = getopt.getopt(argv, "hdi:o:n:")
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

    if debug:
        print('Input file is: ' + inputfile, file=sys.stderr)
        if not outputdir is None:
            print('Output directory is: ' + outputdir, file=sys.stderr)
        if not num_records is None:
            print('Number of records is: ' + num_records, file=sys.stderr)

    plot_csv_features(inputfile, outputdir, num_records, debug)



if __name__ == "__main__":
    main(sys.argv[1:])
