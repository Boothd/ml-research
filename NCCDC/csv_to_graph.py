# -*- coding: utf-8 -*-
'''Parse CSV data from a file and plot features in a graph

This script parses PCAP data from a specified CSV file (pre-processed using pcap_to_csv.py),
plotting features against known packet type.

Example:
    $ python __file__ -i csv_file_data -d

Author: chris.sampson@naimuri.com
'''
import sys, getopt, os.path

import matplotlib.pyplot as plt
import numpy as np

def _print_usage(exit_code=0):
    '''Print usage and exit

    Args:
        exit_code (int):    The exit code to use when terminating the script

    '''
    f = sys.stderr if exit_code > 0 else sys.stdout

    print(__file__ + " -i <input file> [-d]", file=f)
    print("-i <input file>: CSV format data file to be parsed")
    print("-d: debug output")

    sys.exit(exit_code)

def plot_csv_features(csv_file, debug=False):
    '''Parse PCAP data CSV file content and plot graphs of features vs. known packet type

    Fields expected in input:
        row#
        time
        source (IP Address)
        destination (IP Address)
        source port
        destination port
        time to live (IP)
        length (IP)
        fragment (IP)
        protocol (IP)

    Args:
        csv_file (str):    Filename of PCAP file data to be read
        debug (bool):      Whether to output debug information while parsing packets
    '''
    # read CSV file into Numpy multi-dimensional arrays
    csv_data = np.genfromtxt(csv_file, delimiter=',', dtype=None)

    # get arrays of features for plotting
    X_source_dest_ports = csv_data[:, [4, 5]]
    x_sdp_min, x_sdp_max = X_source_dest_ports[:, 0].min() - 1000, X_source_dest_ports[:, 0].max() + 1000
    y_sdp_min, y_sdp_max = X_source_dest_ports[:, 1].min() - 1000, X_source_dest_ports[:, 1].max() + 1000

    X_ttl_length = csv_data[:, [5, 6]]
    x_ttll_min, x_ttll_max = X_ttl_length[:, 0].min() - 1000, X_ttl_length[:, 0].max() + 1000
    y_ttll_min, y_ttll_max = X_ttl_length[:, 1].min() - 10, X_ttl_length[:, 1].max() + 10

    X_length_frag = csv_data[:, [6, 7]]
    x_lf_min, x_lf_max = X_length_frag[:, 0].min() - 10, X_length_frag[:, 0].max() + 10
    y_lf_min, y_lf_max = X_length_frag[:, 1].min() - 1000, X_length_frag[:, 1].max() + 1000

    # TODO: plot 3-dimensions
#     X_ttl_length_frag = csv_data[:, 5:7]
#     x_ttllf_min, x_ttllf_max = X_ttl_length_frag[:, 0].min() - AXIS_LIMIT_BORDER, X_ttl_length_frag[:, 0].max() + AXIS_LIMIT_BORDER
#     y_ttllf_min, y_ttllf_max = X_ttl_length_frag[:, 1].min() - AXIS_LIMIT_BORDER, X_ttl_length_frag[:, 1].max() + AXIS_LIMIT_BORDER

    # get known protocol values
    Y = csv_data[:, 9:]

    # plot source/destination ports
    plt.figure(figsize=(8, 6))
    plt.clf()

    plt.scatter(X_source_dest_ports[:, 0], X_source_dest_ports[:, 1], c=Y, cmap=plt.cm.get_cmap("Paired"))
    plt.xlabel('Source Port')
    plt.ylabel('Dest Port')

    plt.xlim(x_sdp_min, x_sdp_max)
    plt.ylim(y_sdp_min, y_sdp_max)
    plt.xticks(())
    plt.yticks(())

    # plot time to live/length
    plt.figure(figsize=(8, 6))
    plt.clf()

    plt.scatter(X_ttl_length[:, 0], X_ttl_length[:, 1], c=Y, cmap=plt.cm.get_cmap("Paired"))
    plt.xlabel('Time To Live')
    plt.ylabel('Length')

    plt.xlim(x_ttll_min, x_ttll_max)
    plt.ylim(y_ttll_min, y_ttll_max)
    plt.xticks(())
    plt.yticks(())

    # plot length/fragment
    plt.figure(figsize=(8, 6))
    plt.clf()

    plt.scatter(X_length_frag[:, 0], X_length_frag[:, 1], c=Y, cmap=plt.cm.get_cmap("Paired"))
    plt.xlabel('Length')
    plt.ylabel('Fragment')

    plt.xlim(x_lf_min, x_lf_max)
    plt.ylim(y_lf_min, y_lf_max)
    plt.xticks(())
    plt.yticks(())

    # display the graphs
    plt.show()


def main(argv):
    '''Parse input args and run the PCAP parser on specified inputfile (-i)

    Args:
        argv (list):    List of command line arguments

    '''
    inputfile = ''
    debug = False

    try:
        opts, _ = getopt.getopt(argv, "hdi:")
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
        elif opt == '-d':
            debug = True

    if debug:
        print('Input file is: ' + inputfile, file=sys.stderr)

    plot_csv_features(inputfile, debug)



if __name__ == "__main__":
    main(sys.argv[1:])
