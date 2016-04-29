NCCDC
=====

# Overview

Part of the Naimuri - Machine Learning initiative.

Project to parse PCAP data and analyse using Machine Learning algorithms to categorise packets by IP Protocol type.

## Data

Based upon NCCDC "Capture the flag" competition data obtained from PREDICT (https://www.predict.org/Default.aspx?tabid=104) and PCH (https://www.pch.net//resources) for 2014 and 2015 events.

## Python Libraries

### Machine Learning

Machine Learning libraries being tested:
	<ul>
		<li>[TensorFlow] [1]</li>
		<li>[scikit-learn] [2] via [Anaconda] [3]</li>
	</ul>

	[1]: https://www.tensorflow.org/
	[2]: http://scikit-learn.org/
	[3]: https://www.continuum.io/downloads

### Other

Other python libraries being used in this project:
	<ul>
		<li>[scapy] [4] or [scapy3] [5] for python 3</li>
	</ul>

	[4]: http://www.secdev.org/projects/scapy/
	[5]: https://phaethon.github.io/scapy/api/installation.html

## Linux Utilities

Linux utilities (non-standard) being used in this project:
	<ul>
		<li>[GNU Parallel] [6]</li>
	</ul>

	[6]: http://www.gnu.org/s/parallel

# Usage

## Parse PCAP file

To parse IP (v4) packets from a PCAP file into a CSV representation (decimalised), run the pcap_to_csv.py script specifying the input PCAP file:

	$ python pcap_to_csv.py -i data/2015/dayone > data/2015/dayone.csv

See `pcap_to_csv.py -h` for more usage details.

### CSV Output

Packets not containing an IP (version = 4) layer are ignored.

Protocols processed for output:
<dl>
	<dt>1</dt><dd>ICMP</dd>
	<dt>6</dt><dd>TCP</dd>
	<dt>17</dt><dd>UDP</dd>
</dl>

Fields included in output:
<ul>
	<li>Protocol (IP)</li>
	<li>Time</li>
	<li>Source (IP Address)</li>
	<li>Destination (IP Address)</li>
	<li>Source Port</li>
	<li>Destination Port</li>
	<li>Time to Live (IP)</li>
	<li>Packet Length (IP)</li>
	<li>Fragment (IP)</li>
	<li>Flags (TCP)
		- Bit field indicating:
		<dl>
			<dt>1</dt><dd>FIN</dd>
			<dt>2</dt><dd>SYN</dd>
			<dt>4</dt><dd>RST</dd>
			<dt>8</dt><dd>PSH</dd>
			<dt>16</dt><dd>ACK</dd>
			<dt>32</dt><dd>URG</dd>
		</dl>
	</li>
</ul>

## Graph Packet features

Parse CSV packet file (in output format from PCAP parser) and produce graphs, run the csv_to_graph.py script specifying the input PCAP file:

	$ python csv_to_graph.py -i data/2015/dayone.csv -o analysis/2015/dayone -f

See `csv_to_graph.py -h` for more usage details.

### Feature Graphs

Optionally produce feature graphs over the entire dataset:

<ul>
	<li>By Packet Type:
		<ul>
			<li>Source IP vs. Destination IP</li>
			<li>Source Port vs. Destination Port</li>
			<li>Packet Length vs. Fragment</li>
			<li>Packet Length vs. Time to Live</li>
			<li>Source Port vs. TCP Flags</li>
		</ul>
	</li>
</ul>

### Destination Address Analysis Graphs

For each Destination IP, produce graphs:

<ul>
	<li>Destination Port vs. Source IP</li>
	<li>Connection summary:
		<ul>
			<li>#Connections received/sent</li>
            <li>#Bytes received/sent</li>
        </ul>
    </li>
	<li>Time-series plot:
		<ul>
        	<li>Destination Port connections</li>
            <li>#Connections (cumulative sum)
            	<ul>
            		<li>#SYN (no ACK) connections</li>
            		<li>#ACK (no SYN) connections</li>
            		<li>#SYN-ACK connections</li>
            	</ul>
            </li>
            <li>#Bytes received (cumulative sum)</li>
        </ul>
    </li>
</ul>

## Parallel Processing

Several scripts exist to help speed-up parsing and analysis of large datasets (consisting of multiple files) on multi-core systems:

<dl>
	<dt>parallel_convert_pcap_files.sh</dt><dd>Convert a directory of PCAP files in parallel, outputting one CSV file per input<br>
	Input args: DATA_DIR, CSV_DIR</dd>
	<dt>parallel_split_csv_files_by_dst_ip.sh</dt><dd>Identify unique list of Destination IPs in one or more CSV files and produce one CSV per Destination IP (i.e. "conversationalise" traffic to/from individual Destination IPs), using the IP address as filename<br>
	Input args: CSV_DIR, IP_CSV_DIR</dd>
	<dt>parallel_graph_csv_files.sh</dt><dd>Graph multiple IP conversation CSV files, filtering output by Destination IP identified by the filename<br>
	Input args: IP_CSV_DIR, GRAPH_DIR</dd>
</dl>