Naimuri Cyber Test Range
========================

# Analyser

Docker container to analyse logs and data within the Naimuri Cyber Test Range

## Components

### Python 3

Python development and execution environment for writing and running scripts to operate with test range data/logs.

### Anaconda 4 with scikit-learn

[scikit-learn] [1] via [Anaconda] [2] to provide Machine Learning capabilities in a friendly Python environment with many scientific/mathematical libraries included.

### Scapy 3

[scapy3] [3] for Python 3 to parse and manipulate PCAP (Network Packet Capture) files produced by the test range in order to feed into the Machine Learning libraries.

### GNU Parallel

[GNU Parallel] [4] to enable parallelisation of PCAP file processing within the container.

### Scripts

#### Convert PCAP files to CSV

To parse IP (v4) packets from a PCAP file into a CSV representation (decimalised), run the pcap_to_csv.py script specifying the input PCAP file:

	$ python3 /usr/local/sbin/pcap_to_csv.py -i /usr/local/sbin/log/current/*.pcap.* > /usr/local/sbin/data/*.csv

See `pcap_to_csv.py -h` for more usage details.

Parallel conversion of PCAP files is possible using /usr/local/sbin/scripts/parallel_convert_pcap_files.sh

##### CSV Output

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

#### Graph Packet features from CSV files

Parse CSV packet file (in output format from PCAP parser) and produce graphs, run the csv_to_graph.py script specifying the input PCAP file:

	$ python3 /usr/local/sbin/csv_to_graph.py -i /usr/local/sbin/data/*.csv -o /usr/local/sbin/analysis/* -f

See `csv_to_graph.py -h` for more usage details.

Parallel graphing of CSV files is possible using /usr/local/sbin/scripts/parallel_graph_csv_files.sh

It can be advantageous to sort and split the CSV (PCAP) records between files by Destination IP prior to graphing the features. This can be achieved using /usr/local/sbin/scripts/sort_and_split_csv_files_by_dst_ip.sh

##### Feature Graphs

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

##### Destination Address Analysis Graphs

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
            <li>#Connection flags (cumulative sum)
            	<ul>
            		<li>#SYN (no ACK) connections</li>
            		<li>#ACK (no SYN or RST) connections</li>
            		<li>#SYN-ACK connections</li>
					<li>#RST (no ACK) connections</li>
					<li>#RST-ACK connections</li>
            	</ul>
            </li>
			<li>#Connection types (cumulative sum)
            	<ul>
            		<li>#TCP connections</li>
            		<li>#ICMP connections</li>
            		<li>#UDP connections</li>
            	</ul>
            </li>
            <li>#Bytes received (cumulative sum)</li>
        </ul>
    </li>
	<li>Source summary:
		<ul>
			<li>#Connections (from Source IP)</li>
            <li>#Bytes (from Source IP)</li>
        </ul>
    </li>
</ul>

### External Access

Use of the shared /log volume allows Analyser to read and manipulate logs from other test range containers.

Config for the Python scripts (logging.yaml) is available for adjustment from the host machine.

Data and Analysis volumes exist for script output to allow easy access from the host machine.

## Execution

Analyser is designed to be started along with the test range (docker-compose up -d), then used in an ad-hoc fashion with an interactive command line to allow execution of scripts and parsing/manipulation of data:

	docker-compose run analyser
or
	docker attach analyser
	

## References

[1]: http://scikit-learn.org/
[2]: https://www.continuum.io/downloads
[3]: https://phaethon.github.io/scapy/api/installation.html
[4]: http://www.gnu.org/s/parallel
