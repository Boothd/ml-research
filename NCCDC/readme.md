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
		<li>[scapy] [4] (or [scapy3] [5] for python 3)</li>
	</ul>

	[4]: http://www.secdev.org/projects/scapy/
	[5]: https://phaethon.github.io/scapy/api/installation.html

# Usage

## Parse PCAP file

To parse IP (v4) packets from a PCAP file into a CSV representation (decimalised), run the pcap_to_csv.py script specifying the input PCAP file:

	$ python pcap_to_csv.py -i data/2015/dayone > data/2015/dayone.csv

See `pcap_to_csv.py -h` for more usage details.