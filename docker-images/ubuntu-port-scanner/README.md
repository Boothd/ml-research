Naimuri Cyber Test Range
========================

# Scanner

Docker container to port scan the Target on the Naimuri Cyber Test Range

## Components

### Port Scanner (nmap)

Allows port scanning of the Target node using the nmap utility (using TCP, UDP or ICMP connections).

### Scripts

#### port_scanner.py

A script has been written to allow some control over the namp utility and randomise the ports being scanned in an easy manner:

	python3 /usr/local/sbin/port_scanner.py

### External Access

Use of the shared /log volume to output nmap logs for later analysis.

## Execution

Scanner is intended to be executed in an ad-hoc manner within the test range to port scan the Target host (randomising the ports scanned and allowing time between scan runs).

For example, to scan ports 3999 to 4000 (in a randomised order) on the Target node using UDP:

	docker-compose run scanner --min-port=3999 --max-port=4001 -r --nmap-opts="-sU" -t target
