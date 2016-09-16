Naimuri Cyber Test Range
========================

# Attacker

Docker container for attacked the Target within the Naimuri Cyber Test Range

## Components

### BoNeSi

[BoNeSi] [1] is a Bot Net Simulator utility for simulating the execution of large-scale Distributed Denial of Service (DDoS) attacks against target hosts (by DNS hostname or IP Address).

BoNeSi generates ICMP, UDP and TCP (HTTP) flooding attacks from a defined botnet size (different IP addresses).

BoNeSi is highly configurable - rates, data volume, source IP addresses, URLs and other parameters can be configured.

More information is available from the [BoNeSi] [1] website.

#### External Access

Logs of requests sent are stored in the shared /log volume.

Exposes /bonesi-master/config as an external volume (filesystem) that can be modified from the host machine to easily control BoNeSi config files.

## Execution

The Attacker node is designed to be run ad-hoc with command parameters for driving the BoNeSi compone to attack the Target node within the test range.

For example, to hit Target on port 4000 with UDP connections:

	docker-compose run attacker --protocol=udp target:4000

To hit Target on port 8888 with TCP (HTTP GET) connections (the entrypoint of the container is setup by default to use the provided example bots.txt, urllist.txt and browserlist.txt config):

	docker-compose run attacker --protocol=tcp target:8888

## References

[1]: https://github.com/Markus-Go/bonesi
