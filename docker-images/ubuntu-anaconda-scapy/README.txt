Issue the following commands to get this image up and running

docker build -t anaconda-scapy .
docker run --name conda-scapy --rm -it -v log:/log -v analyser-config:/config anaconda-scapy /bin/bash

# run anaconda-scapy container on test-network (setup using docker-compose) and sharing the log and config volumes
docker run --name conda-scapy --rm -it --network=testnetwork_default --link=target -v testnetwork_log:/usr/local/sbin/log -v testnetwork_analyser-config:/usr/local/sbin/config anaconda-scapy /bin/bash
