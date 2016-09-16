Naimuri Cyber Test Range
========================

# Overview

The Naimuri Cyber Test Range is setup as a Docker network. The components within the network are:

<dl>
	<dt>Commander</dt><dd>Control test runs within the network</dd>
	<dt>Target</dt><dd>Accept and monitor incoming netwrok (attack) traffic</dd>
	<dt>Pinger</dt><dd>Generate "normal" TCP (HTTP)/UDP traffic for the Target. Can be scaled to multiple container instances</dd>
	<dt>Attacker</dt><dd>Simulate attack methods against the Target using BoNeSi</dd>
	<dt>Scanner</dt><dd>Port scan the Target using nmap</dd>
	<dt>Analyser</dt><dd>Analyse logs and network traffic data using Machine Learning algorithms</dd>
</dl>

# Install

Install [Docker] [1] and [docker-compose] [2].

## Controller UIs

### Linux

Installer docker-compose-ui (for ease of monitoring and managing network; run from this directory):
	docker run --name docker-compose-ui -d -p 5000:5000 -v /var/run/docker.sock:/var/run/docker.sock -v `pwd`:/opt/docker-compose-projects:ro --net testnetwork_default francescou/docker-compose-ui:0.19.0

### Windows/MAC

Install and setup [Kitematic] [3]

# Setup & Control

## Build Services

Run docker-compose from this directory to create "testnetwork" project services (images):

	docker-compose build

## Run Containers

Run docker-compose from this directory to create "testnetwork" containers and run in the background:

	docker-compose up -d

## Stop Containers (don't remove)

Run docker-compose from this directory to stop "testnetwork" containers:

	docker-compose stop

## Stop and remove Containers

Run docker-compose from this directory to stop and remove "testnetwork" containers and network (but not images):

	docker-compose down

### Note

This <b>does not</b> remove the network's images (see "docker images") or external shared volumes (see "docker volume ls").

## Remove Images

There is no simple docker built-in command to remove all images, but this can be achieved in Linux using a simple script to remove all "testnetwork" related images:

	docker rmi $(docker images -q | grep -F "testnetwork_")

## Remove Volumes

There is no simple docker built-in command to remove all images, but this can be achieved in Linux using a simple script to remove all "testnetwork" related images:

	docker volume rm $(docker volume ls -q | grep -F "testnetwork_")

### Warning

Removing the log, data and analysis volumes will result in loss of all the generated data, so be sure to have copied these files elsewhere before running the above command, or use the following alternative:

	docker volume rm $(docker volume ls -q | grep -F "testnetwork_" | grep -vF "log" | grep -vF "data" | grep -vF "analysis")

# Examine

## Network

Find the Docker network and its details, including container IP Addresses and mapped ports:
	docker network ls
	
	docker network inspect testnetwork_default

## Volumes

Find your docker volumes containing config/log/code files, including path to volume contents on host machine:

	docker volume ls

	docker volume inspect testnetwork_log
	docker volume inspect testnetwork_data
	docker volume inspect testnetwork_analysis

	docker volume inspect testnetwork_target-node
	docker volume inspect testnetwork_pinger-node

	docker volume inspect testnetwork_analyser-config
	docker volume inspect testnetwork_attacker-config
	docker volume inspect testnetwork_scanner-config

### Note

For Windows/Mac running Docker in a VM (even Hyper-V in Windows 10 Professional), the external volume will likely be within the VM so may not be directly accessible from the host operating system.

# Test Runs

## Setup Test Run

Restart the network using docker-compose from this directory:

	docker-compose restart

This will cause the commander to prepare the shared volumes for new log files to be collected and all other containers to make use of the new "current" log directory.

## Execute Port Scan

Launch an nmap port scan at the Target, e.g. for UDP against port 4000:

	docker-compose run scanner --min-port=3999 --max-port=4001 -r --nmap-opts="-sU" -t target

## Execute Attack

Launch a BoNeSi attack at the Target, e.g. using UDP against port 4000:

	docker-compose run attacker --protocol=udp target:4000

## Analyse Logs

Launch an analyser container:

	docker-compose run analyser
or
	docker attach analyser

## View real-time logs

URLs for monitoring container activity:

	docker-compose-ui:	http://localhost:5000/
	target activity:	http://localhost:8888/attackcount
	pinger activity:	http://localhost:8866/

### Note for Pinger

Pinger containers expose port 8866 but no specific port is mapped by the host to allow for the Pinger service to be scaled. The ports will have to be determined by examining the network (see above)

# References

[1]: https://www.docker.com/products/overview
[2]: https://docs.docker.com/compose/install/
[3]: https://kitematic.com/
