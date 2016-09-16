Naimuri Cyber Test Range
========================

# Pinger

Docker container to "ping" Target within the Naimuri Cyber Test Range to simulate "normal" TCP (HTTP) and UDP traffic

## Components

### Webserver (NodeJS)

Simple NodeJS/npm webserver that repeatedly "pings" the Target host in the test range with TCP and UDP traffic.

### External Access

Logs of requests sent are stored in the shared /log volume for later analysis.

Exposes /opt/node as an external volume (filesystem) that can be modified from the host machine to allow easy modification of the NodeJS code.

Exposes port 8866 for external connection by webrowse from outside the Docker container to view a simple log of Pinger activity (port used by host machine may vary; URL: /).

## Execution

Pinger is set to start and run with the overall test range network (i.e. as part of the "docker-compose up -d" command)

Pinger is designed to be easily scalable using the Docker tools to allow generation of more "normal" traffic from more than one source all pointing at the Target:

	docker-compose scale pinger=3
