Naimuri Cyber Test Range
========================

# Target

Docker container that is the Target within the Naimuri Cyber Test Range for all test traffic

## Components

### Webserver (NodeJS)

Simple NodeJS/npm webserver that listens for TCP and UDP traffic on ports 8888 and 4000 respectively.

### Network Packet Capture (tcpdump)

Network listening tools are available to listen to network traffic to/from the container.

### External Access

Incoming connections to port 4000 (UDP) or 8888 (on URL /attackme) are logged by the webserver to the shared /log volume for later analysis.

Incoming/outgoing network traffic is monitored and logged by tcpdump to the shared /log volume (PCAP format).

Exposes /opt/node as an external volume (filesystem) that can be modified from the host machine to allow easy modification of the NodeJS code.

Exposes port 8888 for external connection by webrowser from outside the Docker container to view a simple log of Target activity (URL: /attackcount).

## Execution

Target is set to start and run with the overall test range network (i.e. as part of the "docker-compose up -d" command), both as a target webserver and network listener.
