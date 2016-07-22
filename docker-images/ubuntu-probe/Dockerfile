# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install tshark/tcpcump and pre-requisites
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
# TODO: determine which is better for our needs - tshark or tcpdump
		  tshark \
		  tcpdump \
		  
  && rm -rf /var/lib/apt/lists/* \
