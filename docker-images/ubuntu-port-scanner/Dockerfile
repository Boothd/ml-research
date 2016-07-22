# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install python, nmap and port_scanner script
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          wget \
		  nmap \
		  python3 \
		  python3-nmap \
  && rm -rf /var/lib/apt/lists/* \
  && wget https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/port_scanner.py \
  && chmod +x port_scanner.py \
# setup config & log directories for port_scanner usage
  && mkdir config log \
  && chmod +rwx config log \
  && wget https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/config/logging.yaml -O config/logging.yaml
