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
          python3-yaml \
  && rm -rf /var/lib/apt/lists/* \
# get latest port_scanner script
  && wget https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/port_scanner.py \
  && chmod +x port_scanner.py \
  && mkdir /log
  && apt-get purge -y wget

ADD logging.yaml /config/

