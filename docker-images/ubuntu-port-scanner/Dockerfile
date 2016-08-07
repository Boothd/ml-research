# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install python, nmap and port_scanner script
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          nmap \
          dnsutils \
          inetutils-ping \
          python3 \
          python3-nmap \
          python3-yaml \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir /log /config \
  && apt-get autoremove -y

# add the port_scanner script and config
COPY port_scanner.py /
RUN chmod +x port_scanner.py
COPY config/* config/

# add volumes to control config and see logs outside of container
VOLUME [ "/log", "/config" ]

# by default, launch into python_scanner (requires at least the target to be specified at runtime, "-t target")
ENTRYPOINT [ "/port_scanner.py" ]

