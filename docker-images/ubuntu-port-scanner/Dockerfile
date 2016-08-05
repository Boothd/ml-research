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

# add the port_scanner script
COPY port_scanner.py /

# add volumes to control config and see logs outside of container
COPY config/* config/
VOLUME [ "/log", "/config" ]

# by default, launch into nmap (requires at least the target to be specified at runtime)
ENTRYPOINT [ "nmap", "-oN", "/log/nmap.log" ]

