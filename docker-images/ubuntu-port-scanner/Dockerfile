# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install python, nmap and port_scanner script
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          nmap \
          python3 \
          python3-nmap \
          python3-yaml \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir /usr/local/sbin/log /usr/local/sbin/config \
  && ln -s /usr/local/sbin/log /log \
  && apt-get autoremove -y

# add the port_scanner script and config
COPY port_scanner.py /usr/local/sbin/
RUN chmod +x /usr/local/sbin/port_scanner.py
COPY config/* /usr/local/sbin/config/

# add volumes to control config and see logs outside of container
VOLUME [ "/usr/local/sbin/log", "/usr/local/sbin/config" ]

# setup image defaults to start in the python scripts directory
WORKDIR /usr/local/sbin/
ENV PATH="/usr/local/sbin:$PATH"

# by default, launch into python_scanner (requires at least the target to be specified at runtime)
ENTRYPOINT [ "python3", "/usr/local/sbin/port_scanner.py" ]

