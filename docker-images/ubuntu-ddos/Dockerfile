# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install BONESI and pre-requisites
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          gcc \
          make \
          automake \
          gawk \
          libpcap.\.. \
          libpcap.\..-dev \
          libnet1 \
          libnet1-dev \
          wget \
          unzip \
  && rm -rf /var/lib/apt/lists/* \
# get latest version of bonesi
  && wget -nv https://github.com/Markus-Go/bonesi/archive/master.zip \
  && unzip master.zip \
  && rm master.zip \
# configure and install bonesi
  && cd /bonesi-master \
  && chmod +x configure \
  && ./configure \
  && make \
  && make install \
  && apt-get purge -y unzip wget && apt-get autoremove -y

# add volumes to control config and see logs outside of container
COPY config/* /bonesi-master/config/
VOLUME [ "/log", "/bonesi-master/config" ]

# by default, launch into bonesi (requires at least the target to be specified at runtime)
ENTRYPOINT [ "bonesi", "-o", "/log/current/bonesi_stats_${HOSTNAME}.log", "-i", "/bonesi-master/config/bots.txt", "-l", "/bonesi-master/config/urllist.txt", "-b", "/bonesi-master/config/browserlist.txt" ]
