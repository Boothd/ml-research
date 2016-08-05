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
          dnsutils \
          inetutils-ping \
          wget \
          unzip \
  && rm -rf /var/lib/apt/lists/* \
# get latest version of bonesi
  && wget -nv https://github.com/Markus-Go/bonesi/archive/master.zip \
  && unzip master.zip \
  && rm master.zip \
# configure and install bonesi
  && cd bonesi-master \
  && chmod +x configure \
  && ./configure \
  && make \
  && make install \
  && apt-get purge -y unzip wget && apt-get autoremove -y

# disable rp_filter (desired by BONESI)
COPY 90-disable-rp_filter.conf /etc/sysctl.d/

# add volumes to control config and see logs outside of container
COPY config/* /bonesi-master/config
VOLUME [ "/log", "/bonesi-master/config" ]

# by default, launch into bonesi (requires at least the target to be specified at runtime)
ENTRYPOINT [ "bonesi", "--protocol=tcp", "--ips=/bonesi-master/config/bots.txt", "--url_list=/bonesi-master/config/urllist.txt", "--useragent_file=/bonesi-master/config/browserlist.txt" ]

