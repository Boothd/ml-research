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
  && wget https://github.com/Markus-Go/bonesi/archive/master.zip -O master.zip \
  && unzip master.zip \
  && rm master.zip \
# configure and install bonesi
  && cd bonesi-master \
  && chmod +x configure \
  && configure \
  && make \
  && make install \
  && apt-get purge unzip wget

# disable rp_filter (desired by BONESI)
ADD 90-disable-rp_filter.conf /etc/sysctl.d/

#ENTRYPOINT ["bonesi", "target:80"]

