# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install BONESI and pre-requisites
# TODO: suspect we need to install a lot more pre-requisites before this will work properly...?
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          wget \
          automake \
          libpcap \
          libpcap-dev \
          libnet1 \
          libnet1-dev \
          unzip \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir bonesi \
  && wget https://github.com/Markus-Go/bonesi/archive/master.zip -O bonesi/master.zip \
  && cd bonesi \
  && unzip master.zip \
  && chmod +x configure \
# TODO: might need to update the configure script for automake version before running it?
  && ./configure \
  && make \
  && make install
