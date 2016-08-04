# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install tshark/tcpcump and pre-requisites
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
# TODO: determine which is better for our needs - tshark or tcpdump
          tshark \
          tcpdump \
          dnsutils \
          inetutils-ping \
          nodejs \
          curl \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir /opt/node/ \
  && curl -sL https://deb.nodesource.com/setup_6.x | bash - \
  && apt-get purge -y curl && apt-get autoremove -y

COPY node /opt/node/
WORKDIR /opt/node/
RUN npm install
CMD [ "npm", "start" ]

# TODO: setup a VOLUME so config can be modified outside of the container

