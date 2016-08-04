# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV NODE_SETUP=setup_6.x

# install tshark/tcpcump and nodejs
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
# TODO: determine which is better for our needs - tshark or tcpdump
          tshark \
          tcpdump \
          dnsutils \
          inetutils-ping \
          wget \
  && rm -rf /var/lib/apt/lists/* \
  && wget -nv https://deb.nodesource.com/${NODE_SETUP} \
  && bash ${NODE_SETUP} \
  && apt-get install -y --no-install-recommends nodejs \
  && rm ${NODE_SETUP} \
  && mkdir /opt/node/ \
  && apt-get purge -y wget && apt-get autoremove -y

# TODO: setup a VOLUME so config can be modified outside of the container

COPY node /opt/node/
WORKDIR /opt/node/
RUN npm install
CMD [ "npm", "start" ]

