# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV NODE_SETUP=setup_6.x

# install nodejs
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          dnsutils \
          inetutils-ping \
          wget \
  && rm -rf /var/lib/apt/lists/* \
  && wget -nv https://deb.nodesource.com/${NODE_SETUP} \
  && bash ${NODE_SETUP} \
  && apt-get install -y --no-install-recommends nodejs \
  && rm ${NODE_SETUP} \
  && mkdir /opt/node/ /var/log/supervisor/ \
  && apt-get purge -y wget && apt-get autoremove -y

# setup VOLUME containing the code to be run by nodejs
VOLUME ./node:/opt/node/
WORKDIR /opt/node/
RUN npm install

# start NodeJS and tcpdump using supervisord
CMD [ "npm", "start" ]

