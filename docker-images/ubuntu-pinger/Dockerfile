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
  && mkdir /opt/node/ \
  && apt-get purge -y wget && apt-get autoremove -y

# copy code to be run by nodejs
COPY node/* /opt/node/
WORKDIR /opt/node/
RUN npm install

# add volume to see code outside of container
VOLUME [ "/opt/node" ]

# start NodeJS
CMD [ "npm", "start" ]

