# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV NODE_SETUP=setup_6.x

# install nodejs
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          wget \
  && wget -nv https://deb.nodesource.com/${NODE_SETUP} \
  && bash ${NODE_SETUP} \
  && apt-get install -y --no-install-recommends nodejs \
  && rm ${NODE_SETUP} \
  && mkdir /log /opt/node/ \
  && rm -rf /var/lib/apt/lists/* \
  && apt-get purge -y wget && apt-get autoremove -y

# copy code to be run by nodejs
COPY node/* /opt/node/
WORKDIR /opt/node/
RUN npm install

# add volume to see code outside of container
VOLUME [ "/log", "/opt/node" ]

# expose port to host for to allow viewing of NodeJS logs
EXPOSE 8866

# start NodeJS
ENTRYPOINT [ "npm", "start" ]
