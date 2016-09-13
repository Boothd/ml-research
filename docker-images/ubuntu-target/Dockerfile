# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV NODE_SETUP=setup_6.x

# install tshark/tcpcump and nodejs
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          tcpdump \
          supervisor \
          wget \
  && wget -nv https://deb.nodesource.com/${NODE_SETUP} \
  && bash ${NODE_SETUP} \
  && apt-get install -y --no-install-recommends nodejs \
  && rm ${NODE_SETUP} \
  && mkdir /opt/node/ \
  && rm -rf /var/lib/apt/lists/* \
  && apt-get purge -y wget && apt-get autoremove -y

# configure supervisor daemon
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# copy code to be run by nodejs
COPY node/* /opt/node/
WORKDIR /opt/node/
RUN npm install

# add volume to see logs and code outside of container
VOLUME [ "/log", "/opt/node" ]

# expose ports to listen for network traffic
EXPOSE 8888

# start NodeJS and tcpdump using supervisord
ENTRYPOINT [ "/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf" ]
