# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install tshark/tcpcump and pre-requisites
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
# TODO: determine which is better for our needs - tshark or tcpdump
          tshark \
          tcpdump \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update
RUN apt-get install curl
RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get install -y nodejs

RUN mkdir /opt/node/
COPY node /opt/node/
WORKDIR /opt/node/
RUN npm install
CMD [ "npm", "start" ]