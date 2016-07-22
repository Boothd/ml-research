# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV TF_BINARY=tensorflow-0.9.0-cp35-cp35m-linux_x86_64.whl

# install python, nmap and port_scanner script
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          python3 \
		  python3-pip \
  && rm -rf /var/lib/apt/lists/* \
  && pip3 install --upgrade https://storage.googleapis.com/tensorflow/linux/cpu/${TF_BINARY} \
  && apt-get purge python3-pip
