# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV TF_BINARY=tensorflow-0.9.0-cp35-cp35m-linux_x86_64.whl
ENV ANACONDA=Anaconda3-4.1.1-Linux-x86_64.sh

# install python, nmap and port_scanner script
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          wget
  && rm -rf /var/lib/apt/lists/* \
  && wget http://repo.continuum.io/archive/${ANACONDA} -O ${ANACONDA} \
  && bash ${ANACONDA} \
  && rm ${ANACONDA} \
  && pip3 install --upgrade https://storage.googleapis.com/tensorflow/linux/cpu/${TF_BINARY}

