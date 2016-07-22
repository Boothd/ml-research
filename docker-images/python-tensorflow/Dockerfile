# use latest version of Ubuntu
FROM python:3.5
MAINTAINER chris.sampson@naimuri.com

ENV TF_BINARY=tensorflow-0.9.0-cp35-cp35m-linux_x86_64.whl

# install tensorflow
RUN pip3 install --upgrade https://storage.googleapis.com/tensorflow/linux/cpu/${TF_BINARY}

