# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install anaconda
ENV ANACONDA=Anaconda3-4.1.1-Linux-x86_64.sh
ENV ANACONDA_DIR=/opt/anaconda3

RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          bzip2 \
  && rm -rf /var/lib/apt/lists/*
ADD http://repo.continuum.io/archive/${ANACONDA} /
RUN bash ${ANACONDA} -b -p ${ANACONDA_DIR} \
  && rm ${ANACONDA} \
  && apt-get purge -y bzip2 && apt-get autoremove -y


# install tensorflow
ENV TF_CPU_OR_GPU=cpu
ENV TF_BINARY=tensorflow-0.9.0-cp35-cp35m-linux_x86_64.whl

RUN ${ANACONDA_DIR}/bin/pip install --ignore-installed --upgrade https://storage.googleapis.com/tensorflow/linux/${TF_CPU_OR_GPU}/${TF_BINARY}


# setup image defaults for run
WORKDIR ${ANACONDA_DIR}/bin
ENV PATH="${ANACONDA_DIR}/bin:$PATH"
ENTRYPOINT ["${ANACONDA_DIR}/bin/python3"]

