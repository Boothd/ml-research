# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

# install anaconda with python and scapy (default to use python3, but can override for python2 at build time)
ENV PYTHON_CMD=python3
ENV ANACONDA=Anaconda3-4.1.1-Linux-x86_64.sh
ENV ANACONDA_DIR=/opt/anaconda3
ENV SCAPY=scapy-python3

# python2 equivalents
#ENV PYTHON_CMD=python
#ENV ANACONDA=Anaconda2-4.1.1-Linux-x86_64.sh
#ENV ANACONDA_DIR=/opt/anaconda2
#ENV SCAPY=scapy


# install pre-requisites and PCAP/CSV processing scripts
RUN apt-get update && apt-get install -y --no-install-recommends \
          software-properties-common \
          wget \
          tcpdump \
          parallel \
          bzip2 \
		  python3-qt4 \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir /usr/local/sbin/log /usr/local/sbin/config /usr/local/sbin/scripts \
  && wget -nv https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/pcap_to_csv.py -P /usr/local/sbin/ \
  && wget -nv https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/csv_to_graph.py -P /usr/local/sbin/ \
  && wget -nv https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/scripts/parallel_convert_pcap_files.sh -P /usr/local/sbin/scripts/ \
  && wget -nv https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/scripts/parallel_graph_csv_files.sh -P /usr/local/sbin/scripts/ \
  && wget -nv https://raw.githubusercontent.com/Boothd/ml-research/master/NCCDC/scripts/sort_and_split_csv_files_by_dst_ip.sh -P /usr/local/sbin/scripts/ \
  && chmod -R +x /usr/local/sbin/*

# add the config
COPY config/* /usr/local/sbin/config/

# add volumes to control config and see logs outside of container
VOLUME [ "/usr/local/sbin/log", "/usr/local/sbin/config" ]


# download and install anaconda
ADD http://repo.continuum.io/archive/${ANACONDA} /
RUN bash /${ANACONDA} -b -p ${ANACONDA_DIR} \
  && rm /${ANACONDA} \
  && apt-get purge -y wget bzip2 && apt-get autoremove -y

# install scapy
RUN ${ANACONDA_DIR}/bin/pip install --ignore-installed --upgrade ${SCAPY}


# setup image defaults to start in the anaconda directory
WORKDIR ${ANACONDA_DIR}/bin
ENV PATH="${ANACONDA_DIR}/bin:/usr/local/sbin:$PATH"

