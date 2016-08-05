# use latest version of Ubuntu
FROM ubuntu:latest
MAINTAINER chris.sampson@naimuri.com

ENV NUMPY_VERSION 1.9.2
ENV SCIPY_VERSION 0.16.0
ENV SKLEARN_VERSION 0.16.1

# install anaconda
ENV ANACONDA_VERSION=Anaconda2-4.1.1-Linux-x86_64
ENV ANACONDA_DIR=/pot/anaconda2
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update --fix-missing && apt-get install -y wget bzip2 ca-certificates \
    libglib2.0-0 libxext6 libsm6 libxrender1 \
    git mercurial subversion    

RUN echo 'export PATH=/opt/conda/bin:$PATH' > /etc/profile.d/conda.sh && \
    wget --quiet https://repo.continuum.io/archive/${ANACONDA_VERSION}.sh -O ~/anaconda.sh && \
    /bin/bash ~/anaconda.sh -b -p ${ANACONDA_DIR} && \
    rm ~/anaconda.sh

RUN apt-get install -y curl grep sed dpkg && \
    TINI_VERSION=`curl https://github.com/krallin/tini/releases/latest | grep -o "/v.*\"" | sed 's:^..\(.*\).$:\1:'` && \
    curl -L "https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini_${TINI_VERSION}.deb" > tini.deb && \
    dpkg -i tini.deb && \
    rm tini.deb && \
    apt-get clean



RUN set -x \
    && buildDeps=' \
        ca-certificates \
        curl \
        gcc \
        g++ \
        libbz2-dev \
        libc6-dev \
        libncurses-dev \
        libreadline-dev \
        libsqlite3-dev \
        libssl-dev \
        make \
        xz-utils \
        zlib1g-dev \
    ' \
    && apt-get install -y --no-install-recommends \
        $buildDeps \
    && rm -rf /var/lib/apt/lists/* \
# Install numpy
&& mkdir -p /usr/src/numpy \
&& cd /usr/src/numpy \
&& curl -SL "https://github.com/numpy/numpy/archive/v$NUMPY_VERSION.tar.gz" | tar -xz --strip-components=1 \
&& echo '[default]\n\
    include_dirs = /opt/openblas/include\n\
    library_dirs = /opt/openblas/lib\n\
    \n\
    [openblas]\n\
    openblas_libs = openblas\n\
    library_dirs = /opt/openblas/lib\n\
    \n\
    [lapack]\n\
    lapack_libs = openblas\n\
    library_dirs = /opt/openblas/lib\n'\
    >> site.cfg \
&& python setup.py build --fcompiler=gnu95 \
&& python setup.py install \
&& rm -rf /usr/src/numpy \
# Install scipy
&& mkdir -p /usr/src/scipy \
&& cd /usr/src/scipy \
&& curl -SL "https://github.com/scipy/scipy/archive/v$SCIPY_VERSION.tar.gz" | tar -xz --strip-components=1 \
&& python setup.py build --fcompiler=gnu95 \
&& python setup.py install \
&& rm -rf /usr/src/scipy \
# Install scikit-learn
&& mkdir -p /usr/src/sklearn \
&& cd /usr/src/sklearn \
&& curl -SL "https://github.com/scikit-learn/scikit-learn/archive/$SKLEARN_VERSION.tar.gz" | tar -xz --strip-components=1 \
&& python setup.py build --fcompiler=gnu95 \
&& python setup.py install \
&& rm -rf /usr/src/sklearn \
# Cleanup
&& cd / \
&& pip3 uninstall -y cython \
&& rm -rf ~/.cache/pip \
&& apt-get purge -y $buildDeps \
&& apt-get autoremove -y \
&& apt-get clean -y





# setup image defaults for run
WORKDIR ${ANACONDA_DIR}
ENV PATH ${ANACONDA_DIR}/bin:$PATH
ENTRYPOINT [ "/usr/bin/tini", "--" ]
CMD [ "/bin/bash" ]



#ENTRYPOINT ["${ANACONDA_DIR}/bin/python"]