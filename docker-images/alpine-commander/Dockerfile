# use latest version of alpine
FROM alpine
MAINTAINER chris.sampson@naimuri.com

# install uuidgen and create directories
RUN apk add --no-cache util-linux \
  && mkdir -p /scripts /log

# add control script(s)
COPY scripts/* /scripts/

# add volumes to see logs outside of container
VOLUME [ "/log" ]

# setup initial run with start_run script
RUN chmod +x /scripts/*

# start new run of the test network
ENTRYPOINT [ "/bin/sh" "/scripts/start_run.sh" ]
