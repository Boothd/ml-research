#!/bin/sh

# create new log directory using a UUID
uuid=`uuidgen`
log_dir="run-${uuid}"
mkdir -p /usr/local/sbin/log/${log_dir}

# symlink new UUID log dir for "current" use
if [ -e /usr/local/sbin/log/current ]
then
	rm /usr/local/sbin/log/current
fi
ln -s /usr/local/sbin/log/${log_dir} /usr/local/sbin/log/current

echo "Current log dir now ${log_dir}"
