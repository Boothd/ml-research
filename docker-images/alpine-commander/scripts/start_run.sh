#!/bin/sh

# create new log directory using a UUID
uuid=`uuidgen`
base_dir=/log
current_dir=${base_dir}/current
log_dir=${base_dir}/run-${uuid}
mkdir -p ${log_dir}

# symlink new UUID log dir for "current" use
if [ -e "${current_dir}" ]
then
        rm ${current_dir}
fi
ln -s ${log_dir} ${current_dir}

echo "Current log dir now ${log_dir}"
