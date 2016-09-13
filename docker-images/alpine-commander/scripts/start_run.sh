#!/bin/sh

echoerr() { echo "$@" >&2; }

# generate UUID for use as new log directory
uuid=`uuidgen`
base_dir=/log
current_dir=${base_dir}/current
log_dirname=run-${uuid}
log_dir=${base_dir}/${log_dirname}

# create new log directory (if does not already exist)
if [[ -d "${log_dir}" ]]
then
	echoerr "Log dir ${uuid} already exists, cannot continue"
	exit 1
fi
mkdir -p ${log_dir}

# symlink new UUID log dir for "current" use
if [[ -e "${current_dir}" ]]
then
        rm ${current_dir}
fi

# create symlink relative to the base directory
cd ${base_dir}
ln -s ${log_dirname} current

echo "Current log dir now ${log_dir}"