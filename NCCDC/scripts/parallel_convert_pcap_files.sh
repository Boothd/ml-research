#!/bin/bash

SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

DATA_DIR=$1
OUTPUT_DIR=$2

if [[ -z $DATA_DIR ]]
then
	echo "Must specify directory containing data"
	exit 1
fi
if [[ ! -d $DATA_DIR ]]
then
	echo "Data directory ($DATA_DIR) doesn't exist or is not a directory"
	exit 2
fi

if [[ ! -d $OUTPUT_DIR ]]
then
	echo "Output directory ($OUTPUT_DIR) doesn't exist, creating"
	mkdir -vp $OUTPUT_DIR
	if [[ ! -d $OUTPUT_DIR ]]
	then
		echo "Output directory could not be created"
		exit 3
	fi
fi

parallel --no-notice --eta --progress "python ${SCRIPT_DIR}/../pcap_to_csv.py -i {} > ${OUTPUT_DIR}/{/.}.csv" ::: `ls ${DATA_DIR}/*.gz`
