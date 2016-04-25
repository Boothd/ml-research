#!/bin/bash

SCRIPT_DIR=`dirname "$(readlink -f "$0")"`

CSV_DIR=$1
OUTPUT_DIR=$2

if [[ -z $CSV_DIR ]]
then
	echo "Must specify directory containing CSV data"
	exit 1
fi
if [[ ! -d $CSV_DIR ]]
then
	echo "CSV data directory ($CSV_DIR) doesn't exist or is not a directory"
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

# process each of the CSV files through the graphing script, using the filename as the destination IP filter
parallel --no-notice --eta --progress "python ${SCRIPT_DIR}/../csv_to_graph.py -i {} -o ${OUTPUT_DIR} -d {.}" ::: `ls -1 ${CSV_DIR}/*.csv`

