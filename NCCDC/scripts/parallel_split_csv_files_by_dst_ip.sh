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

# split records from all CSV files into separate IP-based files (contains all records where Destination IP appears as either Source or Destination, sorted by timestamp)
parallel --no-notice --eta --progress "LC_ALL=C; grep -hF ',{},' ${CSV_DIR}/*.csv | sort -t, -k5,5n -k3,3g >> ${OUTPUT_DIR}/{}.csv" ::: `cat ${CSV_DIR}/*.csv | cut -d, -f 5 | sort -u`
