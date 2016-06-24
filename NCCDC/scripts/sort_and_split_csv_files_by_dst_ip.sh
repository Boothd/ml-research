#!/bin/bash

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

sort -t, -k5,5n -k3,3g $CSV_DIR/*.csv | awk -F, "{print >> (\"${OUTPUT_DIR}/\"$4\".csv\"); print >> (\"${OUTPUT_DIR}/\"$2\".csv\")}"
