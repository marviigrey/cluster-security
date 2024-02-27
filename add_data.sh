#!/bin/bash

data_directory=/opt/app/data
mkdir -p ${data_directory}
echo "=> File created at `date`" | tee ${data_directory}/create.log
