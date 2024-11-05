# This repo contains the learning module of ML-IOTRIM

## IoTrim Requirements for Ground-Truth
You will need to extract the list of essential/non-essential destinations for each device following the IoTrim procedure: https://github.com/IoTrim/IoTrigger/tree/main

The procedure requires Moniotr and produces two lists, contained in the folder MONIOTR_DIRECTORY/YOUR_DEVICE/traffic/tagged.\
A txt file for Essential and a file for Non-essential destinations.

## ML-IoTrim Logic
The following scripts start from a traffic folder containing PCAP files and for each file do the following:
* Extract the dns queries in a TXT file
* Extract the network features in CSV format
* Evaluate the machine learning models and output the result


## REQUIREMENTS:
You need the MonIoTr framework installed, or edit the pcap_to_features.py file to pass the device IP address from command line

The following libraries for python3 are required: numpy, scikit-learn, joblib, pandas


## Script 1: mliotrim_convert_folder.sh
The script convert a folder of PCAP file to a folder of CSV files, obtained aggregating packets and extracting statistical features

Usage:
	sudo ./mliotrim_convert_folder.sh DEVICE TRAFFIC_FOLDER

Example: 
	sudo ./mliotrim_convert_folder.sh echo-dot-3 ./devices/echo-dot-3/traffic

This will extract all the features and produce the CSV windowed output

## Script 2: evaluate_rf.py

The script evaluates the machine learning model and take decision on the destinations.

We need to pass the windowed file which is the output of the previous procedure.

Usage:
	sudo python3 evaluate_rf.py WINDOWED_CSV_FILE
