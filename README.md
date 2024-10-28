# This repo contains the learning module of ML-IOTRIM
You will need to extract the list of essential/non-essential destinations for each device following the IoTrim procedure: https://github.com/IoTrim/IoTrigger/tree/main

The following scripts start from a traffic folder containing PCAP files and for each file do the following:
	- Extract the dns queries in a TXT file
	- Extract the network features in CSV format
	- Evaluate the machine learning models and output the result


REQUIREMENTS:
	You need the MonIoTr framework installed, or edit the pcap_to_features.py file to pass the device IP address from command line
	Following libraries in python3 are required: numpy, scikit-learn, joblib, pandas


The first script extracts the dataset: mliotrim_convert_folder.sh
Usage:
	sudo ./mliotrim_convert_folder.sh DEVICE TRAFFIC_FOLDER
Example: 
	sudo ./mliotrim_convert_folder.sh echo-dot-3 ./devices/echo-dot-3/traffic

This will extract all the features and produce the CSV windowed output



To evaluate the machine learning model and take decision on the destinations, we can use the evaluate_rf.py script.
We need to pass the windowed file which is the output of the previous procedure.
Usage:
	sudo python3 evaluate_rf.py WINDOWED_CSV_FILE
