#!/bin/bash
# Take as input the pcap and run all the steps of the framework, place the pcap in the /device/traffic folder
# 1. Convert PCAP to CSV, 2. Extract DNS from PCAP, 3. Convert CSV to windowed!


if [ -z "$4" ]; then
    echo "Usage: $0 <DEVICE_ID> <PCAP_FILE> <DNS_FILE> <WINDOW>"
    exit 1
fi

device=$1
pcap_file=$2
dns_file=$3
window_duration=$4


pcap_dir=$(dirname $pcap_file)
filename=$(basename ${2%.*})
csv_file=$pcap_dir/$filename.csv
windowed_file=$pcap_dir/windowed/$window_duration/$filename.csv

#-------
if [ -f "$csv_file" ]; then
	echo "CSV FILE exists."
else
	echo Converting pcap with Tshark
	#convert pcap to csv with tshark
	/usr/bin/tshark -r $pcap_file -T fields -e frame.time_epoch -e frame.len -e frame.protocols -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.proto -e ip.len -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tcp.flags -E header=y -E separator=, -R "udp or tcp" -2 -E quote=d -E occurrence=f > $pcap_dir/$filename.csv
fi	

if [ -f "$pcap_dir/${filename}_dns.txt" ]; then
	echo "DNS FILE exists."
else
	echo parsing pcap for DNS
	#find all dns and append to main dns file
	/usr/bin/tshark -r $pcap_file -Y 'dns.resp.type == 1' -T fields -e dns.qry.name -e dns.a > $pcap_dir/${filename}_dns.txt
fi

#parse the dns to have one domain/ip for each line
while IFS= read -r line; do
    # Extract destination name and IPs
    dest_name=$(echo "$line" | awk '{print $1}')
    ips=$(echo "$line" | awk '{print $2}')

    # Split IPs by comma and print in the desired format
    for ip in $(echo "$ips" | tr ',' ' '); do
        echo "$dest_name $ip"
    done
done < $pcap_dir/${filename}_dns.txt > $pcap_dir/${filename}_dns_unique.txt

#| sort -u > $main_dir/devices/$device/traffic/${filename}_dns.txt
sort -u $pcap_dir/${filename}_dns_unique.txt >> $dns_file



#make the dns unique (optional)
#sort -u  $dns_file > $dns_file

#extract windowed_features
if [ -f "$windowed_file" ]; then
	echo "WINDOWED FILE exists."
else
	echo "Extracting windowed features with w=$window_duration for device $device"
	#extracts the features with python (input device window csv_file out_file dns_file
	python3 pcap_to_features.py $device $window_duration $csv_file $windowed_file $dns_file
fi


