echo Folder is $folder
if [ -z "$4" ]; then
    echo "Usage: $0 <DEVICE_ID> <PCAP_FOLDER> <DNS_FILE> <WINDOW>"
    exit 1
fi

device=$1
pcap_folder=$(dirname $2)/$(basename $2)
dns_file=$3

window_duration=$4

#get last pcap

for pcapfile in $pcap_folder/*.pcap
do
  echo CASE $pcapfile
  sudo ./pcap_converter.sh $device $pcapfile $dns_file $window_duration
done


