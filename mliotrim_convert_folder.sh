# PUT THE PCAP FILES IN THE FOLDER MAIN_DIR and you are done!
# $1 is the device name, $2 is the traffic folder
#
device=$1
folder=$(dirname $2)/$(basename $2)
echo Folder is $folder
if [ -z "$2" ]; then
    echo "Usage: $0 <DEVICE> <PCAP_FOLDER>"
    exit 1
fi

window_duration=60

#get last pcap

for pcapfile in $folder/*.pcap
do
  echo CASE $pcapfile
  sudo ./mliotrim_pcap_converter.sh $device $pcapfile
done
  
