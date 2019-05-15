if [ $# -eq 0 ]; then
	echo Usage:   ./run.sh name
	echo Example: ./run.sh browsing
	echo Will create file "$HOSTNAME"_browsing_1557922782351.pcap
	exit
fi
if [ $# -eq 2 ]; then
	duration=$2
else 
	duration=600
fi

while [ true ]; do
	tstamp=$(($(date +%s%N)/1000000))
	echo Writing to file "$HOSTNAME"_$1_$tstamp.pcap
	echo Capture started at $(date +"%T"), ends at $(date -d '($duration) seconds' +"%T")
	tshark -w "$HOSTNAME"_$1_$tstamp.pcap -a duration:$duration
	echo
done
