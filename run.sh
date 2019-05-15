if [ $# -eq 0 ]; then
	echo Usage:   ./run.sh name
	echo          ./run.sh name index [when starting count from an offset]
	echo Example: ./run.sh browsing
	echo "$HOSTNAME"_browsing_0.pcap
	exit
fi
if [ $# -eq 2 ]; then
	cnt=$2
else 
	cnt=0
fi

while [ true ]; do 
	tshark -w "$HOSTNAME"_$1_$cnt.pcap -a duration:600
	cnt=$(($cnt+1))
done
