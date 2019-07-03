if [ $# -eq 0 ]; then
	echo Usage:   ./genFeatures.sh dir/*
	exit
fi

a=$#

for i; 
do
	out=${i#data/}
	python3 dataAcquisitionOptimezed.py -id $i -od results/$out
done
