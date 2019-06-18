if [ $# -eq 0 ]; then
	echo Usage:   ./run.sh interface room
	exit
fi

echo python3 dataStream.py -i $1 -ow 120 -wo 20 -c clf* -s scaler* -r $2
python3 dataStream.py -i $1 -ow 120 -wo 20 -c clf* -s scaler* -r $2
