import argparse
import os
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('-id', '--inputdirectory', nargs='?', required=True, help='input directory - captured .pcap filenames') 
parser.add_argument('-od', '--outputdirectory', nargs='?', required=True, help='output directory')
args=parser.parse_args()  

for path, dirs, files in os.walk(args.inputdirectory):
	for filename in files:
		file = open(path+"/"+filename, "rb") 
		inFile = file.read(176)
		while inFile:
			line = np.frombuffer(inFile, dtype = np.float64).reshape((22,))
			print(line)			
			inFile = file.read(176)
