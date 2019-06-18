import argparse
import os
import math
import random
import statistics
import numpy as np
import pickle
from sklearn import svm
from sklearn.preprocessing import StandardScaler

# read files and create matrix
def readFileToMatrix(file):
    f = open(file, "r")
    array = np.loadtxt(f)
    array = np.delete(array, [2,3,6,7,10,11,13,14,15,20,21], axis=1)
    return array

def loadFromFiles(files):
    d = dict()
    for f in files:
        file = open(f, 'rb')
        room = os.path.basename(f).split('_')[1].split('.')[0]
        d[room] = pickle.load(file)
    return d

def main():
    parser = argparse.ArgumentParser()
    # Read from files
    parser.add_argument("-f", "--files", nargs='+')
    # Read from an directory
    parser.add_argument("-d", "--directory", nargs='+')
    # Clf file
    parser.add_argument("-c", "--clf", nargs='+', required='True')
    # Scaler file
    parser.add_argument("-s", "--scaler", nargs='+', required='True')
    # Room
    parser.add_argument("-r", "--room", required='True')
    args=parser.parse_args()

    if not (args.files or args.directory):
        parser.error("No files given, add --files or --directory.")

    if not args.files:
        args.files = []

    # get all filenames from directory
    if args.directory:
        for dir in args.directory:
            for r, d, f in os.walk(dir):
                for file in f:
                    if ".dat" in file:
                        args.files.append(os.path.join(r, file))
    
    # read files generated from training
    clf = loadFromFiles(args.clf)
    scaler = loadFromFiles(args.scaler)


    for f in args.files:
        print("Processing file ", os.path.basename(f))
        data = readFileToMatrix(f)
        data = scaler[args.room].transform(data)
        classification = clf[args.room].predict(data)
        n_error_a = classification[classification == -1].size
        history = [1,1,1,1,1,1,1,1,1,1]
        for cl in classification:
            history = history[1:10] + [cl]
            if history.count(-1) > 8:
                print("Anomaly detected!")
            #print("Anomaly") if cl<0 else print("Regular")
        #print("Anomaly chance: ", (n_error_a/data.shape[0])*100,"%\n")

if __name__ == '__main__':
	main()