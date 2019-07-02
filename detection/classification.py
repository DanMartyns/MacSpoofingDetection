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
    array = np.delete(array, [0,3,4,5,6,10,12,13,14,18,20,21,22,23], axis=1)
    return array

def loadFromFiles(files):
    d = dict()
    for f in files:
        file = open(f, 'rb')
        room = os.path.basename(f).split('_')[1].split('.')[0]
        d[room] = pickle.load(file)
    return d

def decide(pred):
    l = []
    for i in range(0, pred.shape[0]):
        col = pred[i,:]
        if col.tolist().count(-1) > math.ceil(pred.shape[1]/2):
            l.append(-1)
        else:
            l.append(1)
    return np.array(l)

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
    # Prints if anomaly has been found
    parser.add_argument("-p","--print",  action='store_true')
    # Print confusion matrix
    parser.add_argument("-m","--matrix",  action='store_true')
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

    matrix_count = [[0,0],[0,0]]
    for f in args.files:
        print("Processing file ", os.path.basename(f))
        data = readFileToMatrix(f)
        data = scaler[args.room].transform(data)
        flag = True
        for c in clf[args.room]:
            if flag:
                pred = c.predict(data).reshape(-1,1)
                flag = False
            else:
                pred = np.concatenate((pred, c.predict(data).reshape(-1,1)), axis=1)
        classification = decide(pred)
        if args.print:
            history = [1,1,1,1]
            for cl in classification:
                history = history[1:4] + [cl]
                if history.count(-1) > 2:
                    print("Anomaly detected!")
        
        if "deti" in f:
            correct = classification.tolist().count(1)
            matrix_count[1][1] += correct
            matrix_count[1][0] += classification.shape[0] - correct
        else:
            correct = classification.tolist().count(-1)
            matrix_count[0][0] += correct
            matrix_count[0][1] += classification.shape[0] - correct
        if args.matrix:
            print("Correct samples: ", correct,"/",classification.shape[0])
    

    print("\nCONFUSION MATRIX\n", matrix_count[0], "\n", matrix_count[1])

if __name__ == '__main__':
	main()