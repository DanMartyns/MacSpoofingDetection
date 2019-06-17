import argparse
import os
import math
import random
import statistics
import numpy as np
import pickle
from sklearn import svm
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

def readFileToMatrix(files):
    f = open(files[0], "r")
    array = np.loadtxt(f)
    if len(files) > 0:
        for f in files[1:]:
            f = open(f, "r")
            array = np.concatenate((array, np.loadtxt(f)))
    return array

def main():
    parser = argparse.ArgumentParser()
    # Read from files
    parser.add_argument("-f", "--files", nargs='+')
    # Read from an directory
    parser.add_argument("-d", "--directory", nargs='+')
    # Wildcard to detect if legit computer
    parser.add_argument("-w", "--wildcard", required=True)
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

    train_files = []
    test_files = []    
    # divide filenames in true pc or other
    for f in args.files:
        if args.wildcard in f:
                train_files.append(f)
        else:
            test_files.append(f)
    

    train_data = readFileToMatrix(train_files)
    scaler = StandardScaler()
    scaler.fit(train_data)
    train_data = scaler.transform(train_data)
    pca = PCA()
    pca_data = pca.fit_transform(train_data)
   
    np.set_printoptions(precision=5, suppress=True)
    print(pca.explained_variance_ratio_)
    print(abs(pca.components_))


if __name__ == '__main__':
	main()