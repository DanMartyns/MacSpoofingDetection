import argparse
import os
import math
import random
import statistics
import numpy as np
import pickle
from sklearn import svm
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix

# read files and create matrix
def readFileToMatrix(files):
    f = open(files[0], "r")
    array = np.loadtxt(f)
    if len(files) > 0:
        for f in files[1:]:
            f = open(f, "r")
            array = np.concatenate((array, np.loadtxt(f)))

    array = np.delete(array, [2,3,6,7,10,11,13,14,15,20,21], axis=1)
    return array

def predict(files, scaler, clf):
    data = readFileToMatrix(files)
    scaled_data = scaler.transform(data)
    return clf.predict(scaled_data)

def print_results(anomaly_pred, regular_pred):
    print("Average success anomaly: ", ((anomaly_pred[anomaly_pred == -1].size)/anomaly_pred.shape[0])*100,"%")
    print("Average success regular: ", ((regular_pred[regular_pred == 1].size)/regular_pred.shape[0])*100,"%")

    y_pred = np.concatenate((anomaly_pred, regular_pred))
    y_true = np.concatenate((np.full(anomaly_pred.shape[0], -1), np.full(regular_pred.shape[0], 1)))
    print("\nConfusion matrix: \n", confusion_matrix(y_true, y_pred))
    
#main
def main():
    parser = argparse.ArgumentParser()
    # Read from files
    parser.add_argument("-f", "--files", nargs='+')
    # Read from an directory
    parser.add_argument("-d", "--directory", nargs='+')
    # Wildcard to detect if legit computer
    parser.add_argument("-w", "--wildcard", required=True)
    # Assure at least one type of this capture goes to training
    parser.add_argument("-a", "--assure", nargs='+')
    # Kernel config
    parser.add_argument("-k", "--kernel", default="rbf")
    # Wants to export files
    parser.add_argument("-e","--export",  action='store_true')
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
    anomaly_test_files = []
    regular_test_files = []
    # divide filenames in true pc or other
    for f in args.files:
        if args.wildcard in f:
                train_files.append(f)
        else:
            anomaly_test_files.append(f)
    
    # begin process of deciding test and train files
    ratio = 0.3
    remove_elems = math.floor(ratio*len(train_files))
  
    assured_files = []
    count_swapped = 0

    # if there are mandatory files for training
    if args.assure:
        for k in args.assure:
            rescued = []
            for f in train_files:
                if k in f:
                    rescued.append(f)
            if len(rescued) == 1:
                assured_files.append(rescued[0])
            elif len(rescued) > 1:
                random.shuffle(rescued)
                for i in range(0, math.ceil(len(rescued)/2)):
                    elem = rescued.pop(0)
                    assured_files.append(elem)
                for elem in rescued:
                    train_files.remove(elem)
                    regular_test_files.append(elem)
                    count_swapped+=1
                   
    if remove_elems - count_swapped > 0:
        random.shuffle(train_files)
        while count_swapped < remove_elems:
            if train_files[0] not in assured_files:
                regular_test_files.append(train_files.pop(0))
                count_swapped+=1
            else:
                random.shuffle(train_files)

    # fit
    train_data = readFileToMatrix(train_files)
    scaler = StandardScaler()
    scaler.fit(train_data)
    train_data = scaler.transform(train_data)
    clf = svm.OneClassSVM(gamma='auto', kernel=args.kernel)
    clf.fit(train_data)

    # predict
    anomaly_pred = predict(anomaly_test_files, scaler, clf)
    regular_pred = predict(regular_test_files, scaler, clf)

    print_results(anomaly_pred, regular_pred)

    #serialize to file
    if args.export:
        file = open("clf_"+ str(int((n_error_r/test_data.shape[0])*100)) + '.bin',"wb")
        pickle.dump(clf, file)
        file = open("scaler_"+ str(int((n_error_r/test_data.shape[0])*100)) + '.bin',"wb")
        pickle.dump(scaler, file)

if __name__ == '__main__':
	main()