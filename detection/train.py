import argparse
import os
import math
import random
import statistics
import numpy as np
import pickle
import copy
from sklearn import svm
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix
from sklearn.neighbors import LocalOutlierFactor
from sklearn.covariance import EllipticEnvelope
from sklearn.covariance import MinCovDet

# read files and create matrix
def readFileToMatrix(files):
    f = open(files[0], "r")
    array = np.loadtxt(f)
    if len(files) > 0:
        for f in files[1:]:
            f = open(f, "r")
            array = np.concatenate((array, np.loadtxt(f)))

    array = np.delete(array, [0,3,4,5,6,10,12,13,14,18,20,21,22,23], axis=1)
    return array

def predict(files, scaler, clf):
    data = readFileToMatrix(files)
    scaled_data = scaler.transform(data)
    return clf.predict(scaled_data)

def print_results(anomaly_pred, regular_pred):
    an = ((anomaly_pred[anomaly_pred == -1].size)/anomaly_pred.shape[0])*100
    re = ((regular_pred[regular_pred == 1].size)/regular_pred.shape[0])*100
    print("\nAverage success anomaly: ", an, "%")
    print("Average success regular: ", re,"%")
    print("Score: ", int((an+re*1.5)*100/250))

    y_pred = np.concatenate((anomaly_pred, regular_pred))
    y_true = np.concatenate((np.full(anomaly_pred.shape[0], -1), np.full(regular_pred.shape[0], 1)))
    print("Confusion matrix: \n", confusion_matrix(y_true, y_pred), "\n")

    return (int(an), int(re))

def calc_score(anomaly_pred, regular_pred):
    an = ((anomaly_pred[anomaly_pred == -1].size)/anomaly_pred.shape[0])*100
    re = ((regular_pred[regular_pred == 1].size)/regular_pred.shape[0])*100
    return int((an+re*1.5)*100/250)

def remove_algorithms(score):
    remv = copy.deepcopy(score)
    score.sort(reverse=True)
    median = score[math.floor(len(score)/2)]
    step = math.floor((score[0] - score[len(score)-1])/len(score))
    values = []

    for i in range(1, len(score)):
        if score[i] < median and (math.floor(score[i-1] - score[i]) >= step or median - score[i] > 2*step):
            values.append(score[i])

    print(len(values))
    return [i for i, x in enumerate(remv) if x in values]

def decide(pred, ignore=[]):
    pred = np.delete(pred, ignore, axis=1)
    l = []
    for i in range(0, pred.shape[0]):
        col = pred[i,:]
        if col.tolist().count(-1) > math.ceil(pred.shape[1]*0.4):
            l.append(-1)
        else:
            l.append(1)
    return np.array(l)

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
    # Wants to export files
    parser.add_argument("-e","--export",  action='store_true')
    # Print confusion matrix for each algorithm
    parser.add_argument("-v","--verbose",  action='store_true')
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
    clf = []
    clf.append(svm.OneClassSVM(gamma='auto', kernel='rbf'))
    clf.append(svm.OneClassSVM(gamma=0.0000001, kernel='rbf')) 
    clf.append(svm.OneClassSVM(gamma=1, kernel='rbf'))
    clf.append(svm.OneClassSVM(kernel='linear'))
    clf.append(svm.OneClassSVM(gamma='auto', kernel='poly', degree=1))
    clf.append(svm.OneClassSVM(gamma='auto', kernel='poly', degree=2))
    clf.append(svm.OneClassSVM(gamma='auto', kernel='poly', degree=5))
    clf.append(svm.OneClassSVM(gamma=1, kernel='poly', degree=1))
    clf.append(svm.OneClassSVM(gamma=1, kernel='sigmoid'))
    clf.append(IsolationForest(behaviour='new', max_samples='auto', contamination=0.1))
    clf.append(IsolationForest(behaviour='new', max_samples=int(train_data.shape[0]/2), contamination=0.2))
    clf.append(LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.1))
    clf.append(LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.2))
    clf.append(EllipticEnvelope(support_fraction=0.9, contamination=0.1))
    clf.append(EllipticEnvelope(support_fraction=0.9, contamination=0.2))

    flag = True
    score = []
    for c in clf:
        c.fit(train_data)
        # predict
        an = predict(anomaly_test_files, scaler, c).reshape(-1,1)
        re = predict(regular_test_files, scaler, c).reshape(-1,1)

        if flag:
            anomaly_pred = an
            regular_pred = re
            flag = False
        else:
            anomaly_pred = np.concatenate((anomaly_pred, an), axis=1)
            regular_pred = np.concatenate((regular_pred, re), axis=1)
        
        score.append(calc_score(an, re))
        
        if args.verbose:
            print_results(predict(anomaly_test_files, scaler, c), predict(regular_test_files, scaler, c))

    ignore = remove_algorithms(score)
    print_results(decide(anomaly_pred), decide(regular_pred))
    fname = print_results(decide(anomaly_pred, ignore=ignore), decide(regular_pred, ignore=ignore))
    print(ignore)
    
    #serialize to file
    if args.export:
        ignore.reverse()
        for c in ignore:
            del clf[c]
        file = open("clf_" + str(fname[0]) + "_" + str(fname[1]) + '.bin',"wb")
        pickle.dump(clf, file)
        file = open("scaler_" + str(fname[0]) + "_" + str(fname[1]) + '.bin',"wb")
        pickle.dump(scaler, file)

if __name__ == '__main__':
	main()