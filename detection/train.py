#pickle
import argparse
import os
import math
import random
import statistics
import numpy as np
import pickle
from sklearn import svm

percentage_anomaly = []
percentage_not = []

# read files and create matrix
def readFileToMatrix(files):
    print(files[0])
    f = open(files[0], "r")
    array = np.loadtxt(f)
    #print("Current dimensions: ", array.shape)
    if len(files) > 0:
        for f in files[1:]:
            print(f)
            f = open(f, "r")
            array = np.concatenate((array, np.loadtxt(f)))
            #print("Current dimensions: ", array.shape)
    array = np.delete(array, list(range(16,22)), axis=1)
    array = np.delete(array, 11, axis=1)
    array = np.delete(array, 8, axis=1)
    array = np.delete(array, 7, axis=1)
    array = np.delete(array, 6, axis=1)
    array = np.delete(array, 3, axis=1)
    array = np.delete(array, 0, axis=1)
    #print("Current dimensions: ", array.shape)
    return array

# fit
def fit(matrix, room):
    if room == '214':
        clf = svm.OneClassSVM(gamma='auto', kernel='linear')
    else:
        clf = svm.OneClassSVM(gamma='auto', kernel='rbf')
    return clf.fit(matrix)

# serialize and write to file
def serializeToFile(result):
    return 0

#test data
def predictFile(clf, file, anomaly):
    print("\nFile ", os.path.basename(file), " anomaly status: ", anomaly)
    array = readFileToMatrix([file])
    predict = clf.predict(array)
    #print(predict)
    if anomaly:
        n_error = predict[predict == -1].size
        percentage_anomaly.append((n_error/array.shape[0])*100)
    else:
        n_error = predict[predict == 1].size
        percentage_not.append((n_error/array.shape[0])*100)
    print((n_error/array.shape[0])*100, "% correct")

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
    # DETI room
    parser.add_argument("-r", "--room", required=True)
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
    
    print("ROOM %s\nAllowed count: %d\nAnomaly count: %d" % (args.room, len(train_files), len(test_files)))
    # begin process of deciding test and train files
    percentage = len(train_files) / len(test_files)
    if percentage > 4:
        ratio = 0.6
    elif percentage > 0.9:
        ratio = 0.5
    elif percentage > 0.75:
        ratio = 0.4
    elif percentage > 0.5:
        ratio = 0.3
    else:
        ratio = 0.20
    remove_elems = math.floor(ratio*len(train_files))
    
    print("Ratio moved for testing: ", ratio)
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
                    test_files.append(elem)
                    count_swapped+=1
                   
    if remove_elems - count_swapped > 0:
        random.shuffle(train_files)
        while count_swapped < remove_elems:
            if train_files[0] not in assured_files:
                test_files.append(train_files.pop(0))
                count_swapped+=1
            else:
                random.shuffle(train_files)

    print("\nTrain file count: ", len(train_files))
    print("Test file count: ", len(test_files))
    print("\nTrain files: ") 
    for f in train_files:
        print(os.path.basename(f))
    print("\nTest files: ") 
    for f in test_files:
        print(os.path.basename(f))

    print("\n\n\nStart training...")
    clf = fit(readFileToMatrix(train_files), args.room)
    print("Finished training!")

    #predict
    print("\n\n\nStart predictions...")
    for f in test_files:
        predictFile(clf, f, not args.wildcard in f)

    print("Average success anomaly: ", statistics.mean(percentage_anomaly), "% +- ", statistics.stdev(percentage_anomaly))
    print("Average success normal: ", statistics.mean(percentage_not), "% +- ", statistics.stdev(percentage_not))
        
    
    #serialize to file
    file = open("clf_"+ args.room + "_" + str(int(statistics.mean(percentage_anomaly))) + "_" + str(int(statistics.mean(percentage_not))),"wb")
    pickle.dump(clf, file)


if __name__ == '__main__':
	main()