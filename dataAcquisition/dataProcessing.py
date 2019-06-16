    
# Features to be written to the output file
# [0] - IPv4 packets sum length
# [1] - Number of TCP packets (IPv4)
# [2] - Number of UDP packets (IPv4)
# [3] - Number of other packets
# [4] - IPv4 packets number (from pcs_ip to known_ip and vice-versa) 
# [5] - IPv4 packets number (from pcs_ip to unknow ips and vice-versa)
# [6] - Number of TCP SYN flags
# [7] - Number of TCP FIN flags
import numpy as np
import math as m
import statistics
import argparse
import os 

window_offset = 20
window_size = 120
observation = None
result = np.zeros(22)

def observation_analyse(ob_window, file_obj):

    print("\nMedia para cada métrica :")
    print([float(x) for x in np.mean(ob_window,axis=0)])
    result[0:8] = [float(x) for x in np.mean(ob_window,axis=0)]
    print("\nDesvio padrão para cada métrica :")    
    print([float(x) for x in np.std(ob_window, axis=0)])
    result[8:16] = [float(x) for x in np.std(ob_window, axis=0)]
    info = []
    tmpS = 0
    tmpD = 0
    for x in ob_window[:,0] :
        x = int(x)
        if x==0 and tmpD > 0 :
            tmpS += 1
            info.append([1,tmpD])
            tmpD = 0
        elif x == 0 :
            tmpS += 1
        elif x != 0 and tmpS > 0 :
            tmpD += 1
            info.append([0,tmpS])
            tmpS = 0            
        elif x != 0 :
            tmpD += 1     

    if info != []:
        #print("\n( [ Time type , How many consecutive ] ) \n Time Type : 0 - Silence time || 1 - Data time")
        #print(info)
        print("\nNumero de dados -> %d" %sum(x[0]==1 for x in info))
        result[16] = sum(x[0]==1 for x in info)
        print("\nNumero de silencios -> %d"%sum(x[0]==0 for x in info))
        result[17] = sum(x[0]==0 for x in info)
        print("\nTempo de dados medio : %.2f"%statistics.mean([x[1] for x in info if x[0] == 1 ]))
        result[18] = statistics.mean([x[1] for x in info if x[0] == 1 ])
        print("\nTempo de silêncio medio : %.2f"%statistics.mean([x[1] for x in info if x[0] == 0 ] ))
        result[19] = statistics.mean([x[1] for x in info if x[0] == 0 ])
        print("\nVariância do tempo de dados : %.2f"%statistics.variance([x[1] for x in info if x[0] == 1 ]))
        result[20] = statistics.variance([x[1] for x in info if x[0] == 1 ])
        print("\nVariância do tempo de silêncios : %.2f"%statistics.variance([x[1] for x in info if x[0] == 0 ]))
        result[21] = statistics.variance([x[1] for x in info if x[0] == 0 ])
        print("\nMatriz de Saída ")
        print(result)
        for r in result:
            file_obj.write(str(result.tostring) + ' ')
        file_obj.write("\n")
    else :
        print("\nThe file was little information")

def readFile(filetoread) :
    global observation

    file = open(filetoread, "r") 
    line = file.readline()
    i = 0
    while line:
        splitted = line.split(" ")
        if len(splitted) > 8:
            splitted = splitted[:-1]
        tmp = [int(x) for x in splitted]
        observation[i] = tmp
        line = file.readline()
        i += 1
        print(line)
        print(i)
    file.close()

def main() :

    parser = argparse.ArgumentParser()
    parser.add_argument('-id', '--inputdirectory', required=True, help='input directory - captured .pcap filenames') 
    parser.add_argument('-od', '--outputdirectory', required=True, help='output directory')    
    parser.add_argument('-si', '--samplingInterval', type=int, help=' time between which measurements are taken, or data is recorded (seconds)', default=1)
    args=parser.parse_args()
    
    interval = args.samplingInterval
    
    for path, dirs, files in os.walk(args.inputdirectory):
        for filename in files:
            
            num_arrays = os.path.getsize(path+"/"+filename)
            
            global observation
            observation = np.zeros((num_arrays,8))            
            
            print(filename)
            readFile(path+"/"+filename)

            num_windows = m.ceil((len(observation) -  window_size) / window_offset) + 1
            print("Windows's number with a slice strategy : ", num_windows)

            file_obj = open(args.outputdirectory+"/"+filename,"w")

            for x in range(0,num_windows) :
                print("=====================================================================")
                print()
                start = x*window_offset
                print("Window's Start : "+str(start))
                print("Window's End : "+str(start+window_size))
                observation_analyse(observation[start:start+window_size,:], file_obj)       
                print()
                print("=====================================================================")

if __name__ == '__main__':
	main()

