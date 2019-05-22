    
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


window_offset = 0
window_size = 0
observation = np.array(np.zeros((600,8)))

def observation_analyse(ob_window):
    print(np.mean(ob_window,axis=0))
    print(np.std(ob_window, axis=0))

def initialInformation(offset, size):
    window_offset = offset
    window_size = size

def readFile(filetoread) :
    file = open(filetoread, "r") 
    line = file.readline()
    i = 0
    while line:
        splited = line.split(" ")[:-1]
        tmp = [int(x) for x in splited]
        observation[i] = tmp    
        line = file.readline()
        i+=1
    file.close()

initialInformation(40,120)
readFile("Results/ubuntu_225_tpr_1557940526388.dat")

num_windows = m.floor((len(observation) -  window_size) / window_offset)
print("Windows's number with a slice strategy : ", num_windows)

for x in range(0,num_windows+1) :
    print("=====================================================================")
    print()
    start = x*window_offset
    print("Window's Start : "+str(start))
    print("Window's End : "+str(start+window_size))
    observation_analyse(observation[start:start+window_size,:])
    # if observation[start:start+window_size,0] == 0 :
    #     silenceTimes += 1
    #print("Number os silence times : %d"%silenceTimes)        
    print()
    print("=====================================================================")


