########################################################################
# Features to be written to the output file
# [0] - IPv4 packets sum length
# [1] - Number of TCP packets (IPv4)
# [2] - Number of UDP packets (IPv4)
# [3] - Number of other packets
# [4] - IPv4 packets number (from pcs_ip to known_ip and vice-versa) 
# [5] - IPv4 packets number (from pcs_ip to unknow ips and vice-versa)
# [6] - Number of TCP SYN flags
# [7] - Number of TCP FIN flags
########################################################################
import numpy as np
import math as m
import statistics
import time 


def define_observation(array_observationWindow, time_observationWindow, offset_observationWindow, file_obj):

    num_windows = m.ceil((len(array_observationWindow) -  time_observationWindow) / offset_observationWindow) + 1
    print("Windows's number with a slice strategy : ", num_windows)
    for x in range(0,num_windows) :
        print("=====================================================================")
        print()
        start = x*offset_observationWindow
        print("Window's Start : "+str(start))
        print("Window's End : "+str(start+time_observationWindow))
        observation_analyse(array_observationWindow[start:start+time_observationWindow,:], file_obj)       
        print()
        print("=====================================================================")        

def observation_analyse(ob_window, file_obj):
    result = np.zeros(22)

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
        tmp_data = [x[1] for x in info if x[0] == 1 ]
        tmp_silence = [x[1] for x in info if x[0] == 0 ]
        avg_data = 0
        var_data = 0
        avg_silence = 0
        var_silence = 0
        if len(tmp_data) > 0:
            avg_data = statistics.mean(tmp_data)
            if len(tmp_data) > 1:
                var_data = statistics.variance([x[1] for x in info if x[0] == 1 ])
        if len(tmp_silence) > 0:
            avg_silence = statistics.mean(tmp_silence)
            if len(tmp_silence) > 1:
                var_silence = statistics.variance([x[1] for x in info if x[0] == 0 ])
                
        print("\nNumero de dados -> %d" %sum(x[0]==1 for x in info))
        result[16] = sum(x[0]==1 for x in info)
        print("\nNumero de silencios -> %d"%sum(x[0]==0 for x in info))
        result[17] = sum(x[0]==0 for x in info)
        print("\nTempo de dados medio : %.2f"%avg_data)
        result[18] = avg_data
        print("\nTempo de silêncio medio : %.2f"%avg_silence)
        result[19] = avg_silence
        print("\nVariância do tempo de dados : %.2f"%var_data)
        result[20] = var_data
        print("\nVariância do tempo de silêncios : %.2f"%var_silence)
        result[21] = var_silence
        file_obj.write(result.tobytes())

