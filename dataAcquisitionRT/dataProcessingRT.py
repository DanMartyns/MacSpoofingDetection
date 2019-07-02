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

"""
function that normalizes each row of the matrix x to have unit length.

Args:
    ``x``: A numpy matrix of shape (n, m)

Returns:
    ``x``: The normalized (by row) numpy matrix.
"""
def normalize_rows(x: np.ndarray):
    return x/np.linalg.norm(x, ord=2, axis=0, keepdims=True)


def define_observation(array_observationWindow, time_observationWindow, offset_observationWindow, file_obj):

    num_windows = m.ceil((len(array_observationWindow) -  time_observationWindow) / offset_observationWindow) + 1
    print("Windows's number with a slice strategy : ", num_windows)
    for x in range(0,num_windows) :
        print("=====================================================================")
        print()
        start = x*offset_observationWindow
        print("Window's Start : "+str(start))
        print("Window's End : "+str(start+time_observationWindow))
        result = observation_analyse(array_observationWindow[start:start+time_observationWindow,:], file_obj)       
        print()
        print("=====================================================================")        
        return result

def observation_analyse(ob_window, file_obj):
    result = np.zeros(24)

    info = []
    tmpS = 0
    tmpD = 0

    # Get the number of rows and columns
    row,column = ob_window.shape
    print(row,column)

    join = np.zeros((column,row))
    
    #Each array is a column, that is, each array is the data of a metric
    for i in range(0,column) :
        join[i] = ob_window[:,i]
    
    # Initalize array for the mean and variance
    mean = np.zeros(column)
    std = np.zeros(column)

    #Calculate the mean and variance for each metric
    for x in range(0,column):
        mean[x] = np.mean(join[x])
        std[x] = np.std(join[x])

    #Normalize each result
    mean = normalize_rows(mean)
    std = normalize_rows(std)
    
    print("\nMedia para cada métrica :")    
    print(mean)
    result[0:9] = mean
    print("\nDesvio padrão para cada métrica : ")    
    print(std)
    result[9:18] = std

    #Find the number of sampling windows with data and with silences
    for x in ob_window[:,0] :
        x = int(x)
        if x==0 and tmpD > 0 :
            tmpS += 1            
            tmpD = 0
        elif x == 0 :
            tmpS += 1
        elif x != 0 and tmpS > 0 :
            info.append([tmpD,tmpS])            
            tmpD += 1
            tmpS = 0 
        elif x != 0 :                     
            tmpD += 1
    
    #In case of only data or only silences
    if tmpD != 0 or tmpS != 0 :
        info.append([tmpD,tmpS])    
  
    print("\nInfo :")
    print(info)

    # Regardless of the time of a sampling window, count how many data jails there are. This gives us the time of data and the time of silence
    tmp_data = [ x[0] for x in info ]
    tmp_silence =[ x[1] for x in info ]
    
    avg_data = 0
    var_data = 0
    avg_silence = 0
    var_silence = 0
    if len(tmp_data) > 0:    
        avg_data = statistics.mean(tmp_data)
        if len(tmp_data) > 1:
            var_data = statistics.variance([ x[0] for x in info ])
    if len(tmp_silence) > 0:
        avg_silence = statistics.mean(tmp_silence)
        if len(tmp_silence) > 1:           
            var_silence = statistics.variance([ x[1] for x in info ])

    #print("\n( [ Time type , How many consecutive ] ) \n Time Type : 0 - Silence time || 1 - Data time")
    print("\nNumero de dados -> %d" %sum(x[0] for x in info))
    result[18] = sum(x[0]==1 for x in info)
    print("\nNumero de silencios -> %d"%sum(x[1] for x in info))
    result[19] = sum(x[0]==0 for x in [x for x in info] )
    print("\nTempo de dados medio : %.2f"%avg_data)
    result[20] = avg_data
    print("\nTempo de silêncio medio : %.2f"%avg_silence)
    result[21] = avg_silence
    print("\nVariância do tempo de dados : %.2f"%var_data)
    result[22] = var_data
    print("\nVariância do tempo de silêncios : %.2f"%var_silence)
    result[23] = var_silence
    print("\nMatriz de Saída ")
    print([ round(x,3) for x in result] )
    
    # Write the results for this observation window in the file
    return result

