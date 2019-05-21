    
# Features to be written to the output file
# [0] - IPv4 packets sum length
# [1] - Number of TCP packets (IPv4)
# [2] - Number of UDP packets (IPv4)
# [3] - Number of other packets
# [4] - IPv4 packets number (from pcs_ip to known_ip and vice-versa) 
# [5] - IPv4 packets number (from pcs_ip to unknow ips and vice-versa)
# [6] - Number of TCP SYN flags
# [7] - Number of TCP FIN flags

window_offset = 60
window_size = 120


file = open("results1G.txt", "r") 

line = file.readline()
mean_sum_length = []
mean_tcp_packets = []
mean_udp_packets = []
mean_other_packets = []
mean_packets_known = []
mean_packets_unknown = []
mean_tcp_syn = []
mean_tcp_fin = []

while line:
    splited = line.split(" ")[:-1]
    
    mean_sum_length.append(int(splited[0]))
    mean_tcp_packets.append(int(splited[1]))
    mean_udp_packets.append(int(splited[2]))
    mean_other_packets.append(int(splited[3]))
    mean_packets_known.append(int(splited[4]))
    mean_packets_unknown.append(int(splited[5]))
    mean_tcp_syn.append(int(splited[6]))
    mean_tcp_fin.append(int(splited[7]))
    
    line = file.readline()
file.close()

num_windows = len(mean_sum_length) // window_offset
mean = []
for x in range(0,num_windows) :
    start = x*window_offset
    #print("Start : "+str(start))
    #print("End : "+str(start+window_size))
    sum_length = sum(mean_sum_length[start:start+window_size])/len(mean_sum_length[start:start+window_size])
    print("IPv4 packets sum length - Mean for the window %d : %d" %( x , sum_length ))
    
