# [0] - IPv4 packets sum length
# [1] - Number of TCP packets (IPv4)
# [2] - Number of UDP packets (IPv4)
# [3] - Number of other packets
# [4] - IPv4 packets nckets number (from pcs_ip to known_ip and vicumber (from pcs_ip to known_ip and vice-versa) 
# [5] - IPv4 packets number (from pcs_ip to unknow ips and vice-versa)
# [6] - Number of times of silence in an observation window
# [7] - Number of TCP SYN flags
# [8] - Number of TCP FIN flags

import argparse
import matplotlib.pyplot as plt

# configs
window_size = 120
window_offset = 20
sample_size = 0

# feature count
tcp_count = []

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--files", nargs='+', required=True)
args=parser.parse_args()
files = args.files

for f in files:
    f = open(f, "r")
    for line in f:
        values = list(map(int, line.split()))
        tcp_count.append(values[1])
        sample_size += 1

num_windows = sample_size // window_offset
if window_offset < window_size:
    num_windows -= 1
    
for i in range(0, num_windows):
    start = i*window_offset
    plt.plot(tcp_count[start:start+window_size])

plt.yscale('log')
plt.ylabel('tcp packets')
plt.show()