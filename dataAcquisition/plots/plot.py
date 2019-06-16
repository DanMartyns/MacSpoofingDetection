# [0] - IPv4 packets sum length
# [1] - Number of TCP packets (IPv4)
# [2] - Number of UDP packets (IPv4)
# [3] - Number of other packets
# [4] - IPv4 packets number (from pcs_ip to known_ip and vice-versa) 
# [5] - IPv4 packets number (from pcs_ip to unknow ips and vice-versa)
# [6] - Number of TCP SYN flags
# [7] - Number of TCP FIN flags
import argparse
import matplotlib.pyplot as plt
from numpy import var as variance

# configs
window_size = 120
window_offset = 40
sample_size = 0

# feature count
count = [('IPv4 packets sum length', [], "_ipv4sum"), \
    ('TCP packets', [], "_tcppkts"), \
    ('UDP packets', [], "_udppkts"), \
    ('Other protocol packets', [], "_otherpkts"), \
    ('IPv4 packets to known IP addresses', [], "_known"), \
    ('IPv4 packets to unknown IP addresses', [], "_unknown"), \
    ('TCP SYN flags', [], "_syn"), \
    ('TCP FIN flags', [], "_fin")]

plots = []

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--files", nargs='+', required=True)
args=parser.parse_args()
files = args.files

for f in files:
    f = open(f, "r")
    for line in f:
        values = list(map(int, line.split()))
        for i in range(0, len(values)):
            count[i][1].append(values[i])
        sample_size += 1

num_windows = sample_size // window_offset
if window_offset < window_size:
    num_windows -= 1

for feature in count:  
    for i in range(0, num_windows):
        start = i*window_offset
        plt.plot(feature[1][start:start+window_size])
    if variance(feature[1]) > 50:
        plt.yscale('log')
    plt.ylabel(feature[0])
    if feature[0] == 'TCP packets':
        filename = args.files[0].split(".")[0] + feature[2] + ".png"
        plt.savefig(filename, dpi=150)
    plt.close()