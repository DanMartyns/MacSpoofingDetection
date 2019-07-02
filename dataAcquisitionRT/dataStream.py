import sys
import argparse
import pyshark
import time
import numpy as np
import pygeoip
import math
from geopy.distance import geodesic
from dataProcessingRT import define_observation, observation_analyse
from sklearn import svm
from sklearn.preprocessing import StandardScaler
import pickle
import os
import datetime

# DETI coordinates
local_coords = (40.633184, -8.659476)

# GeoIP data
geoip_data = pygeoip.GeoIP('GeoLiteCity.dat')

# IP address wildcard for the captured machine
ip_wildcard = '192.168.8.'

# Milisecond offset in initial packet
timestamp_ms_offset = None

# History of decisions
history = [1,1,1,1]

clf = dict()
scaler = dict()

def processPacket(packet) :
    global packets_amount
    global interval
    global outFile
    global args 
    global T0
    global last_time
    global num_silences
    global ks
    global observationWindow
    global start_ow
    global ow
    global file_obj
    global local_coords
    global geoip_data
    global ip_wildcard
    global timestamp_ms_offset
    global TCP

    # Process packets in file
    try:           
        # Get packet information
        packet_length = packet.length
        timestamp = float(packet.sniff_timestamp)
        frame_info = packet.frame_info
        layers = packet.layers
        eth = packet.eth
        interface_captured = packet.interface_captured             

        if timestamp_ms_offset == None:
            timestamp_ms_offset = timestamp - int(timestamp)
        # Get layer 1 information

        fields = frame_info._all_fields

        protocols = fields.get('frame.protocols')
        time_epoch = fields.get('frame.time_epoch')
        frame_length = fields.get('frame.len')
        encapsulation_type = fields.get('frame.encap_type')

        # If encapsulation is ethernet
        if encapsulation_type=="1":
            eth_fields = eth._all_fields
            src = eth_fields["eth.src"]
            dst = eth_fields["eth.dst"]
            eth_type = eth_fields.get("eth.type")
            addr = eth_fields["eth.addr"]
            
            # IPv4 Packet
            if eth_type == "0x00000800" :
                ipv4_packet = layers[1]
                ipv4_all_fields = ipv4_packet._all_fields

                ipv4_geoIp = ipv4_all_fields.get('')
                ipv4_dst = ipv4_all_fields.get('ip.dst')
                ipv4_protocol = ipv4_all_fields.get('ip.proto')
                ipv4_src = ipv4_all_fields.get('ip.src')
                ipv4_src_host = ipv4_all_fields.get('ip.src_host')
                ipv4_dst_host = ipv4_all_fields.get('ip.dst_host')
                ip_addr = ipv4_all_fields.get('ip.addr')
                
                # TCP packet
                if ipv4_protocol=='6':
                    tcp_packet = layers[2]
                    tcp_all_fields = tcp_packet._all_fields

                    tcp_text = tcp_all_fields.get('')
                    tcp_src_port = tcp_all_fields.get('tcp.srcport')
                    tcp_dst_port = tcp_all_fields.get('tcp.dstport')                     
                    tcp_flags_res = tcp_all_fields.get('tcp.flags.res')
                    tcp_flags_fin = tcp_all_fields.get('tcp.flags.fin')
                    tcp_flags_syn = tcp_all_fields.get('tcp.flags.syn')


            # If packet is IPv4, update features
            if encapsulation_type == "1" and eth_type == "0x00000800":
                outFile[0] = outFile[0] + len(packet_length)
            
                # If TCP, update features
                if ipv4_protocol == "6" : 
                    outFile[1] += 1 # Count TCP packets
                    if tcp_flags_syn != "0" and tcp_flags_syn != None:
                        outFile[6] += int(tcp_flags_syn)
                    if tcp_flags_fin != "0" and tcp_flags_fin != None:
                        outFile[7] += int(tcp_flags_fin)                         
                    
                    if len(TCP) > 0 :                              
                        for i in range(len(TCP)):

                            test = np.prod( np.array([ipv4_src,tcp_src_port,ipv4_dst,tcp_src_port]) == TCP[i,:])
                            testReverse = np.prod( np.array([ipv4_dst,tcp_src_port,ipv4_src,tcp_src_port]) == TCP[i,:])

                            if test or testReverse:
                                break
                            elif (i >= len(TCP) - 1) and not test and not testReverse:
                                TCP = np.vstack( (TCP, [[ipv4_src,tcp_src_port,ipv4_dst,tcp_src_port]]) )
                                outFile[8] += 1                                            

                    else :                          
                        TCP = np.vstack( (TCP, [[ipv4_src,tcp_src_port,ipv4_dst,tcp_src_port]]) )
                        outFile[8] += 1

                # If UDP, update features
                elif ipv4_protocol == "17" : 
                    outFile[2] += 1 # Count UDP packets
                
                # If other, update features
                else: 
                    outFile[3] += 1 # Count other packets



                # If the source ip is known and the destiny ip is known, update feature   
                other_ip = None
                if ip_wildcard in ipv4_src:
                    other_ip = geoip_data.record_by_name(ipv4_dst)
                elif ip_wildcard in ipv4_dst:
                    other_ip = geoip_data.record_by_name(ipv4_src)
                if other_ip != None:
                    distance = geodesic(local_coords, (other_ip["latitude"], other_ip["longitude"]))
                    distance = distance._Distance__kilometers
                    if distance<5500:
                        outFile[4] += 1
                    else :
                        outFile[5] += 1
            

            # If is first packet, get the first timestamp
            if packets_amount==0:
                T0 = float(timestamp)
                last_ks = -1
            else:
                # Save the last ks
                last_ks = ks
            
            # Update the ks
            ks=int((float(timestamp)-T0)/interval)

            #print(ks)
            if packets_amount == 0 :
                last_time = timestamp 

            tmp = math.floor(timestamp-timestamp_ms_offset)-math.ceil(last_time-timestamp_ms_offset)
            num_silences = int(tmp) // interval
            
            end_ow = time.time()

            # If the last ks is different from the ks, update the file
            # Clean features and repeat until the last ks is the same
            if last_ks != ks:            
                observationWindow = np.vstack([observationWindow,outFile])
                last_time = timestamp
                for x in range(0,num_silences):
                    observationWindow = np.vstack([observationWindow,np.zeros(9)])
                #Change to another observation window
                if end_ow - start_ow >= args.observationWindow :
                    result = define_observation(observationWindow, ow, args.windowOffset, file_obj)
                    classify(result)
                    start_ow = end_ow
                    observationWindow = np.empty(shape=[0, 8])                       
                num_silences = 0                        
                outFile = np.zeros(9)
                last_ks = (last_ks + 1)
                
            # Update the number of packets
            packets_amount += 1           

    except FileNotFoundError:
        print('\nFile not found. Program finished.')
        sys.exit()
    except Exception as e:
        print(e)
        print('\nCapture reading interrupted.')
        file_obj.close()

def classify(result):
    global args
    global history
    result = result.reshape(1, -1)
    result = np.delete(result, [2,3,6,7,10,11,13,14,15,20,21], axis=1)
    data = scaler[args.room].transform(result)
    flag = True
    for c in clf[args.room]:
        if flag:
            pred = c.predict(data).reshape(-1,1)
            flag = False
        else:
            pred = np.concatenate((pred, c.predict(data).reshape(-1,1)), axis=1)
    classification = decide(pred)
    history = history[1:4] + [int(classification[0])]
    if history.count(-1) > 2:
        print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"), " Anomaly detected!")
    else:
        print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"), " No anomalies.")
    print(pred)
    print(history)
    
def decide(pred):
    l = []
    for i in range(0, pred.shape[0]):
        col = pred[i,:]
        if col.tolist().count(-1) > math.ceil(pred.shape[1]/2):
            l.append(-1)
        else:
            l.append(1)
    return np.array(l)

def loadFromFiles(files):
    d = dict()
    for f in files:
        file = open(f, 'rb')
        room = os.path.basename(f).split('_')[1].split('.')[0]
        d[room] = pickle.load(file)
    return d

def main():

    global packets_amount
    # Packets amount in the capture
    packets_amount = 0 

    # Features to be written to the output file
    # [0] - IPv4 packets sum length
	# [1] - Number of TCP packets (IPv4)
	# [2] - Number of UDP packets (IPv4)
    # [3] - Number of other packets
	# [4] - IPv4 packets number (from pcs_ip to known_ip and vice-versa) 
	# [5] - IPv4 packets number (from pcs_ip to unknow ips and vice-versa)
    # [6] - Number of TCP SYN flags
	# [7] - Number of TCP FIN flags
    # [8] - Number of TCP sessions
    global outFile
    outFile = np.zeros(9)

    # Timestamp of the first packet
    global T0
    T0 = 0

    global last_time
    last_time = 0    

    parser = argparse.ArgumentParser(prog='python3 dataAcquisition.py', usage='%(prog)s [options]')
    parser.add_argument('-i','--interface', nargs='?', required=True, help='interface for monitoring')
    parser.add_argument('-si', '--samplingInterval', type=int, help=' time between which measurements are taken, or data is recorded (seconds)', default=1)
    parser.add_argument('-ow', '--observationWindow', required=True, type=int, help = 'time between decision making (seconds)')
    parser.add_argument('-wo', '--windowOffset', required=True, type=int, help = 'how many seconds the observation window drags')
    parser.add_argument("-c", "--clf", nargs='+', required='True')
    parser.add_argument("-s", "--scaler", nargs='+', required='True')
    parser.add_argument("-r", "--room", required='True')
    global args
    args=parser.parse_args()

    global interval
    interval = args.samplingInterval

    global ow
    ow = args.observationWindow

    global num_silences
    num_silences = 0

    global observationWindow
    observationWindow = np.empty(shape=[0, 9])

    global start_ow
    start_ow = time.time()

    global ks
    ks = 0

    #TCP sessions
    global TCP
    TCP = np.empty(shape=[0, 4], dtype=np.int64)

    global file_obj
    file_obj = open("afterProcessing.dat",'w')              

    global clf, scaler
    clf = loadFromFiles(args.clf)
    scaler = loadFromFiles(args.scaler)

    try:
        capture = pyshark.LiveCapture(interface=args.interface,bpf_filter='')
        capture.apply_on_packets(processPacket)
    except KeyboardInterrupt:
        print('\n{} packets captured! Done!\n'.format(packets_amount))

if __name__ == '__main__':   
    main()
