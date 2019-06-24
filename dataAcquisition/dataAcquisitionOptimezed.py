import sys
import argparse
import pyshark
import json
import time
import math
import pygeoip
from geopy.distance import geodesic
import os
import numpy as np
from netaddr import IPNetwork, IPAddress

def main():
    # DETI coordinates
    local_coords = (40.633184, -8.659476)

    # GeoIP data
    geoip_data = pygeoip.GeoIP('GeoLiteCity.dat')

    # IP address wildcard for the captured machine
    ip_wildcard = '192.168.8.'

    # Start time to calculate execution time
    start_time = None

    # Packets amount in the capture
    packets_amount = 0

    #Number of TCP sessions
    TCP = []

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
    outFile = np.zeros(9)

    last_time = 0     
    num_silences = 0

    # Timestamp of the first packet
    t0 = 0

    parser = argparse.ArgumentParser()
    parser.add_argument('-id', '--inputdirectory', required=True, help='input directory - captured .pcap filenames') 
    parser.add_argument('-od', '--outputdirectory', required=True, help='output directory')    
    parser.add_argument('-si', '--samplingInterval', type=int, help=' time between which measurements are taken, or data is recorded (seconds)', default=1)
    args=parser.parse_args()

    interval = args.samplingInterval

    start_time = time.time()

    num_packets_for_window = 0
    for path, dirs, files in os.walk(args.inputdirectory):
        for filename in files:
            # Write in the file output
            f = filename.replace("pcap","dat")
            print("\n>>> Initiate "+filename)
            file_obj = open(args.outputdirectory+"/"+f,'w')            
            # Process packets in file
            try:
                cap = pyshark.FileCapture(path+"/"+filename, keep_packets=False)
                timestamp_ms_offset = None
                # Iteration through packets
                for packet in cap :              

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
                            
                            #print(ipv4_all_fields)
                            
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
                                if tcp_flags_syn != "0 " and tcp_flags_syn != None:
                                    outFile[6] += int(tcp_flags_syn)
                                if tcp_flags_fin != "0" and tcp_flags_fin != None:
                                    outFile[7] += int(tcp_flags_fin)
                                print(TCP)                             
                                if [ipv4_src,tcp_src_port,ipv4_dst,tcp_dst_port] not in TCP :
                                    if [ipv4_dst,tcp_dst_port,ipv4_src,tcp_src_port] not in TCP :
                                        print('IP packet from {} (TCP:{}) to {} (TCP:{}) '.format(IPAddress(ipv4_src),tcp_src_port,IPAddress(ipv4_dst),tcp_dst_port))
                                        TCP.append([ipv4_src,tcp_src_port,ipv4_dst,tcp_src_port])
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

                        if packets_amount == 0 :
                            last_time = timestamp 

                        tmp = math.floor(timestamp-timestamp_ms_offset)-math.ceil(last_time-timestamp_ms_offset)
                        num_silences = int(tmp) // interval

                        # If the last ks is different from the ks, update the file
                        # Clean features and repeat until the last ks is the same
                        if last_ks != ks:
                            print(outFile[1])
                            print("TCP size : %d"%len(TCP))
                            TCP = []                                             
                            outF_len = len(outFile)
                            for i in range(outF_len):
                                file_obj.write(str(int(outFile[i]))+' ')
                                #print(outFile[i])
                                outFile[i] = 0
                            file_obj.write('\n')
                            last_time = timestamp
                            for x in range(0,num_silences):
                                file_obj.write("0 0 0 0 0 0 0 0 \n")
                            num_silences = 0                        
                            outFile = np.zeros(9)
                            last_ks = (last_ks + 1)
                            last_num_packets = 0
                        
                        # Update the number of packets
                        packets_amount += 1
                        num_packets_for_window += 1

            except FileNotFoundError:
                print('\nFile not found. Program finished.')
                sys.exit()
            except Exception as e:
                print(e)
                print('\nCapture reading interrupted.')

            start_time = None
            packets_amount = 0
            outFile = np.zeros(8)
            last_time = 0     
            num_silences = 0
            t0 = 0
            start_time = time.time()
            num_packets_for_window = 0
            file_obj.close()
            cap.close()            
            print(">>> {} concluded\n".format(filename))
        print(">>> All Done")    

if __name__ == '__main__':
	main()