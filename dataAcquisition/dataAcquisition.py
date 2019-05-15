import sys
import argparse
import pyshark
import json
import time
from termcolor import colored
from geoip import geolite2

def main():

    # Start time to calculate execution time
    start_time = None

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
    outFile = [0, 0, 0, 0, 0, 0, 0, 0]

    # Timestamp of the first packet
    t0 = 0

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?', required=True, help='input file - captured .pcap filename')
    parser.add_argument('-o', '--output', nargs='?', required=True, help='output file')
    parser.add_argument('-si', '--samplingInterval', type=int, help=' time between which measurements are taken, or data is recorded (seconds)', default=1)
    args=parser.parse_args()

    interval = args.samplingInterval

    start_time = time.time()

    num_packets_for_window = 0

    # Process packets in file
    try:
        cap = pyshark.FileCapture(args.input, keep_packets=False)

        # Write in the file output
        with open(args.output,'w') as file_obj :

            # Iteration throgh packets
            for packet in cap :              

                # Get packet information
                number = packet.number
                captured_length = packet.captured_length
                packet_length = packet.length
                packet_time = packet.sniff_time 
                timestamp = packet.sniff_timestamp
                frame_info = packet.frame_info
                layers = packet.layers
                highest_layer = packet.highest_layer
                transport_layer = packet.transport_layer
                eth = packet.eth
                interface_captured = packet.interface_captured             

                # Get layer 1 information

                fields = frame_info._all_fields

                #print(fields)
                protocols = fields.get('frame.protocols')
                offset_shift = fields.get('frame.offset_shift')
                frame_number = fields.get('frame.number')
                time_epoch = fields.get('frame.time_epoch')
                frame_length = fields.get('frame.len')
                interface_id = fields.get('frame.interface_id')
                encapsulation_type = fields.get('frame.encap_type')
                capture_length = fields.get('frame.cap_len')

                # If encapsulation is ethernet
                if encapsulation_type=="1":
                    eth_raw_mode = eth.raw_mode
                    eth_layer_name = eth._layer_name
                    eth_fields = eth._all_fields
                    src = eth_fields["eth.src"]
                    dst = eth_fields["eth.dst"]
                    src_resolved = eth_fields["eth.src_resolved"]
                    dst_resolved = eth_fields["eth.dst_resolved"]
                    eth_type = eth_fields.get("eth.type")
                    lg = eth_fields["eth.lg"]
                    addr = eth_fields["eth.addr"]
                    addr_resolved = eth_fields["eth.addr_resolved"]
                    
                    # IPv4 Packet
                    if eth_type == "0x00000800" :
                        ipv4_packet = layers[1]

                        ipv4_layer_name = ipv4_packet._layer_name
                        ipv4_raw_mode = ipv4_packet.raw_mode
                        ipv4_all_fields = ipv4_packet._all_fields

                        ipv4_geoIp = ipv4_all_fields.get('')
                        ipv4_flags_mf = ipv4_all_fields.get('ip.flags.mf')
                        ipv4_len = ipv4_all_fields.get('ip.len')
                        ipv4_dst = ipv4_all_fields.get('ip.dst')
                        ipv4_protocol = ipv4_all_fields.get('ip.proto')
                        ipv4_host = ipv4_all_fields.get('ip.host')
                        ipv4_id = ipv4_all_fields.get('ip.id')
                        ipv4_flags_rb = ipv4_all_fields.get('ip.flags.rb')
                        ip_version = ipv4_all_fields.get('ip.version')
                        ip_checksum = ipv4_all_fields.get('ip.checksum.status')
                        ipv4_src = ipv4_all_fields.get('ip.src')
                        ipv4_dsfield_ecn = ipv4_all_fields.get('ip.dsfield.ecn')
                        ipv4_ttl = ipv4_all_fields.get('ip.ttl')
                        ipv4_src_host = ipv4_all_fields.get('ip.src_host')
                        ipv4_dst_host = ipv4_all_fields.get('ip.dst_host')
                        ip_addr = ipv4_all_fields.get('ip.addr')
                        ipv4_checksum = ipv4_all_fields.get('ip.checksum')
                        
                        # TCP packet
                        if ipv4_protocol=='6':
                            tcp_packet = layers[2]

                            tcp_layer_name = tcp_packet._layer_name
                            tcp_raw_mode = tcp_packet.raw_mode
                            tcp_all_fields = tcp_packet._all_fields

                            tcp_text = tcp_all_fields.get('')
                            tcp_flags_res = tcp_all_fields.get('tcp.flags.res')
                            tcp_flags_fin = tcp_all_fields.get('tcp.flags.fin')
                            tcp_flags_syn = tcp_all_fields.get('tcp.flags.syn')

                        # UDP
                        elif ipv4_protocol=="17":
                            udp_packet = layers[2]

                            udp_raw_mode = udp_packet.raw_mode
                            udp_layer_name = udp_packet._layer_name
                            udp_all_fields = udp_packet._all_fields

                            udp_port = udp_all_fields.get("udp.port")
                            udp_source_port = udp_all_fields.get("udp.srcport")
                            udp_checksum = udp_all_fields.get("udp.checksum")
                            udp_stream = udp_all_fields.get("udp.stream")
                            udp_destination_port = udp_all_fields.get("udp.dstport")
                            udp_length = udp_all_fields.get("udp.length")
                            udp_checksum_status = udp_all_fields.get("udp.checksum.status")

                            # DNS request
                            if len(layers)>3 and layers[3]._layer_name=='dns':
                                upper_layer = layers[3]

                        else:
                            print("Unrecognized transport protocol")
                            #print(ipv4_protocol)
                            #print(layers[2])
                    
                    elif eth_type != None :
                        # https://en.wikipedia.org/wiki/EtherType
                        # eth type = Ethernet Configuration Testing Protocol
                        print("Doesn't matter")
                        #print(colored(" Eth type : \n",'yellow'),eth_type)
                        #print(colored(" Eth content : \n",'yellow'),eth)                    
                        
                    else:
                        print(colored(" Frame info\n",'yellow'),frame_info)

                    # If packet is IPv4, update features
                    if encapsulation_type == "1" and eth_type == "0x00000800":
                        outFile[0] = outFile[0] + len(packet_length)
					
                        # If TCP, update features
                        if ipv4_protocol == "6" : 
                            outFile[1] += 1 # Count TCP packets
                            if tcp_flags_syn != "0":
                                outFile[6] += int(tcp_flags_syn)
                            if tcp_flags_fin != "0":
                                outFile[7] += int(tcp_flags_fin)                         
                        
                        # If UDP, update features
                        elif ipv4_protocol == "17" : 
                            outFile[2] += 1 # Count UDP packets
                        
                        # If other, update features
                        else: 
                            outFile[3] += 1 # Count other packets
   


                        # If the source ip is known and the destiny ip is known, update feature   
                        match_src = geolite2.lookup(ipv4_src)
                        match_dst = geolite2.lookup(ipv4_dst)
                        if (match_src is not None and match_dst is not None) and (match_src.continent == 'EU' or match_dst.continent == 'EU'): 
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
                    # print("KS : ",ks)
                    # print("Packets amount : ",packets_amount)

                    # If the last ks is different from the ks, update the file
                    # Clean features and repeat until the last ks is the same
                    if last_ks != ks:
                        outF_len = len(outFile)
                        for i in range(outF_len):
                            file_obj.write(str(outFile[i])+' ')
                            outFile[i] = 0
                        file_obj.write('\n')
                        
                        print("File updated")
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

if __name__ == '__main__':
	main()