import sys
import argparse
import pyshark
import json
import time
from termcolor import colored
import netifaces as ni

def main():
    
    print( colored(' First version of detection of mac spofing','green'), colored("\n Time :" + time.strftime(" %d-%m-%Y %H:%M:%S",time.gmtime()),'green') )
    print(colored(" Your Computer IP Address is : ",'yellow'),ni.ifaddresses(ni.interfaces()[2])[ni.AF_INET][0]['addr'])
    print(colored(" The information about the interface %s is : \n",'yellow') % ( ni.interfaces()[2]), ni.ifaddresses(ni.interfaces()[2]))  
    print(colored(" Computer interfaces \n",'yellow'),ni.interfaces())

    # Start time to calculate execution time
    start_time = None

    # Packets amount in the capture
    packets_amount = 0

    # Features to be written to the output file
	# [1] - Number of ARP packets
	# [2] - Number of TCP packets (IPv4)
	# [3] - Number of UDP packets (IPv4)
	# [4] - Number of other packets (IPv4)
	# [5] - IPv4 packets number (from pcs_ip to another_pcs_ip)
	# [7] - IPv4 packets number (from hosts_ip to unknow ips)
	# [8] - Number of DNS packets
	# [9] - Number of ICMP packets    

    outFile = [0, 0, 0, 0, 0, 0, 0, 0, 0]

    # Timestamp of the first packet
    t0 = 0

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?', required=True, help='input file - captured .pcap filename')
    parser.add_argument('-o', '--output', nargs='?', required=True, help='output file')
    parser.add_argument('-si', '--samplingInterval', type=int, help=' time between which measurements are taken, or data is recorded (seconds)', default=1)
    parser.add_argument('-ow', '--observationWindow', type=int, help=' observation window (seconds)', default=300)
    args=parser.parse_args()

    interval = args.samplingInterval
    window = args.observationWindow

    start_time = time.time()

    # Process packets in file
    try:
        cap = pyshark.FileCapture(args.input, keep_packets=False)

        # List all attributes from capture
        # print(dir(cap))

        # print("\n")

        # List all attributes from packet
        # print(dir(cap[0]))

        # Write in the file output
        with open(args.output,'w') as file_obj :

            # Iteration throgh packets
            for packet in cap :

                # print(packet.__dict__) 
                # ONE example result -> {'layers': [<ETH Layer>, <IP Layer>, <TCP Layer>], 'frame_info': <FRAME Layer>, 'number': '3611', 
                # 'interface_captured': None, 'captured_length': '66', 'length': '66', 'sniff_timestamp': '1553699065.282865000'}

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

                # print(frame_info.__dict__)
                print(colored("\n Layers : \n", 'yellow'),layers)

                raw_mode = frame_info.raw_mode
                layer_name = frame_info._layer_name
                fields = frame_info._all_fields

                protocols = fields.get('frame.protocols')
                offset_shift = fields.get('frame.offset_shift')
                frame_number = fields.get('frame.number')
                time_epoch = fields.get('frame.time_epoch')
                frame_length = fields.get('frame.len')
                time_delta = fields.get('frame.time_delta')
                interface_id = fields.get('frame.interface_id')
                frame_ignored = fields.get('frame.ignored')
                encapsulation_type = fields.get('frame.encap_type')
                marked = fields.get('frame.marked')
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

                    #ARP
                    if eth_type == "0x00000806" :
                        arp_packet = layers[1]
                        print(colored(" ARP Packet\n",'yellow'),arp_packet)

                        arp_layer_name = arp_packet._layer_name
                        arp_raw_mode = arp_packet.raw_mode
                        arp_fields = arp_packet._all_fields

                        arp_opcode = arp_fields.get("arp.opcode")
                        arp_hw_size = arp_fields.get("arp.hw.size")
                        arp_src_hw_mac = arp_fields.get("arp.src.hw_mac")
                        arp_src_proto_ipv4 = arp_fields.get("arp.src.proto_ipv4")
                        arp_proto_type = arp_fields.get("arp.proto.type")
                        arp_dst_hw_max = arp_fields.get("arp.dst.hw_mac")
                        arp_proto_size = arp_fields.get("arp.proto.size")
                        arp_dst_proto_ipv4 = arp_fields.get("arp.dst.proto_ipv4")
                        arp_hw_type = arp_fields.get("arp.hw.type")
                    
                    # IPv4 Packet
                    elif eth_type == "0x00000800" :
                        ipv4_packet = layers[1]
                        print(colored("\n IPv4 Packet\n",'yellow'),ipv4_packet)
                        # print(colored(" IPv4 Packet dict\n",'yellow'),ipv4_packet.__dict__)

                        ipv4_layer_name = ipv4_packet._layer_name
                        ipv4_raw_mode = ipv4_packet.raw_mode
                        ipv4_all_fields = ipv4_packet._all_fields

                        ipv4_geoIp = ipv4_all_fields.get('')
                        ipv4_flags_mf = ipv4_all_fields.get('ip.flags.mf')
                        ipv4_len = ipv4_all_fields.get('ip.len')
                        ipv4_frag_offset = ipv4_all_fields.get('ip.frag_offset')
                        ipv4_dst = ipv4_all_fields.get('ip.dst')
                        ipv4_protocol = ipv4_all_fields.get('ip.proto')
                        ipv4_dsfield_dscp = ipv4_all_fields.get('ip.frag_offset')
                        ipv4_dsfield = ipv4_all_fields.get('ip.dsfield')
                        ipv4_hdr_len = ipv4_all_fields.get('ip.hdr_len')
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
                        ipv4_flags_df = ipv4_all_fields.get('ip.flags.df')
                        ipv4_flags = ipv4_all_fields.get('ip.flags')
                        ip_addr = ipv4_all_fields.get('ip.addr')
                        ipv4_checksum = ipv4_all_fields.get('ip.checksum')                    

                        # TCP packet
                        if ipv4_protocol=='6':
                            tcp_packet = layers[2]
                            print(colored("\n TCP Packet\n",'yellow'),tcp_packet)
                            # print(colored(" TCP Packet dict\n",'yellow'),tcp_packet.__dict__)

                            tcp_layer_name = tcp_packet._layer_name
                            tcp_raw_mode = tcp_packet.raw_mode
                            tcp_all_fields = tcp_packet._all_fields

                            tcp_text = tcp_all_fields.get('')
                            tcp_timestamp_tsval = tcp_all_fields.get('tcp.options.timestamp.tsval')
                            tcp_flags_res = tcp_all_fields.get('tcp.flags.res')
                            tcp_flags_fin = tcp_all_fields.get('tcp.flags.fin')
                            tcp_flags_syn = tcp_all_fields.get('tcp.flags.syn')
                            tcp_type_class = tcp_all_fields.get('tcp.options.type.class')
                            tcp_flags_push = tcp_all_fields.get('tcp.flags.push')
                            tcp_nxtseq = tcp_all_fields.get('tcp.nxtseq')
                            tcp_flags_ns = tcp_all_fields.get('tcp.flags.ns')
                            tcp_port = tcp_all_fields.get('tcp.port')
                            tcp_window_size_value = tcp_all_fields.get('tcp.window_size_value')
                            tcp_src_port = tcp_all_fields.get('tcp.srcport')
                            tcp_timestamp_tsecr = tcp_all_fields.get('tcp.options.timestamp.tsecr')
                            tcp_ack = tcp_all_fields.get('tcp.ack')
                            tcp_stream = tcp_all_fields.get('tcp.stream')
                            tcp_flags = tcp_all_fields.get('tcp.flags')
                            tcp_analysis_push_bytes_sent = tcp_all_fields.get('tcp.analysis.push_bytes_sent')
                            tcp_urgent_pointer = tcp_all_fields.get('tcp.urgent_pointer')
                            tcp_flags_ack = tcp_all_fields.get('tcp.flags.ack')
                            tcp_flags_cwr = tcp_all_fields.get('tcp.flags.cwr')
                            tcp_checksum_status = tcp_all_fields.get('tcp.checksum.status')
                            tcp_window_size = tcp_all_fields.get('tcp.window_size')
                            tcp_flags_ecn = tcp_all_fields.get('tcp.flags.ecn')
                            tcp_options = tcp_all_fields.get('tcp.options')
                            tcp_type_copy = tcp_all_fields.get('tcp.options.type.copy')
                            tcp_flags_urg = tcp_all_fields.get('tcp.flags.urg')
                            tcp_analysis_bytes_in_flight = tcp_all_fields.get('tcp.analysis.bytes_in_flight')
                            tcp_length = tcp_all_fields.get('tcp.len')
                            tcp_window_size_scale_factor = tcp_all_fields.get('tcp.window_size_scalefactor')
                            tcp_segment_data = tcp_all_fields.get('tcp.segment_data')
                            tcp_seg = tcp_all_fields.get('tcp.seq')
                            tcp_reset = tcp_all_fields.get('tcp.flags.reset')
                            tcp_hdr_len = tcp_all_fields.get('tcp.hdr_len')
                            tcp_options_len = tcp_all_fields.get('tcp.option_len')
                            tcp_option_kind = tcp_all_fields.get('tcp.option_kind')
                            tcp_dstport = tcp_all_fields.get('tcp.dstport')
                            tcp_checksum = tcp_all_fields.get('tcp.checksum')
                            tcp_flags_str = tcp_all_fields.get('tcp.flags.str')
                            tcp_options_type = tcp_all_fields.get('tcp.options.type')
                            tcp_type_number = tcp_all_fields.get('tcp.options.type.number')
                            tcp_analysis = tcp_all_fields.get('tcp.analysis')
                            tcp_ws_expert_severity = tcp_all_fields.get('_ws.expert.severity')
                            tcp_ws_expert_message = tcp_all_fields.get('_ws.expert.message')
                            tcp_ws_expert = tcp_all_fields.get('_ws.expert')
                            tcp_ws_expert_group = tcp_all_fields.get('_ws.expert.group')
                            tcp_checksum = tcp_all_fields.get('tcp.checksum')
                            tcp_analysis_ack_frame = tcp_all_fields.get('tcp.analysis.acks_frame')

                        # UDP
                        elif ipv4_protocol=="17":
                            udp_packet = layers[2]
                            print(colored("\n UDP Packet\n",'yellow'),udp_packet)
                            # print(colored(" UDP Packet dict\n",'yellow'),udp_packet.__dict__)

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

                        # ICMP
                        elif ipv4_protocol=="1":
                            icmp_packet = layers[2]

                        else:
                            print("Unrecognized transport protocol")
                            print(ipv4_protocol)
                            print(layers[2])
                            print(layers[2].__dict__)

                    # Ipv6 packet
                    elif eth_type=="0x000086dd":
                        ipv6_packet = layers[1]
                        print(colored("\n IPv6 Packet\n",'yellow'),ipv6_packet)
                        # print(colored(" IPv6 Packet dict\n",'yellow'),ipv6_packet.__dict__)

                        ipv6_raw_mode = ipv6_packet.raw_mode
                        ipv6_layer_name = ipv6_packet._layer_name
                        ipv6_all_fields = ipv6_packet._all_fields

                        ipv6_text = ipv6_all_fields.get('')
                        ipv6_tclass = ipv6_all_fields.get('ipv6.tclass')
                        ipv6_version = ipv6_all_fields.get('ipv6.version')
                        ipv6_payload_length = ipv6_all_fields.get('ipv6.plen')
                        ipv6_host = ipv6_all_fields.get('ipv6.host')
                        ip_version = ipv6_all_fields.get('ip.version')
                        ipv6_src_host = ipv6_all_fields.get('ipv6.src_host')
                        ipv6_tclass_dscp = ipv6_all_fields.get('ipv6.tclass.dscp')
                        ipv6_nxt = ipv6_all_fields.get('ipv6.nxt')
                        ipv6_dst = ipv6_all_fields.get('ipv6.dst')
                        ipv6_src = ipv6_all_fields.get('ipv6.src')
                        ipv6_hop_limit = ipv6_all_fields.get('ipv6.hlim')
                        ipv6_dst_host = ipv6_all_fields.get('ipv6.dst_host')
                        ipv6_addr = ipv6_all_fields.get('ipv6.addr')
                        ipv6_tclass_ecn = ipv6_all_fields.get('ipv6.tclass.ecn')
                        ipv6_flow = ipv6_all_fields.get('ipv6.flow')
                    
                    elif eth_type != None :
                        # https://en.wikipedia.org/wiki/EtherType
                        # eth type = Ethernet Configuration Testing Protocol
                        print(colored(" Eth type : \n",'yellow'),eth_type)
                        print(colored(" Eth content : \n",'yellow'),eth)                    
                    
                    else:
                        print(colored(" Frame info\n",'yellow'),frame_info)

                    # If is first packet, get the first timestamp
                    if packets_amount==0:
                        T0 = float(timestamp)
                        last_ks = -1
                    else:
                        # Save the last ks
                        last_ks = ks

                    # Update the ks
                    ks=int((float(timestamp)-T0)/interval)%window
                    print("---------------------------------------------------")
    except FileNotFoundError:
        print('\nFile not found. Program finished.')
        sys.exit()
    except Exception as e:
        print(e)
        print('\nCapture reading interrupted.')

if __name__ == '__main__':
	main()