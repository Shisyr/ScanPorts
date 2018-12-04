#!/usr/bin/env python
import pyshark
import json
import sys
import os

def isFoundResponse(packet, packet2):
    isSimilarIP = packet.ip.src == packet2.ip.dst and packet.ip.dst == packet2.ip.src
    isSimilarPort = packet.tcp.port == packet2.tcp.dstport and packet.tcp.dstport == packet2.tcp.port
    return isSimilarIP and isSimilarPort

def isFoundResponseUDP(packet, packet2):
    isSimilarIP = packet.icmp.ip_src == packet2.ip.src and packet.icmp.ip_dst == packet2.ip.dst
    isSimilarPort = packet.icmp.udp_port == packet2.udp.port and packet.icmp.udp_dstport == packet2.udp.dstport
    return isSimilarIP and isSimilarPort

def isFoundResponseICMP(packet, packet2):
    isSimilarIP = packet.ip.src == packet2.ip.dst and packet.ip.dst == packet2.ip.src
    return isSimilarIP

def run_null_scan(packets):
    pkt_request = '';
    result = []
    for pkt in packets:
        isOpenPort = True
        if(pkt_request == '' and pkt['tcp'].flags == '0x00000000'):
            pkt_request = pkt;
        elif(pkt_request != '' and pkt['tcp'].flags == '0x00000004' and isFoundResponse(pkt_request, pkt)):
            isOpenPort = False;
            pkt_request = ''
        elif(pkt_request != ''):
            result.append(pkt_request)
            if(pkt['tcp'].flags == '0x00000000'):
                pkt_request = pkt;
            else:
                pkt_request = ''
    if(len(result) > 0):
        print("NULL SCAN:")
        print("The number of scanned packets: ", len(result));
        index = 0
        source_ip = ''
        destination_ip = ''
        for pack in result:
            if(pack.ip.src != source_ip or pack.ip.dst != destination_ip):
                source_ip = pack.ip.src
                destination_ip = pack.ip.dst
                print("IP Address: ", source_ip, " -> ", destination_ip);
            print(pack.tcp.dstport, end=' ')
            index += 1
            if(index == 10):
                print('')
                index = 0
        print('')
        print('END---------------------------------------------------END')
    else:
        print("NULL SCAN:")
        print("The number of scanned packets: ", len(result));

def run_xmas_scan(packets):
    pkt_request = ''
    result = []
    for pkt in packets:
        isOpenPort = True
        if(pkt_request == '' and int(pkt['tcp'].flags, 16) == 41):
            pkt_request = pkt
        elif(pkt_request != '' and pkt['tcp'].flags == '0x00000004' and isFoundResponse(pkt_request, pkt)):
            isOpenPort = False
            pkt_request = ''
        elif(pkt_request != '' and isOpenPort):
            result.append(pkt_request)
            if(int(pkt['tcp'].flags, 16) == 41):
                pkt_request = pkt;
            else:
                pkt_request = ''
    if(len(result) > 0):
        print("XMAS SCAN:")
        print("The number of packets: ", len(result));
        print('Scanned Ports: ')
        index = 0;
        source_ip = ''
        destination_ip = ''
        for pack in result:
            if(pack.ip.src != source_ip or destination_ip != pack.ip.dst):
                source_ip = pack.ip.src
                destination_ip = pack.ip.dst
                print("IP Address: ", source_ip, " -> ", destination_ip)
            print(pack.tcp.dstport, end=' ')
            index += 1
            if(index == 10):
                print('')
                index = 0
        print('')
        print('END---------------------------------------------------END')
    else:
        print('XMAS SCAN:')
        print('The Number of packets: ', len(result))

def run_udp_scan(packets):
    udp = ''
    result = []
    for pkt in packets:
        if('udp' in pkt and not ('dns' in pkt) and udp == ''):
            udp = pkt
        elif('icmp' in pkt and udp != '' and not isFoundResponseUDP(pkt, udp)):
            result.append(udp)
            udp = ''
        elif(udp != ''):
            result.append(udp)
            udp = ''
    if(len(result) > 0):
        print("UDP SCAN:")
        print("The number of scanned packets: ", len(result));
        index = 0
        source_ip = ''
        destination_ip = ''
        for pack in result:
            if(pack.ip.src != source_ip or pack.ip.dst != destination_ip):
                source_ip = pack.ip.src;
                destination_ip = pack.ip.dst;
                print('')
                print("IP Address: ", source_ip, " -> ", destination_ip)
            print(pack.udp.dstport,  end=' ')
            index += 1
            if(index == 10):
                print('')
                index = 0
        print('')
        print('END---------------------------------------------------END')
    else:
        print('UDP SCAN:')
        print("The number of scanned packets: ", len(result));

def run_icmp_echo_scan(packets):
    pkt_request = ''
    result = []
    for pkt in packets:
        if(pkt_request == '' and pkt.icmp.type == '8'):
            pkt_request = pkt
        else:
            if(pkt.icmp.type == '0' and isFoundResponseICMP(pkt_request, pkt)):
                result.append(pkt_request);
            pkt_request = ''
    if(len(result) > 0):
        source_ip = ''
        destination_ip = ''
        isOutput = False
        print('ICMP ECHO')
        print("The number of scanned packets: ", len(result));
        for pack in result:
            if(pack.ip.src != source_ip or pack.ip.dst != destination_ip):
                source_ip = pack.ip.src
                destination_ip = pack.ip.dst
                isOutput = False
            if(not isOutput):
                print('IP Address: ', pack.ip.src, ' -> ', pack.ip.dst)
                isOutput = True
        print('')
        print('END---------------------------------------------------END')
    else:
        print('ICMP ECHO')
        print("The number of scanned packets: ", len(result));

def run_half_open_scan(packets):
    tcp_client_packets = ''
    tcp_result = []
    for pack in packets:
        if(pack.tcp.flags == '0x00000002'):
            tcp_client_packets = pack;
        else:
            if(tcp_client_packets != '' and pack.tcp.flags == '0x00000014' and isFoundResponse(tcp_client_packets, pack)):
                tcp_result.append(pack);
            tcp_client_packets = ''
    if(len(tcp_result) > 0):
        source_ip = ''
        destination_ip = ''
        index = 0
        print('HALF OPEN SCAN:')
        print("The number of scans: ", len(tcp_result));
        print("All Half Open Scan Ports:")
        for pack in tcp_result:
            if(source_ip != pack.ip.src or destination_ip != pack.ip.dst):
                source_ip = pack.ip.src;
                destination_ip = pack.ip.dst;
                print("IP Address: ", source_ip, " -> ", destination_ip)
            print(pack.tcp.port, end=' ')
            index += 1
            if(index == 10):
                print('')
                index = 0
        print('')
        print('END---------------------------------------------------END')
    else:
        print('HALF OPEN SCAN:')
        print("The number of scans: ", len(tcp_result));

def run_program():
    filtered_pcap = pyshark.FileCapture('{}/{}'.format(os.getcwd(), sys.argv[1]), display_filter='icmp');
    run_icmp_echo_scan(filtered_pcap)
    filtered_pcap.close()
    filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(os.getcwd(), sys.argv[1]), display_filter='tcp');
    run_null_scan(filtered_pcap)
    filtered_pcap.close()
    filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(os.getcwd(), sys.argv[1]));
    run_udp_scan(filtered_pcap)
    filtered_pcap.close()
    filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(os.getcwd(), sys.argv[1]), display_filter='tcp');
    run_xmas_scan(filtered_pcap)
    filtered_pcap.close()
    filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(os.getcwd(), sys.argv[1]), display_filter='tcp');
    run_half_open_scan(filtered_pcap)
    filtered_pcap.close()

run_program();
