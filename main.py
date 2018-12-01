#!/usr/bin/env python
import pyshark
import json
import sys
# pcap = pyshark.FileCapture('/Users/Mukhamed/Downloads/null_scan.pcap')

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
    # print(packets.layers)
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
    print("XMAS SCAN")
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

def run_udp_scan(packets):
    udp = ''
    result = []
    for pkt in packets:
        if('udp' in pkt and udp == ''):
            udp = pkt
        elif('icmp' in pkt and udp != '' and not isFoundResponseUDP(pkt, udp)):
            result.append(udp)
            udp = ''
        elif(udp != ''):
            result.append(udp)
            udp = ''
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
            print('--------------------')
            print("IP Address: ", source_ip, " -> ", destination_ip)
        print(pack.udp.dstport,  end=' ')
        index += 1
        if(index == 10):
            print('')
            index = 0

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

    source_ip = ''
    destination_ip = ''
    isOutput = False
    for pack in result:
        if(pack.ip.src != source_ip or pack.ip.dst != destination_ip):
            source_ip = pack.ip.src
            destination_ip = pack.ip.dst
            isOutput = False
        if(not isOutput):
            print('IP Address: ', pack.ip.src, ' -> ', pack.ip.dst)
            isOutput = True

def run_half_open_scan(packets):
    tcp_client_packets = ''
    tcp_result = []
    source_id = ''
    destination_ip = ''
    ip_addresses = []
    for pack in packets:
        if(pack.tcp.flags == '0x00000002'):
            tcp_client_packets = pack;
        else:
            if(tcp_client_packets != '' and pack.tcp.flags == '0x00000014' and isFoundResponse(tcp_client_packets, pack)):
                tcp_result.append(pack);
                if(source_id != pack.ip.src or destination_ip != pack.ip.dst):
                    source_id = pack.ip.src
                    destination_ip = pack.ip.dst
                    ip_addresses.append(pack)
            tcp_client_packets = ''
    print("The number of scans: ", len(tcp_result));
    print("All Half Open Scan Ports:")
    for address in ip_addresses:
        print("IP Address: ", address.ip.src, " -> ", address.ip.dst)
        index = 0
        for pack in tcp_result:
            print(pack.tcp.port, end=' ')
            index += 1
            if(index == 10):
                print('')
                index = 0

def run_program():
    filtered_pcap = ''
    if(sys.argv[1] == 'icmpecho.pcap'):
        filtered_pcap = pyshark.FileCapture('{}/{}'.format(sys.path[0], sys.argv[1]), display_filter='icmp');
        run_icmp_echo_scan(filtered_pcap)
    elif(sys.argv[1] == 'null_scan.pcap'):
        filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(sys.path[0], sys.argv[1]), display_filter='tcp');
        run_null_scan(filtered_pcap)
    elif(sys.argv[1] == 'udp_scan.pcap'):
        filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(sys.path[0], sys.argv[1]), display_filter='icmp || udp');
        run_udp_scan(filtered_pcap)
    elif(sys.argv[1] == 'xmas_scan.pcap'):
        filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(sys.path[0], sys.argv[1]), display_filter='tcp');
        run_xmas_scan(filtered_pcap)
    elif(sys.argv[1] == 'halfopen.pcap'):
        filtered_pcap = filtered_pcap = pyshark.FileCapture('{}/{}'.format(sys.path[0], sys.argv[1]), display_filter='tcp');
        run_half_open_scan(filtered_pcap)
    else:
        print('The directory does not exist such file.')

run_program();
