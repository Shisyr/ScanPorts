import pyshark
import json
import sys
# pcap = pyshark.FileCapture('/Users/Mukhamed/Downloads/null_scan.pcap')
filtered_pcap = pyshark.FileCapture('{}/{}'.format(sys.path[0], sys.argv[1]));

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
    for pkt in packets:
        isOpenPort = True
        if('tcp' in pkt and pkt['tcp'].flags == '0x00000000'):
            for pkt2 in packets:
                if('tcp' in pkt2 and isFoundResponse(pkt, pkt2)):
                    isOpenPort = False
                    break
            if(isOpenPort):
                print(pkt)

def run_xmas_scan(packets):
    for pkt in packets:
        isOpenPort = True
        if('tcp' in pkt and int(pkt['tcp'].flags, 16) == 41):
            for pkt2 in packets:
                if('tcp' in pkt2 and isFoundResponse(pkt, pkt2)):
                    isOpenPort = False
                    break
            if(isOpenPort):
                print(pkt)



def run_udp_scan(packets):
    udp_array = []
    icmp_array = []
    for pkt in packets:
        if('icmp' in pkt):
            icmp_array.append(pkt)
        elif('udp' in pkt):
            udp_array.append(pkt)
    for udp in udp_array:
        isOpenPort = True
        for icmp in icmp_array:
            if(isFoundResponseUDP(icmp, udp)):
                isOpenPort = False
                break
        if(isOpenPort):
            print(udp)


def run_icmp_echo_scan(packets):
    for pkt in packets:
        isHasResponse = False
        if('icmp' in pkt):
            response = ''
            for pkt2 in packets:
                if('icmp' in pkt2 and isFoundResponseICMP(pkt, pkt2)):
                    isHasResponse = True
                    response = pkt2
                    break
            if(isHasResponse):
                print(pkt.ip)
                print(response.ip)


def run_half_open_scan(packets):
    tcp_packets = []
    for pack in packets:
        if('tcp' in pack and (pack.tcp.flags == '0x00000002' or pack.tcp.flags == '0x00000014')):
            tcp_packets.append(pack)
    for pkt in tcp_packets:
        isHalfOpenPort = False;
        if(pkt.tcp.flags == '0x00000002'):
            response = ''
            for pkt2 in tcp_packets:
                if(pkt2.tcp.flags == '0x00000014'):
                    if(isFoundResponse(pkt, pkt2)):
                        isHalfOpenPort = True;
                        response = pkt2
                        break;
            if(isHalfOpenPort):
                print('Start')
                print('--------------------------------------')
                print('| ',pkt.ip.src, ' -> ', pkt.ip.dst, ' |')
                print('| ', pkt.tcp.port, ' -> ', pkt.tcp.dstport, '                  |');
                print('| ---------------------------------- |')
                print('| ', pkt2.ip.src, ' -> ', pkt2.ip.dst, ' |');
                print('| ', pkt2.tcp.port, ' -> ', pkt2.tcp.dstport, '                  |');
                print('--------------------------------------')
                print('End')

def run_program():
    if(sys.argv[1] == 'icmpecho.pcap'):
        run_icmp_echo_scan(filtered_pcap)
    elif(sys.argv[1] == 'null_scan.pcap'):
        run_null_scan(filtered_pcap)
    elif(sys.argv[1] == 'udp_scan.pcap'):
        run_udp_scan(filtered_pcap)
    elif(sys.argv[1] == 'xmas_scan.pcap'):
        run_xmas_scan(filtered_pcap)
    elif(sys.argv[1] == 'halfopen.pcap'):
        run_half_open_scan(filtered_pcap)
    else:
        print('The directory does not exist such file.')

run_program();
