from scapy.all import *
import sys
isFirst = False
def handle_packet(packet):
    print("got packet")
  
    try:
        if packet[Raw].load is not None:
            packet[Raw].load = '\x69'
        print(packet.show())
    except:
        print("error")
    #send(packet)
    '''
    if( packet[TCP].flags == 'SA' or packet[TCP].flags == 'S' or packet[TCP].flags == 'A'):
        print("found handshake")
        print(packet.show())
        isFirst = True
        packet[Ether].dst = "00:50:56:b9:fd:bd"
        resp_packet = send(packet)
    else:
        print("found not handshake")
        print(packet.show())
    '''
    '''
    elif ((packet[IP].src == "10.10.10.4" and packet[IP].dst == "10.10.10.3")):
        print("Captured a packet:")
        print(packet.show())
        packet[IP].src = "10.10.10.89"
        packet[Ether].src = "00:50:56:b9:ca:53"
        packet[Ether].dst = "00:50:56:b9:fd:bd"
        print("New packet:")
        print(packet.show())
        print("Sending packet")
        resp_packet = sr(packet, timeout=1)
        #print("Response:")
        #print(resp_packet.show())
    if (packet[IP].src == "10.10.10.4" and packet[IP].dst == "10.10.10.89"):
        print("Captured altered packet from 10.10.10.4:")
        print(packet.show())
        packet[IP].src = "10.10.10.89"
        packet[IP].dst = "10.10.10.3"
        print("New altered packet:")
        print(packet.show())
        print("Sending packet")
        resp_packet = sr1(packet, timeout=1)
        #print("Response:")
        #print(resp_packet.show())
        '''
    '''
    elif (packet[IP].src == "10.10.10.3" and packet[IP].dst == "10.10.10.89"):
        print("Captured altered packet from 10.10.10.3:")
        print(packet.show())
        packet[IP].src = "10.10.10.3"
        packet[IP].dst = "10.10.10.4"
        packet[Ether].dst = "00:50:56:b9:9a:67"
        print("New altered packet:")
        print(packet.show())
        print("Sending packet")
        resp_packet = sr1(packet, timeout=1)
        #print("Response:")
        #print(resp_packet.show())
    '''    

p = sniff(prn=handle_packet, filter='tcp port 445')
wrpcap('sniffed.pcap',p)

