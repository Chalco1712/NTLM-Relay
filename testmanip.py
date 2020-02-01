from scapy.all import *
import sys

def handle_packet(packet):
    if ((packet[IP].src == "10.10.10.3" and packet[IP].dst == "10.10.10.4") or (packet[IP].src == "10.10.10.4" and packet[IP].dst == "10.10.10.3")):
        print("Captured a packet:")
        print(packet.show())
        packet[IP].src = "10.10.10.89"
        print("New packet:")
        print(packet.show())
        print("Sending packet")
        resp_packet = sr(packet)
        print("Response:")
        print(resp_packet.show())
    if (packet[IP].src == "10.10.10.4" and packet[IP].dst == "10.10.10.89"):
        print("Captured altered packet from 10.10.10.4:")
        print(packet.show())
        packet[IP].src = "10.10.10.89"
        packet[IP].dst = "10.10.10.3"
        print("New altered packet:")
        print(packet.show())
        print("Sending packet")
        resp_packet = sr(packet)
        print("Response:")
        print(resp_packet.show())
    if (packet[IP].src == "10.10.10.3" and packet[IP].dst == "10.10.10.89"):
        print("Captured altered packet from 10.10.10.3:")
        print(packet.show())
        packet[IP].src = "10.10.10.89"
        packet[IP].dst = "10.10.10.4"
        print("New altered packet:")
        print(packet.show())
        print("Sending packet")
        resp_packet = sr(packet)
        print("Response:")
        print(resp_packet.show())
        

sniff(prn=handle_packet, filter='ip')

