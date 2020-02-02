import socket
from netfilterqueue import NetfilterQueue
import os
from scapy.all import *

iptablesr = "iptables -I INPUT -d 192.168.19.0/24 -j NFQUEUE --queue-num 1"


print("Adding iptable rules")
print(iptablesr)
os.system(iptablesr)

def callback(packet):
    data = packet.get_payload()
    pkt = IP(data)
    print(pkt.show())

def main():
    q = NetfilterQueue()
    q.bind(1, callback)
    #q.set_callback(callback)
    s = socket.fromfd(q.get_fd(), socket.AF_INET, socket.SOCK_STREAM)
    try:
        q.run_socket(s)
    except KeyboardInterrupt:
        q.unbind()
        print("flushing tables")
        os.system('iptables -F')
        os.system('iptables -X')

if __name__ == "__main__":
    main()
