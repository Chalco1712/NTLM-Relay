import socket
from netfilterqueue import NetfilterQueue
import os
from scapy.all import *

#iptablesr = "iptables -A FORWARD -i eth0 -j ACCEPT"
#iptablesr2 = "iptables -t nat -A PREROUTING -i eth0 -p icmp -j NFQUEUE --queue-num 1"
#iptablesr = "iptables -I INPUT -p tcp --dport 445 -j NFQUEUE --queue-num 1"
iptablesr2 = "iptables -I INPUT -i eth0 -j NFQUEUE --queue-num 1"
#iptablesr2 = "iptables -A OUTPUT -j NFQUEUE --queue-num 1"
#iptablesr = "iptables -t nat -A PREROUTING -i eth0 -p icmp -j NFQUEUE --queue-num 1"
#iptablesr2 = "iptables -"

print("Adding iptable rules")
#print(iptablesr)
print(iptablesr2)
#os.system(iptablesr)
os.system(iptablesr2)

def callback(packet):
    data = packet.get_payload()
    pkt = IP(data)
    print(pkt.show())
    packet.drop()
    #packet.set_payload(raw(pkt))
    #packet.accept()

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
