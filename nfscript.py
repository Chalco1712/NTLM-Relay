import socket
from netfilterqueue import NetfilterQueue
import os
from scapy.all import *

#iptablesr = "iptables -A FORWARD -i eth0 -j ACCEPT"
chains = "iptables -N client-incoming"
chains2 = "iptables -N dc-incoming"

client = "iptables -A client-incoming -t nat -A PREROUTING -i eth0 -p tcp --dport 445 -j DNAT --to 10.10.10.89"
client1 = "iptables -A client-incoming -I INPUT -p tcp --dport 445 -j NFQUEUE --queue-num 1"
client2 = "iptables -A client-incoming -t nat -A POSTROUTING -o eth0 -s 10.10.10.89 -p tcp --dport 445 -j SNAT --to 10.10.10.4"
iptablesr2 = "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 445 -j DNAT --to 10.10.10.89"
iptablesr = "iptables -I INPUT -p tcp --dport 445 -j NFQUEUE --queue-num 1"
iptablesr3 = "iptables -t nat -A POSTROUTING -o eth0 -s 10.10.10.3 -p tcp --dport 445 -j SNAT --to 10.10.10.4"
iptablesr4 = "iptables -t nat -A POSTROUTING -o eth0 -s 10.10.10.4 -p tcp -j SNAT --to 10.10.10.3"
#iptablesr2 = "iptables -I INPUT -i eth0 -j NFQUEUE --queue-num 1"
#iptablesr2 = "iptables -A OUTPUT -j NFQUEUE --queue-num 1"
#iptablesr = "iptables -t nat -A PREROUTING -i eth0 -p icmp -j NFQUEUE --queue-num 1"
#iptablesr2 = "iptables -"

print("Adding iptable rules")
print(iptablesr)
print(iptablesr2)
os.system(iptablesr)
os.system(iptablesr2)
os.system(iptablesr3)
os.system(iptablesr4)

def callback(packet):
    data = packet.get_payload()
    pkt = IP(data)
    print(pkt.show())
    #packet.drop()
    #packet.set_payload(raw(pk))
    packet.accept()

def main():
    q = NetfilterQueue()
    q.bind(1, callback)
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
