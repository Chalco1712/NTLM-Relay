#Figure out how to forward traffic (use stackoverflow post)
#Figure out how to arpspoof (stackoverflow)
#Figure out how to manipulate traffic (consider using sniff() instead of SniffSource)

import sys
from scapy.all import *

s = SniffSource(filter = 'dst port 80')

d1 = Drain()

#d2 = TransformDrain(lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))

d2 = TransformDrain(lambda x: x.show()) 

si1 = QueueSink()

si2 = QueueSink()

s > d1
s > d2
#d1 > d2
#d2 > si1
d1 > si1
d2 > si2

p = PipeEngine()
p.add(s)
p.start()

while True:
	#print(si1.recv())
	if si1.recv() is not None and si2.recv() is not None:
            print("Captured packet: " + si2.recv())
            sys.exit()
            #time.sleep(10)
            #print("Forwarding packet")
            #response = sr(si1.recv())
            #print(response.show())

