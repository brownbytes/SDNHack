__author__ = 'root'
from scapy.all import *
answer = sr1(IP(dst="10.0.0.2")/UDP(sport=65431,dport=53)/DNS(rd=1,qd=DNSQR(qname="www.astro.qc.ca")),verbose=0)
print answer[DNS].summary()

