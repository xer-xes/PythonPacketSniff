#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=ProcessPacket)

def ProcessPacket(packet):
    print(packet)

sniff("eth0")