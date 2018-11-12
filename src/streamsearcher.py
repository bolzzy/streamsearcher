#!/usr/bin/env python3

from scapy.all import *
import hashlib
import argparse


def test_stream(pkt):
    try:
        a = pkt.sport
        b = pkt.dport
    except:
        return False
    return True


def xor_str(a,b):
    xored = []
    for i in range(max(len(a), len(b))):
        xored_value = ord(a[i%len(a)]) ^ ord(b[i%len(b)])
        xored.append(hex(xored_value)[2:])
    return ''.join(xored)


def packet_symhash(pkt):
    src = (str(pkt.src) + ":" + str(pkt.sport))
    dst = (str(pkt.dst) + ":" + str(pkt.dport))
    shash = hashlib.sha256(src.encode('utf-8')).hexdigest()
    dhash = hashlib.sha256(dst.encode('utf-8')).hexdigest()
    return xor_str(shash,dhash)


def process_packets(pr,string):
    hashlist=[]
    for p in pr:
        if p.payload:
            if string.lower() in str(p.payload).lower():
                print("[+] Found match: " + p.summary())
                if not packet_symhash(p) in hashlist:
                    hashlist.append(packet_symhash(p))
    return hashlist


def get_hashpackets(pr,hashlist,outputpackets):
    for p in pr:
        if not test_stream(p):
            continue
        if packet_symhash(p) in hashlist:
            outputpackets.append(p)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--inputpcap",help="input pcap", dest="inputfile",required=True)
    parser.add_argument("-o","--outputpcap",help="output pcap", dest="outputfile",required=True)
    parser.add_argument("-s","--string",help="search string", dest="string",required=True)
    args = parser.parse_args()

    inpcap  = args.inputfile
    outpcap = args.outputfile
    string  = args.string

    outputpackets = []
    hashlist = []

    print("[i] Starting streamsearcher.py")

    with PcapReader(inpcap) as pr:
        print("[i] Searching packets")
        hashlist = process_packets(pr,string)

    if hashlist:
        with PcapReader(inpcap) as pr:
            print("[i] Processing matching packet streams")
            get_hashpackets(pr,hashlist,outputpackets)

    if outputpackets:
        print("[i] Writing matched streams to " + outpcap)
        wrpcap(outpcap,outputpackets)


if __name__ == '__main__':
    main()
