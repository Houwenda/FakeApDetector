import sys
import scapy
from scapy.all import *
from scapy.utils import PcapReader

uploadPath = 'upload/'
fileName = str(sys.argv[1])
packets = rdpcap(uploadPath + fileName)

def beaconLengthInspect():
    macAddresses = []
    for data in packets:
        if data.haslayer(Dot11Beacon):
            mac = data.addr2
            if mac not in macAddresses:
                macAddresses.append(mac)
    for mac in macAddresses:
        for data in packets:
            if data.haslayer(Dot11Beacon) and data.addr2 == mac:
                length = data.__len__()
                break
        for data in packets:
            if data.haslayer(Dot11Beacon) and data.addr2 ==mac:
                if abs(data.__len__() - length) >= 10:
                    print "There is an AP using fake mac address [[" + data.addr2 + "]]"
                    evil.append(data.addr2)
                    break

def timestampInspect(fileName):
    packets = rdpcap(uploadPath + fileName)
    netNames = []
    for data in packets:
        if data.haslayer(Dot11Beacon):
            netName = data.getlayer(Dot11Beacon).info
            if netName not in netNames:
                netNames.append(netName)

    for netName in netNames:
        #print '----- ' + netName + ' -----'
        formerTimestamp = 0
        for data in packets:
            if data.haslayer(Dot11Beacon) and data.getlayer(Dot11Beacon).info == netName:
                timestamp = data.getlayer(Dot11Beacon).timestamp
                interval = timestamp - formerTimestamp
                gap = interval % 1024
                if gap > 512:
                    gap = 1024 - gap
                #print data.addr2 + ' : ' + str(gap)
                formerTimestamp = timestamp

#analysis
evil = []
print "\n------------------------------------------------------\n"
print "starting timestamp based analysis....................."
timestampInspect(fileName)
print "Done!"
print "\n------------------------------------------------------\n"
print "starting beacon length based analysis................."
beaconLengthInspect()
print "Done!"
print "\n------------------------------------------------------\n"

#result
print "------------------analysing results-------------------\n"
if evil == []:
    print "No fake AP detected!!!"
else:
    print "Fake APs:"
    for fake in evil:
        for data in packets:
            if data.haslayer(Dot11Beacon) and data.addr2 == fake:
                print data.getlayer(Dot11Beacon).info
                break
print "\n\n"
