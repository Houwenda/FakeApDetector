import os
import scapy
import sys
import requests
import time
from scapy.all import *
from scapy.utils import PcapReader

def sendPcapng():
    f = open('server.conf')
    url = f.readline()
    print url
    #url = "http://10.15.29.82/hackathon/index.php"
    data = None
    files = {'file': (fileName, open(fileName, 'rb'), 'application/octet-stream')}
    r = requests.post(url, data, files=files)
    print(r.text)

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

def macInspect(macAddresses):
    f = open('mac.txt','r')
    all_lines = f.readlines()
    for line in all_lines:
        mac = line[0:2] + ':' + line[2:4] + ':' + line[4:6]
        mac = mac.lower()
        for macAddress in macAddresses:
            if mac == macAddress[0:8]:
                print "the AP [[" + mac + "]] seems to be set up by a wireless interface, be careful!!!"
                evil.append(mac)
    f.close()

def timestampInspect(fileName):
    packets = rdpcap("cap/" + fileName)
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
def start():
    os.system("clear")
    print "\n\n"
    print "  ___________       __                 _____          "
    time.sleep(0.1)
    print "  \_   _____/____  |  | __ ____       /  _  \ ______   "
    time.sleep(0.1)
    print "   |    __) \__  \ |  |/ // __ \     /  /_\  \\____ \  "
    time.sleep(0.1)
    print "   |     \   / __ \|    <\  ___/    /    |    \  |_> > "
    time.sleep(0.1)
    print "   \___  /  (____  /__|_ \\___  >   \____|__  /   __/  "
    time.sleep(0.1)
    print "       \/        \/     \/    \/            \/|__|     "
    time.sleep(0.1)
    print "________          __                 __                "
    time.sleep(0.1)
    print "\______ \   _____/  |_  ____   _____/  |_  ___________ "
    time.sleep(0.1)
    print " |    |  \_/ __ \   __\/ __ \_/ ___\   __\/  _ \_  __ \ "
    time.sleep(0.1)
    print " |    `   \  ___/|  | \  ___/\  \___|  | (  <_> )  | \/ "
    time.sleep(0.1)
    print "/_______  /\___  >__|  \___  >\___  >__|  \____/|__|   "
    time.sleep(0.1)
    print "        \/     \/          \/     \/                  "
    print "\n-------------------------------------------------------------\n"

start()
#check user privilege
if os.getuid() != 0:
    print "Please run this script as root"
    sys.exit(1)

#set interface into monitor mode
print "setting interfaces............"
tmp = os.popen("airmon-ng check kill").readlines()
tmp = os.popen("airmon-ng start wlan0").readlines()

#capture traffic
evil = []
print "Enter the number of packets you want to capture "
while True:
    packetCount = raw_input("(the number of packets affects accuracy, analysis based on less than 50 beacon frames is not reliable): \n")
    if packetCount.isdigit():
        break;
    packetCount = int(packetCount)
if packetCount < 0:
    sys.exit(1)
fileName = str(time.strftime("%a-%b-%d-%H-%M-%S-%Y", time.localtime())) + '.pcapng'
print 'traffic saved in cap/' + fileName
os.system("touch cap/" + fileName)
os.system("chmod 646 cap/" + fileName)
os.system("tshark -i wlan0mon -c " + packetCount +" -w cap/" + fileName)

#parse pcapng
print "start analysing............"
packets = rdpcap("cap/" + fileName)
#packets = rdpcap("/home/hwd/Desktop/cap2.pcapng")
#get all mac addresses and number of beacon frame
macAddresses = []
for data in packets:
    if data.haslayer(Dot11Beacon):
        mac = data.addr2
        if mac not in macAddresses:
            macAddresses.append(mac)
netNames = []
for data in packets:
    if data.haslayer(Dot11Beacon):
        netName = data.getlayer(Dot11Beacon).info
        if netName not in netNames:
            netNames.append(netName)
tmp = 1
for netName in netNames:
    print '[' + str(tmp) + ']' + netName
    tmp += 1
    for mac in macAddresses:
        count = 0
        for data in packets:
            if data.haslayer(Dot11Beacon) and data.addr2 == mac and data.getlayer(Dot11Beacon).info == netName:
                count += 1
        if count != 0 and count < 50:
            print '--------' + mac + '\n--------' + str(count) + '(needs more beacon frames)\n'
        elif count >= 50:
            print '--------' + mac + '\n--------' + str(count) + '\n'

#analysis
print "\n------------------------------------------------------\n"
print "starting timestamp based analysis....................."
timestampInspect(fileName)
print "Done!"
print "\n------------------------------------------------------\n"
print "starting mac address based analysis..................."
macInspect(macAddresses)
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

sendPcapng()

#reset interface
tmp = os.popen("airmon-ng stop wlan0mon").readlines()
#remove capfile
tmp = os.popen("rm cap/*").readlines()
