# coding=utf-8
import os
import time
import dpkt
import socket
import re

# dir_path 为流量包所在文件夹路径
dir_path = "E:\\pcap"
result = {}


def analysis(file, sip):
    try:
        f = open(file, "rb")
        pcap = dpkt.pcap.Reader(f)
        for (ts, buf) in pcap:
            try:
                #print buf.decode('gb2312')
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                if src != sip and dst != sip:
                    continue
                protocol = getType(buf)

                if protocol != "ICMP":
                    sport = tcp.sport
                    dport = tcp.dport

                if sport == 25 or dport == 25:
                    protocol = "SMTP"
                if sport == 143 or dport == 143:
                    protocol = "IMAP"
                if sport ==109 or dport ==109:
                    protocol = "POP2"
                if sport ==110 or dport ==110:
                    protocol = "POP3"
                if sport ==80 or dport ==80 :
                    protocol = "HTTP"
                if sport ==53 or dport ==53:
                    protocol = "DNS"
                if sport == 3389 or dport == 3389:
                	protocol = "RDP"
                if sport == 22 or dport ==22 :
                	protocol = "SSH"
                if sport == 21 or dport == 21:
                	protocol = "FTP" 
                	
                length = len(buf)
                result[ts] = src+":"+str(sport)+"-->"+dst+":"+str(dport)+"\t"+protocol+"\t"+str(length)
                #break
            except Exception,e:
                #print e.message
                continue
    except Exception, e:
        #print e.message
        pass


def TCPorUDP(obj):
    if ( ord(obj) == 0x01 ):
        return "ICMP"
    elif (ord(obj) == 0x02):
        return "IGMP"
    elif (ord(obj) == 0x06):
        return "TCP"
    elif (ord(obj) == 0x08):
        return "EGP"
    elif (ord(obj) == 0x09):
        return "IGP"
    elif (ord(obj) == 0x11):
        return "UDP"
    elif (ord(obj) == 41):
        return "IPv6"
    elif (ord(obj) == 89):
        return "OSPF"
    else:
        return "error"

def getType(buf):
    ethType = buf[12:14]
    if ord(ethType[0])==0x08 and ord(ethType[1])==0x00:
        pktheader = buf[14:34]
        trans_type = pktheader[9]
        return TCPorUDP(trans_type)
    elif ord(ethType[0])== 0x08 and ord(ethType[1]) == 0x06:
        return "ARP"
    elif ord(ethType[0])== 0x08 and ord(ethType[1]) == 0x35:
        return "RARP"
    elif ord(ethType[0]) == 0x81 and ord(ethType[1]) == 0x00:
        pktheader = buf[18:38]
        trans_type = pktheader[9]
        return TCPorUDP(trans_type)
    else:
        return "error"

def get_files(path, sip):
    files = os.listdir(path)
    files = [(path+os.sep+file, os.stat(path+os.sep+file).st_mtime) for file in files]
    files = sorted(files, key=lambda x: x[1])
    for i in files:
        if i[0].endswith(".pcap"):
            analysis(i[0], sip)


def result_to_files(ip):
    sort_result = sorted(result.items(),key=lambda x:x[0])
    with open(ip+".txt",'w') as f:
        for record in sort_result:
            #print record
            time_array = time.localtime(record[0])
            pcap_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
            f.write(pcap_time+"\t"+record[1]+"\n")


def get_ip(path):
    ipset = set()
    if os.path.exists(path):
        with open(path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                ss = re.split(r'\t|:|-->',line)
                ipset.add(ss[3])
                ipset.add(ss[5])
    else:
        print path+" no exists"

    with open(path.replace(".txt", "_ip.txt"),'w') as f:
        for ip in ipset:
            f.write(ip+"\n")


def start():
    ip = raw_input("please input the IP you want to analysis:")
    get_files(dir_path, ip)
    result_to_files(ip)
    get_ip(ip+".txt")


start()