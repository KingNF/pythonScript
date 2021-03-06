# coding=utf-8
import os
import time
from scapy.all import *

# dir_path 为流量包所在文件夹路径
dir_path = "test/"

def  filter_pcap(filePath):
    pcaps = rdpcap(filePath)
    length = pcaps.__len__()
    start_time = pcaps[0].time
    start_array = time.localtime(start_time)
    start_hour = time.strftime("%H:%M:%S", start_array)
    end_time = pcaps[length - 1].time
    end_array = time.localtime(end_time)
    end_hour = time.strftime("%H:%M:%S", end_array)
    # 此处为修改判断条件
    if int(start_hour[:2]) >= 8 and int(start_hour[:2]) < 22:
        if int(end_hour[:2]) >= 8 and int(end_hour[:2]) < 22:
            if int(end_hour[:2]) - int(start_hour[:2]) >= 0:
                os.remove(filePath)
                print "remove " + filePath

def getFile(path):
    files = os.listdir(path)
    for file in files:
        if os.path.isdir(path+os.sep+file):
            getFile(path+os.sep+file)
        # 这里过滤了文件，只处理.pcap 结尾的流量包，若类型不符合，请修改
        if file.endswith(".pcap"):
            filter_pcap(path+os.sep+file)

getFile(dir_path)



