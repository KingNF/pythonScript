# coding=utf-8
import os
import time
from scapy.all import *
# dir_path 为流量包所在文件夹路径
dir_path = "test/"
files = os.listdir(dir_path)
for file in files:
    # 这里过滤了文件，只处理.pcap 结尾的流量包，若类型不符合，请修改
    if not file.endswith(".pcap"):
        continue
    pcaps = rdpcap(dir_path+os.sep+file)
    length = pcaps.__len__()
    start_time = pcaps[0].time
    start_array = time.localtime(start_time)
    start_hour = time.strftime("%H:%M:%S", start_array)
    end_time = pcaps[length-1].time
    end_array = time.localtime(end_time)
    end_hour = time.strftime("%H:%M:%S", end_array)
    #此处为修改判断条件
    if int(start_hour[:2])>= 8 and int(start_hour[:2]) < 22:
        if int(end_hour[:2])>= 8 and int(end_hour[:2]) < 22:
            if int(end_hour[:2]) - int(start_hour[:2])>= 0:
                os.remove(dir_path+os.sep+file)
                print "remove " + file

