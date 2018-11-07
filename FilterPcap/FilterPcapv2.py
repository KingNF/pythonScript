# coding=utf-8
import os
import time
import dpkt

# dir_path 为流量包所在文件夹路径
dir_path = "E:\\pcap"

def filter_pcap(filePath):
	try:
	    f = open(filePath, "rb")
	    pcap = dpkt.pcap.Reader(f)
	    start_time = ""
	    for index,(ts, buf)in enumerate(pcap):
	        time_array = time.localtime(ts)
	        pcap_hour = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
	        if index == 0:
	            start_time = pcap_hour
	    end_time = pcap_hour
	    start_hour = int (start_time[11:13])
	    end_hour = int (end_time[11:13])
	    f.close()
	    if start_hour >= 8 and end_hour < 22:
	        if end_hour >= 8 and end_hour < 22:
	            if end_hour - start_hour >= 0:
	                os.remove(filePath)
	                print "remove " + filePath
	except Exception,e:
		pass

def getFile(path):
    files = os.listdir(path)
    for file in files:
        if os.path.isdir(path+os.sep+file):
            getFile(path+os.sep+file)
        # 这里过滤了文件，只处理.pcap 结尾的流量包，若类型不符合，请修改
        if file.endswith(".pcap"):
            filter_pcap(path+os.sep+file)

getFile(dir_path)