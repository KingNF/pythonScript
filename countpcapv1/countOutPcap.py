# coding=utf-8
import datetime
import os
import time
import dpkt
import pygeoip
import socket

# dir_path 为流量包所在文件夹路径
dir_path = "E:\\pcap"
# serverIp 为服务器IP地址
serverIp = "192.168.128.69"
result = {}
# City数据库地址路径
gi = pygeoip.GeoIP("GeoLiteCity/GeoLiteCity.dat")
counrtyPath = "GeoLiteCity/country_chinese.txt"
countryList={}
resultPath="output_result.txt"

def filter_pcap(filePath):
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


def count_pcap(filePath):
	try:
	    f = open(filePath, "rb")
	    pcap = dpkt.pcap.Reader(f)
	    for index, (ts, buf) in enumerate(pcap):
	        time_array = time.localtime(ts)
	        format_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
	        dtime = datetime.datetime.strptime(format_time, "%Y-%m-%d %H:%M:%S")
	        if dtime.hour >= 8 and dtime.hour < 22 :
	            continue
	        try:
	            eth = dpkt.ethernet.Ethernet(buf)
	            ip = eth.data
	            src = socket.inet_ntoa(ip.src)
	            dst = socket.inet_ntoa(ip.dst)
	            length = len(buf)
	        except Exception,e:
	            continue
	        date = ""
	        if src == serverIp:
	           # date = dtime.date().__str__()
	            if dtime.hour >= 22 and dtime.hour < 24:
	                date = dtime.date().__str__()
	            else:
	                date = (dtime.date() + datetime.timedelta(-1)).__str__()
	            if result.has_key(date):
	                date_dict = result.get(date)
	                if dst in date_dict:
	                    date_dict[dst] += length
	                else:
	                    date_dict.update({dst: length})
	            else:
	                result.update({date: {dst: length}})
	except Exception,e:
		pass

def get_city(ip):
    rec = gi.record_by_name(ip)
    try:
        city = rec['city']
    except Exception,e:
        city = ""
    try:
        region = rec['region_name']
    except Exception,e:
        region = ""
    try:
        english_country = rec['country_name']
        country = get_chinese_country(english_country)
    except Exception,e:
        country = ""
    if city == "" and  region=="" and country=="":
        return u"未知"
    if city ==None or  region==None or country==None:
        return u"未知"
    return city + " " + region + " " + country


def get_country_list():
	with open(counrtyPath,'r') as f:
		countrylines=f.readlines()
		for countryline in countrylines:
			countrys = countryline.split("\t")
			countryList[countrys[1].replace("\n","")]=countrys[0]

def get_chinese_country(englishname):
	if englishname in countryList:
		return countryList[englishname]
	return englishname


def print_result():
	f=open(resultPath,'w')
	for date in result:
		date_result = sorted(result[date].items(),key=lambda item: item[1], reverse=True)
		print date
    	f.write(date+"\n")
    	for ip in date_result:
            # 可修改输出结果流量单位
        	f.write(serverIp + " ---> " + ip[0] + "  " + get_city(ip[0]) + "  " + str(float(ip[1])/1024/1024) + "M"+"\n")
        	print serverIp + " ---> " + ip[0] + "  " + get_city(ip[0]) + "  " + str(float(ip[1])/1024/1024) + "M"
	f.close()


def get_file(path):
    files = os.listdir(path)
    for file in files:
        if os.path.isdir(path+os.sep+file):
            get_file(path + os.sep + file)
        # 这里过滤了文件，只处理.pcap 结尾的流量包，若类型不符合，请修改
        if file.endswith(".pcap"):
            # filter_pcap(path+os.sep+file)
            count_pcap(path + os.sep + file)


get_country_list()
get_file(dir_path)
print_result()


