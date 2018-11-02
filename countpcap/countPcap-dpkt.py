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
geopath = "GeoLiteCity/GeoLiteCity.dat"
gi = pygeoip.GeoIP(geopath)

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
            if dtime.hour >= 22 and dtime < 24:
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
        country = rec['country_name']
    except Exception,e:
        country = ""
    if city == "" and  region=="" and country=="":
        return "don't know"
    if city ==None or  region==None or country==None:
        return "don't know"
    return city + " " + region + " " + country


def print_result():
    for date in result:
        date_result = sorted(result[date].items(),key=lambda item: item[1], reverse=True)
        print date
        for ip in date_result:
            # 可修改输出结果流量单位
            print serverIp + " ---> " + ip[0] + "  " + get_city(ip[0]) + "  " + str(float(ip[1])/1024/1024) + "M"


def get_file(path):
    files = os.listdir(path)
    for file in files:
        if os.path.isdir(path+os.sep+file):
            get_file(path + os.sep + file)
        # 这里过滤了文件，只处理.pcap 结尾的流量包，若类型不符合，请修改
        if file.endswith(".pcap"):
            # filter_pcap(path+os.sep+file)
            count_pcap(path + os.sep + file)

get_file(dir_path)
print_result()



