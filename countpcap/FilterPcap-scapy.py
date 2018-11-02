# coding=utf-8
import datetime
import os
import time
import scapy.all

# dir_path 为流量包所在文件夹路径
dir_path = "test/"
# serverIp 为服务器IP地址
serverIp = "192.168.2.8"
result = {}


def filter_pcap(filePath):
    pcaps = scapy.all.rdpcap(filePath)
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


def count_pcap(filePath):
    pcaps = scapy.all.rdpcap(filePath)
    for index, pcap in enumerate(pcaps):
        stime = pcap.time
        time_array = time.localtime(stime)
        format_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
        dtime = datetime.datetime.strptime(format_time, "%Y-%m-%d %H:%M:%S")

        if dtime.hour >= 8 and dtime.hour < 22 :
            continue
        src = pcap.payload.src
        dst = pcap.payload.dst
        length = pcap.payload.len+14
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


def print_result():
    for date in result:
        date_result = sorted(result[date].items(),key=lambda item: item[1], reverse=True)
        print date
        for ip in date_result:
            # 此次可修改输出结果流量单位
            print serverIp + " ---> " + ip[0] + "  " + str(float(ip[1])/1024/1024) + "M"


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



