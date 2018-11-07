# coding=utf-8
import datetime
import os
import socket
import time
import dpkt

# dir_path 为流量包所在文件夹路径
dir_path = "E:\\pcap"
result = set()
# resultPath 为输出结果路径
resultPath = "ip_result.txt"


def get_ip(filePath, start_date, end_date):
    try:
        f = open(filePath, "rb")
        pcap = dpkt.pcap.Reader(f)
        for index, (ts, buf) in enumerate(pcap):
            try:
                time_array = time.localtime(ts)
                format_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
                dtime = datetime.datetime.strptime(format_time, "%Y-%m-%d %H:%M:%S")
                if dtime >= start_date and dtime < end_date:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    result.add(src)
                    result.add(dst)
            except Exception, e:
               # print e.message
                continue
    except Exception, e:
       # print e.message
        pass


def print_result(start_date,end_date):
    f = open(resultPath, 'w')
    f.write(start_date.__str__()+"--->"+end_date.__str__()+"\n")
    for ip in result:
        f.write(ip + "\n")
        print ip
    f.close()


def get_file(path, start_date, end_date):
    files = os.listdir(path)
    for file in files:
        if os.path.isdir(path + os.sep + file):
            get_file(path + os.sep + file, start_date, end_date)
        # 这里过滤了文件，只处理.pcap 结尾的流量包，若类型不符合，请修改
        if file.endswith(".pcap"):
            get_ip(path + os.sep + file, start_date, end_date)


def start():
    while True:
        try:
            line = raw_input(" please input the time format(%Y%m%d%H%M)start-end:")
            ss = line.split('-')
            start_date = datetime.datetime.strptime(ss[0], "%Y%m%d%H%M")
            end_date = datetime.datetime.strptime(ss[1], "%Y%m%d%H%M")
            break
        except Exception, e:
            print "the time format is wrong "
    print start_date , end_date
    get_file(dir_path, start_date, end_date)
    print_result(start_date,end_date)

start()
