# coding=utf-8
import os
import re

dirpath = "test2/"
resultPath = "common_ip.txt"

txtFiles = list()
previous = ""
seg_ip_set = set()
f1 = open(resultPath, 'w+')


def get_files(path):
    files = os.listdir(path)
    for file in files:
        if os.path.isdir(file):
            get_files(path+os.sep+file)
        if file.endswith(".txt"):
            txtFiles.append(path+os.sep+file)


def compare_ip(ip, index):
    ss = ip.split('.')
    seg_ip = ss[0]+"."+ss[1]+"."+ss[2]
    if seg_ip in seg_ip_set:
        return
    seg_ip_set.add(seg_ip)
    pattern = re.compile("'("+ss[0]+"\."+ss[1]+"\."+ss[2]+"\..*?"+")'")
    for file in txtFiles:
        with open(file, 'r')as f:
            lines = f.readlines()
            same_ips = pattern.findall(lines.__str__())
            if txtFiles[index] == file and same_ips.__len__() == 1:
                continue
            if same_ips.__len__() == 0:
                continue
            write_result_to_files(seg_ip, txtFiles[index], ip, file, same_ips)


def write_result_to_files(seg_ip, srcfile, srcip, samefile, sameips):
    global previous
    if previous != srcfile+srcip:
        f1.write(seg_ip+".* :"+"\n")
        previous = srcfile + srcip
    f1.write("\t"+samefile + ":")
    for ip in sameips:
        ip = ip.replace("\\n", "")
        f1.write("\t"+ip)
    f1.write("\n")
    f1.flush()


def compare_file():
    for index, file in enumerate(txtFiles):
        with open(file, 'r') as f:
           ips = f.readlines()
           for ip in ips:
               ip = ip.replace('\n', '')
               compare_ip(ip, index)


get_files(dirpath)
compare_file()
f1.close()