import csv
import subprocess
import json
from time import sleep

ip_range_list = []
ip_split_list = []


def save_file(split_result: [], file_name: str):
    # json파일로 저장함
    json_str = json.dumps(split_result)
    with open(file_name, 'w', newline='') as file:
        file.write(json_str)
        pass


def make_scannfile_by_count(count: int) -> bool:
    with open("iprange.csv") as file:
        spamreader = csv.reader(file, delimiter=' ', quotechar='|')
        for row in spamreader:
            row_list = row[0].split("\t")
            ip_range = {"start_ip": row_list[0], "end_ip": row_list[1]}
            ip_range_list.append(ip_range)

        del ip_range_list[0]

    print(len(ip_range_list))

    split_size = int(len(ip_range_list) / count)
    split_start_index = 0
    split_end_index = split_size

    for i in range(0, count):
        print("split by " + str(i))
        if i == count - 1:
            split_end_index = len(ip_range_list) - 1

        split_reuslt = ip_range_list[split_start_index: split_end_index + 1]
        ip_split_list.append(split_reuslt)

        split_start_index += split_size
        split_end_index += split_size

        # 파일 저장해야한다.
        save_file(split_reuslt, "instance" + str(i))


def read_scanning_info():
    with open("scanning_info", 'r') as json_file:
        json_data = json.load(json_file)
        return json_data
    pass


def read_address_list_info(instace_name: str):
    with open(instace_name, 'r') as json_file:
        json_data = json.load(json_file)
        return json_data
    pass


def start_scanning():
    # scanning_info 파일들을 불러오기
    scanning_info = read_scanning_info()

    # 대역대를 갖고옴
    file_name = "instance" + scanning_info["file_name"]
    address_list_info = read_address_list_info(file_name)

    # VM이름들을 갖고 오기
    instance_name = scanning_info["name"]

    # 공격 스크립트를 실행함
    for i in range(0, len(address_list_info)):
        entity = address_list_info[i]

        start_ip_address = str(entity["start_ip"])
        end_ip_address = str(entity["end_ip"])

        result_document_name = instance_name + "_" + str(i) + ".txt"
        command = "./ssdps " + start_ip_address + " " + end_ip_address + " " + result_document_name + " 4096 1000"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        print(str(i) + " scaaning is on progress")

        while (process.poll() == None):
            for output in process.stdout:
                print(output)
            sleep(1)

        process.wait()


start_scanning()
