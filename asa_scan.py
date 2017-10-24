import pprint
import time
from os import system
import argparse


def ping_probe(hostname):
    response = system('ping -c {} -w {} {} > /dev/null 2>&1'.format(
                      count, deadline, hostname))
    if response == 0:
        result = True
    else:
        result = False
    return result


def find_objects(filename):
    result = dict()
    object_name = ''
    with open(filename, 'r') as f:
        for raw_line in f:
            if 'object-group network' in raw_line:
                object_name = raw_line.split()[2]
                result[object_name] = list()
            elif 'object network' in raw_line:
                object_name = raw_line.split()[2]
                result[object_name] = list()
            elif raw_line[0] == ' ' and ('host' in raw_line or
                                         'fqdn' in raw_line):
                result[object_name].append(raw_line.split()[-1])
    return result


def clean_dict(raw_dict):
    cleaned_dict = dict()
    for key in raw_dict.keys():
        dead_ip = list()
        if raw_dict[key] != []:
            for ip_addr in raw_dict[key]:
                if not ping_probe(ip_addr):
                    dead_ip.append(ip_addr)
            if dead_ip != []:
                cleaned_dict[key] = dead_ip
    return cleaned_dict


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='Set an ASA\
                        config file to scan')
    parser.add_argument('-c', '--count', help='Set a number of icmp \
                        packets to scan a host (default 1)', default=1)
    parser.add_argument('-w', '--deadline', help='Set a deadline in seconds\
                        to stop executing ping (default 1)', default=1)
    namespace = parser.parse_args()
    filename = namespace.file
    count = namespace.count
    deadline = namespace.deadline

    t0 = time.time()
    raw_network_objects = find_objects(filename)
    network_objects = clean_dict(raw_network_objects)
    pprint.pprint(network_objects)
    print(time.time() - t0)
