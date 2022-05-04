from scapy.all import *
from collections import OrderedDict
from scapy.layers.inet import *

def extractHtml(PCAPS, host_ip):
    ip_port_id_list = list()
    id = 0
    for pcap in PCAPS:
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = pcap.sport
            dport = pcap.dport
            if sport == 80 or sport == 8080:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append(
                        {'ip_port': ip + ':' + str(port) + ':' + 'HTTP', 'id': id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append(
                        {'ip_port': ip + ':' + str(port) + ':' + 'HTTP', 'id': id})
                else:
                    pass
            elif dport == 80 or dport == 8080:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append(
                        {'ip_port': ip + ':' + str(port) + ':' + 'HTTP', 'id': id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append(
                        {'ip_port': ip + ':' + str(port) + ':' + 'HTTP', 'id': id})
                else:
                    pass
            else:
                pass
        id += 1
    # {'192.134.13.234:232':[2,3,4,5],'192.134.13.234:236':[4,3,2,4,3]}
    ip_port_ids_dict = OrderedDict()
    for ip_port_id in ip_port_id_list:
        if ip_port_id['ip_port'] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id['ip_port']].append(
                ip_port_id['id'])  # PCAPS[ip_port_id['id']].load)
        else:
            ip_port_ids_dict[ip_port_id['ip_port']] = [
                ip_port_id['id']]  # [PCAPS[ip_port_id['id']].load]
    ip_port_data_list = list()
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        raw_data = b''.join([PCAPS[i].load for i in load_list])
        # 解决编码问题
        tmp_data = raw_data.decode('UTF-8', 'ignore')
        if ('gbk' in tmp_data) or ('GBK' in tmp_data):
            data = raw_data.decode('GBK', 'ignore')
        else:
            data = tmp_data
        # ip_port_data_list.append({'data_id': data_id, 'ip_port': ip_port,
        #                          'data': data, 'raw_data': raw_data, "index_list": load_list})
        ip_port_data_list.append({'data_id': data_id, 'ip_port': ip_port,
                                  'data': data, "index_list": load_list})
    return ip_port_data_list
