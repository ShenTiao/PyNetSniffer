import datetime
from scapy.all import *
from scapy.layers import http
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.inet6 import *

#分组信息
def PktInfoGet(pkt):
    data = ""
    #App layer
    if pkt.haslayer(http.HTTP):
        #HTTP
        data += "HyperText Transfer Protocol:\n"
        layer = {}
        if pkt.haslayer(http.HTTPRequest):
            layer = pkt.getlayer(http.HTTPRequest).fields
        elif pkt.haslayer(http.HTTPResponse):
            layer = pkt.getlayer(http.HTTPResponse).fields
        if 'Headers' in layer.keys():
            #HTTP header split
            dec = layer['Headers'].decode()
            dec.split('\r\n')
            data += "\tHeader:\n"
            for i in dec:
                data += "\tHeaders:\n" % i
        for key in layer.keys():
            if key == 'Headers':
                continue
            else:
                try:
                    data += ("\t%s: %s\n" % (key, layer[key].decode()))
                except:
                    continue
    #ICMP
    if pkt.haslayer(ICMP):
        data += "Internet Control Message Protocol:"
        data += "Internet Control Message Protocol:\n"
        icmp = pkt.getlayer(ICMP)
        #icmp fields
        data += "\ttype: %d\n" % icmp.type
        data += "\tcode: %d\n" % icmp.type
        data += "\tchecksum: %s\n" % hex(icmp.chksum)\

    #DNS
    if pkt.haslayer(DNS):
        data += "Domain Name System\n"
        dns = pkt.getlayer(DNS)
        #DNS fields
        if dns.opcode == 0:
            data += "\topcode: %s\n" % "answer"
        else:
            data += "\topcode: %s\n" % "query"
        try:
            data += "\tqname: %s\n" % dns.qd.qname.decode()
        except:
            data += "\rerror\n"
            return data
        for i in range(0, dns.ancount):
            data += "\t===========================\n"
            if (type(dns.an[i].rrname) == bytes):
                data += "\trrname: %s\n" % dns.an[i].rrname.decode()
            else:
                data += "\trrname: %s\n" % dns.an[i].rrname
            if (type(dns.an[i].rdata) == bytes):
                data += "\trdata: %s\n" % dns.an[i].rdata.decode()
            else:
                data += "\trdata: %s\n" % dns.an[i].rdata

    #transport layer
    #TCP
    if pkt.haslayer(UDP):
        data += "User Datagram Protocol:\n"
        udp = pkt.getlayer(UDP)
        data += "\tsrc port: %d\n" % udp.sport
        data += "\tdst port: %d\n" % udp.dport
        data += "\tlength: %d\n" % udp.len
        data += "\tchecksum: %s\n" % hex(udp.chksum)
    elif pkt.haslayer(TCP):
        data += "Transmission Control Protocol:\n"
        tcp = pkt.getlayer(TCP)
        data += "\tsrc port: %d\n" % tcp.sport
        data += "\tdst port: %d\n" % tcp.dport
        data += "\tseq: %d\n" % tcp.seq
        data += "\tack: %d\n" % tcp.ack
        data += "\theader length: %s bytes (%d)\n" % (
            hex(tcp.dataofs), tcp.dataofs)
        data += "\tflags : 0x%03x (%s)\n" % (tcp.flags.value, str(tcp.flags))
        data += "\twindow size: %d\n" % tcp.window
        data += "\tchecksum: %s\n" % hex(tcp.chksum)
        data += "\turgent pointer: %d\n" % (tcp.urgptr)

    #network layer
    #IPv4
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        data += "Internet Protocol Version 4:\n"
        data += "\tSrc: %s\n" % ip.src
        data += "\tDst: %s\n" % ip.dst
        data += "\tIhl: %d bytes (%d)\n" % (ip.ihl * 4, ip.ihl)
        data += "\tTos: %s\n" % hex(ip.tos)
        data += "\tLength: %d\n" % ip.len
        data += "\tId: %s (%d)\n" % (hex(ip.id), ip.id)
        data += "\tFlags: 0x%04x\n" % ip.flags.value
        data += "\tTtl: %d\n" % ip.ttl
        data += "\tProtocol: %s\n" % ip.proto
        data += "\tChecksum: %s\n" % hex(ip.chksum)
    elif pkt.haslayer(IPv6):
        ipv6 = pkt.getlayer(IPv6)
        d = {1: "ICMP", 2: "IGMP", 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        data += "Internet Protocol Version 6:\n"
        data += "\tSrc: %s\n" % ipv6.src
        data += "\tDst: %s\n" % ipv6.dst
        data += "\tTraffic class: 0x%02x\n" % ipv6.tc
        data += "\tFlow label: %s\n" % hex(ipv6.fl)
        data += "\tPayload length: %d\n" % ipv6.plen
        if (ipv6.nh in d.keys()):
            data += "\tNext header: %s (%d)\n" % (d[ipv6.nh], ipv6.nh)
        else:
            pass
        data += "\tHop limit: %d\n" % ipv6.hlim

    #Datalink layer
    if pkt.haslayer(Ether):
        eth = pkt.getlayer(Ether)
        data += "Ethernet II:\n"
        data += "\tsrc: %s\n" % eth.src
        data += "\tdst: %s\n" % eth.dst
        data += "\ttype: %s\n" % eth.type

    return data

class PacketDecode:
    def __init__(self):
        # Load ether configurations
        with open('./protocol/ETHER', 'r', encoding='UTF-8') as eth_f:
            eths = eth_f.readlines()
        self.ETHER_DICT = dict()
        for et in eths:
            et = et.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(et.split(':')[0])] = et.split(':')[1]

        # Load ip configurations
        with open('./protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        # Load app layer configurations
        with open('./protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        # Load tcp configurations
        with open('./protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        # Load udp configurations
        with open('./protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    # parsing ethernet protocols
    def etherProtoParsing(self, p):
        data = dict()
        if p.haslayer(Ether):
            data = self.ipProtoParsing(p)
            return data
        else:
            data['time'] = datetime.fromtimestamp(
                p.time).strftime("%H:%M:%S.%f")
            data['Source'] = 'Unknown'
            data['Destination'] = 'Unknown'
            data['Protocol'] = 'Unknown'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    #parsing tcp/udp protocols
    def udpProtoParsing(self, p, ip):
        data = dict()
        udp = p.getlayer(UDP)
        data['time'] = datetime.fromtimestamp(
            p.time).strftime("%H:%M:%S.%f")
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if udp.dport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Protocol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Protocol'] = self.UDP_DICT[udp.sport]
        else:
            data['Protocol'] = "UDP"
        return data

    def tcpProtoParsing(self, p, ip):
        data = dict()
        tcp = p.getlayer(TCP)
        data['time'] = datetime.fromtimestamp(
            p.time).strftime("%H:%M:%S.%f")
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if tcp.dport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Protocol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Protocol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Protocol'] = "TCP"
        return data

    # parsing ip protocols
    def ipProtoParsing(self, p):
        data = dict()
        if p.haslayer(IP):
            ip = p.getlayer(IP)
            if p.haslayer(TCP):
                data = self.tcpProtoParsing(p, ip)
                return data
            elif p.haslayer(UDP):
                data = self.udpProtoParsing(p, ip)
                return data
            else:
                if ip.proto in self.IP_DICT:
                    data['time'] = datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Protocol'] = self.IP_DICT[ip.proto]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    # 其他都算IPv4
                    data['time'] = datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Protocol'] = 'IPv4'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        elif p.haslayer(IPv6):
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):
                data = self.tcpProtoParsing(p, ipv6)
                return data
            elif p.haslayer(UDP):
                data = self.udpProtoParsing(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['time'] = datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Protocol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Protocol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = datetime.fromtimestamp(
                    p.time).strftime("%H:%M:%S.%f")
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Protocol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data
            else:
                data['time'] = datetime.fromtimestamp(
                    p.time).strftime("%H:%M:%S.%f")
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Protocol'] = hex(p.type)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data

if __name__ == '__main__':
    decoder = PacketDecode()
    device = "Intel(R) Wireless-AC 9560 160MHz"
    test = sniff(filter="", iface=device, count=10)
    res = dict()
    for i in test:
        res = decoder.etherProtoParsing(i)
        print(res)