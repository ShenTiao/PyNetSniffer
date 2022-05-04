import geoip2.database
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
import collections
from pyecharts import options as opts
from pyecharts.charts import Pie
from pyecharts.charts import Geo
from pyecharts.charts import Line
from pyecharts.globals import ChartType, SymbolType


def line_base(in_x, in_y, out_y):
    c = (
        Line()
        .add_xaxis(in_x)
        .add_yaxis("流入流量(kb)", in_y, is_smooth=True)
        .add_yaxis("流出流量(kb)", out_y, is_smooth=True)
        .set_series_opts(
            areastyle_opts=opts.AreaStyleOpts(opacity=0.5),
            label_opts=opts.LabelOpts(is_show=False),
        )
        .set_global_opts(
            title_opts=opts.TitleOpts(title="流量时间统计图"),
            xaxis_opts=opts.AxisOpts(
                axistick_opts=opts.AxisTickOpts(is_align_with_label=True),
                is_scale=False,
                boundary_gap=False,
            ),
        )
    )
    c.js_host = "./js/"
    return c


def pie_base(data_frame, data_bytes, graphname) -> Pie:
    pie = (
        Pie()
        .add(
            "",
            data_frame,
            radius=["15%", "50%"],
            center=["25%", "50%"],
            label_opts=opts.LabelOpts(formatter="{b}: {c} frames"),
        )
        .add(
            "",
            data_bytes,
            radius=["15%", "50%"],
            center=["75%", "50%"],
            label_opts=opts.LabelOpts(formatter="{b}: {c} bytes"),
        )
        .set_global_opts(title_opts=opts.TitleOpts(title=graphname, pos_bottom=True))
    )
    pie.js_host = "./js/"
    return pie


def geo_base(data_count, src_dst, graphname) -> Geo:
    geo = (
        Geo()
        .add_schema(
            maptype="china",
            itemstyle_opts=opts.ItemStyleOpts(
                color="#323232", border_color="#111"),
        )
        .add(
            "",
            [("广州", "55 bytes"), ("北京", 66), ("杭州", 77), ("重庆", 88)],
            type_=ChartType.EFFECT_SCATTER,
            color="white",
            #label_opts=opts.LabelOpts(formatter="%s:%d bytes")
        )
        .add(
            "geo",
            [("广州", "上海"), ("广州", "北京"), ("广州", "杭州"), ("广州", "重庆")],
            type_=ChartType.LINES,
            effect_opts=opts.EffectOpts(
                symbol=SymbolType.ARROW, symbol_size=6, color="blue"
            ),
            linestyle_opts=opts.LineStyleOpts(curve=0.2),
        )
        .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
        .set_global_opts(title_opts=opts.TitleOpts(title=graphname, pos_bottom=True))
    )
    geo.js_host = "./js/"
    return geo


def unique_proto_statistic_frame(packageInfos):
    d = {}
    for package in packageInfos:
        info = package['info']
        if(info['Protocol'] in d.keys()):
            d[info['Protocol']] += 1
        else:
            d[info['Protocol']] = 1
    return d


def unique_proto_statistic_bytes(packageInfos):
    d = {}
    for package in packageInfos:
        info = package['info']
        if(info['Protocol'] in d.keys()):
            d[info['Protocol']] += len(corrupt_bytes(package['pkt']))
        else:
            d[info['Protocol']] = len(corrupt_bytes(package['pkt']))
    return d


def proto_flow_bytes(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap.haslayer(IP):
            proto_flow_dict['IP'] += pcap_len
        elif pcap.haslayer(IPv6):
            proto_flow_dict['IPv6'] += pcap_len
        if pcap.haslayer(TCP):
            proto_flow_dict['TCP'] += pcap_len
        elif pcap.haslayer(UDP):
            proto_flow_dict['UDP'] += pcap_len
        if pcap.haslayer(ARP):
            proto_flow_dict['ARP'] += pcap_len
        elif pcap.haslayer(ICMP):
            proto_flow_dict['ICMP'] += pcap_len
        elif pcap.haslayer(DNS):
            proto_flow_dict['DNS'] += pcap_len
        elif pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += pcap_len
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer(UDP):
            udp = pcap.getlayer(UDP)
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer(ICMPv6ND_NS):
            proto_flow_dict['ICMP'] += pcap_len
        else:
            proto_flow_dict['Others'] += pcap_len
    return proto_flow_dict


def proto_flow_frames(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            proto_flow_dict['IP'] += 1
        elif pcap.haslayer(IPv6):
            proto_flow_dict['IPv6'] += 1
        if pcap.haslayer(TCP):
            proto_flow_dict['TCP'] += 1
        elif pcap.haslayer(UDP):
            proto_flow_dict['UDP'] += 1
        if pcap.haslayer(ARP):
            proto_flow_dict['ARP'] += 1
        elif pcap.haslayer(ICMP):
            proto_flow_dict['ICMP'] += 1
        elif pcap.haslayer(DNS):
            proto_flow_dict['DNS'] += 1
        elif pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += 1
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += 1
            else:
                proto_flow_dict['Others'] += 1
        elif pcap.haslayer(UDP):
            udp = pcap.getlayer(UDP)
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += 1
            else:
                proto_flow_dict['Others'] += 1
        elif pcap.haslayer(ICMPv6ND_NS):
            proto_flow_dict['ICMP'] += 1
        else:
            proto_flow_dict['Others'] += 1
    return proto_flow_dict


def get_host_ip(PCAPS):
    ip_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            ip_list.append(pcap.getlayer(IP).src)
            ip_list.append(pcap.getlayer(IP).dst)
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip


def get_public_ip():
    from urllib.request import urlopen
    from json import load
    ip = None
    # four methods to get my public ip
    try:
        ip = urlopen('http://ip.42.pl/raw', timeout=3).read()
        return ip
    except:
        ip = None

    try:
        ip = load(urlopen('http://jsonip.com', timeout=3))['ip']
        return ip
    except:
        ip = None

    try:
        ip = load(urlopen('http://httpbin.org/ip', timeout=3))['origin']
        return ip
    except:
        ip = None

    try:
        ip = load(
            urlopen('https://api.ipify.org/?format=json', timeout=3))['ip']
        return ip
    except:
        ip = None
    return ip


def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            dst = pcap.getlayer(IP).dst
            src = pcap.getlayer(IP).src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass

    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(),
                            key=lambda d: d[1], reverse=False)
    in_len_dict = sorted(in_len_dict.items(),
                         key=lambda d: d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(),
                             key=lambda d: d[1], reverse=False)
    out_len_dict = sorted(out_len_dict.items(),
                          key=lambda d: d[1], reverse=False)
    in_keyp_list = list()
    in_packet_list = list()
    for key, value in in_packet_dict:
        in_keyp_list.append(key)
        in_packet_list.append(value)
    in_keyl_list = list()
    in_len_list = list()
    for key, value in in_len_dict:
        in_keyl_list.append(key)
        in_len_list.append(value)
    out_keyp_list = list()
    out_packet_list = list()
    for key, value in out_packet_dict:
        out_keyp_list.append(key)
        out_packet_list.append(value)
    out_keyl_list = list()
    out_len_list = list()
    for key, value in out_len_dict:
        out_keyl_list.append(key)
        out_len_list.append(value)
    d = {'in_keyp': in_keyp_list, 'in_packet': in_packet_list, 'in_keyl': in_keyl_list, 'in_len': in_len_list,
         'out_keyp': out_keyp_list, 'out_packet': out_packet_list, 'out_keyl': out_keyl_list, 'out_len': out_len_list}
    return d


def time_flow(PCAPS, host_ip):
    in_time_flow_dict = collections.OrderedDict()
    out_time_flow_dict = collections.OrderedDict()
    tmp = [p.time for p in PCAPS]
    start = min(tmp)
    end = max(tmp)
    for i in range(0, int(float("%.1f" % (end-start))*10)+1):
        in_time_flow_dict[i/10.0] = 0
        out_time_flow_dict[i/10.0] = 0
    #timediff = float
    for pkt in PCAPS:
        if(not pkt.haslayer(IP)):
            continue
        if(pkt.getlayer(IP).dst != host_ip):
            continue
        timediff = pkt.time - start
        if float('%.1f' % timediff) in in_time_flow_dict.keys():
            in_time_flow_dict[float('%.1f' % timediff)
                              ] += len(corrupt_bytes(pkt))
        else:
            in_time_flow_dict[float('%.1f' % timediff)] = len(
                corrupt_bytes(pkt))
    for k in in_time_flow_dict.keys():
        in_time_flow_dict[k] = float(
            "%.1f" % (float(in_time_flow_dict[k])/1024.0))

    for pkt in PCAPS:
        if(not pkt.haslayer(IP)):
            continue
        if(pkt.getlayer(IP).src != host_ip):
            continue
        timediff = pkt.time - start
        if float('%.1f' % timediff) in out_time_flow_dict.keys():
            out_time_flow_dict[float('%.1f' % timediff)
                               ] += len(corrupt_bytes(pkt))
        else:
            out_time_flow_dict[float('%.1f' % timediff)] = len(
                corrupt_bytes(pkt))
    for k in out_time_flow_dict.keys():
        out_time_flow_dict[k] = float(
            "%.1f" % (float(out_time_flow_dict[k])/1024.0))

    return in_time_flow_dict, out_time_flow_dict


def get_geo(reader, ip):
    try:
        response = reader.city(ip)
        city_name = response.country.names['zh-CN'] + \
            response.city.names['zh-CN']
        longitude = response.location.longitude
        latitude = response.location.latitude
        return [city_name, longitude, latitude]
    except:
        return None


def get_ipmap(PCAPS, host_ip):
    reader = geoip2.database.Reader('./GeoIp/GeoLite2-City.mmdb')
    ip_value_dict = dict()
    ip_value_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            pcap_len = len(corrupt_bytes(pcap))
            if src == host_ip:
                oip = dst
            else:
                oip = src
            if oip in ip_value_dict:
                ip_value_dict[oip] += pcap_len
            else:
                ip_value_dict[oip] = pcap_len
    for ip, value in ip_value_dict.items():
        geo_list = get_geo(reader, ip)
        if geo_list:
            ip_value_list.append([ip, value, geo_list[0]])
        else:
            pass
    return ip_value_list
