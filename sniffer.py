from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from pcap import *
from qtpy.QtWebEngineWidgets import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
import dpkt
import sys
import os
import re
import time
import datetime
import threading
import logging
from analysis import *
from decode import PktInfoGet, PacketDecode
from pcap_extract import extractHtml

logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                    level=logging.DEBUG, filename="log", filemode="w")
logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        logger.info("Sniffer is starting")
        self.setUpUI()
        self.setUpSnifferInfos()
        self.setSignalConnect()

    def setUpUI(self):
        font = QFont("微软雅黑", 8)
        self.title = "Sniffer"
        self.setWindowTitle(self.title)
        self.setFixedSize(1000, 800)

        self.widget = QWidget(self)
        self.HLayoutTop = QHBoxLayout()
        self.HLayoutMiddle = QHBoxLayout()
        self.HLayoutBottom = QHBoxLayout()
        self.HwidgetTop = QWidget()
        self.HwidgetMiddle = QWidget()
        self.HwidgetBottom = QWidget()
        self.VLayout = QVBoxLayout()

        self.setCentralWidget(self.widget)

        # set HLayoutTop to HwidgetTop
        self.chooseNICLabel = QLabel("选择网卡:")
        self.chooseNICLabel.setFixedHeight(20)
        self.chooseNICLabel.setFixedWidth(32)
        self.chooseNICLabel.setAlignment(Qt.AlignCenter)

        self.chooseNICComboBox = QComboBox()
        self.chooseNICComboBox.setFixedHeight(32)
        self.chooseNICComboBox.setFixedWidth(160)
        devs = findalldevs()
        self.chooseNICComboBox.addItems(devs)
        self.chooseNICComboBox.setFont(font)

        self.beginBtn = QPushButton()
        self.beginBtn.setText("开始抓包")
        self.beginBtn.setFixedHeight(32)
        self.beginBtn.setFixedWidth(100)

        self.stopBtn = QPushButton()
        self.stopBtn.setText("停止抓包")
        self.stopBtn.setFixedHeight(32)
        self.stopBtn.setFixedWidth(100)

        self.clearBtn = QPushButton()
        self.clearBtn.setText("清空数据")
        self.clearBtn.setFixedHeight(32)
        self.clearBtn.setFixedWidth(100)

        self.saveBtn = QPushButton()
        self.saveBtn.setText("保存数据")
        self.saveBtn.setFixedHeight(32)
        self.saveBtn.setFixedWidth(100)

        self.loadBtn = QPushButton()
        self.loadBtn.setText("读取数据")
        self.loadBtn.setFixedHeight(32)
        self.loadBtn.setFixedWidth(100)

        self.quitBtn = QPushButton()
        self.quitBtn.setText("退出程序")
        self.quitBtn.setFixedHeight(32)
        self.quitBtn.setFixedWidth(100)

        self.HLayoutTop.addWidget(
            self.chooseNICLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.chooseNICComboBox, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.beginBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.stopBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.clearBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.saveBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.loadBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.quitBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)

        self.HwidgetTop.setLayout(self.HLayoutTop)
        self.HwidgetTop.setFixedWidth(880)
        self.HwidgetTop.setFixedHeight(40)

        # set HLayoutMiddle to HwidgetMiddle
        self.protocolLabel = QLabel()
        self.protocolLabel.setText("协议类型: ")
        self.protocolLabel.setFixedHeight(32)
        self.protocolLabel.setFixedWidth(60)
        self.protocolLabel.setAlignment(Qt.AlignCenter)

        self.protocolComboBox = QComboBox()
        self.protocolComboBox.setFixedHeight(32)
        self.protocolComboBox.setFixedWidth(100)
        tmp = ['all', 'arp only', 'tcp only',
               'udp only', 'tcp or udp', 'ip only']
        self.protocolComboBox.addItems(tmp)
        self.protocolComboBox.setFont(font)

        self.srcIpLabel = QLabel()
        self.srcIpLabel.setText("源地址: ")
        self.srcIpLabel.setFixedHeight(32)
        self.srcIpLabel.setFixedWidth(60)
        self.srcIpLabel.setAlignment(Qt.AlignCenter)

        self.srcIpLineEdit = QLineEdit()
        self.srcIpLineEdit.setFixedHeight(32)
        self.srcIpLineEdit.setFixedWidth(100)
        self.srcIpLineEdit.setFont(font)

        self.srcPortLabel = QLabel()
        self.srcPortLabel.setText("源端口: ")
        self.srcPortLabel.setFixedHeight(32)
        self.srcPortLabel.setFixedWidth(60)
        self.srcPortLabel.setAlignment(Qt.AlignCenter)

        self.srcPortLineEdit = QLineEdit()
        self.srcPortLineEdit.setFixedHeight(32)
        self.srcPortLineEdit.setFixedWidth(40)
        self.srcPortLineEdit.setFont(font)

        self.desIpLabel = QLabel()
        self.desIpLabel.setText("目的地址: ")
        self.desIpLabel.setFixedHeight(32)
        self.desIpLabel.setFixedWidth(60)
        self.desIpLabel.setAlignment(Qt.AlignCenter)

        self.desIpLineEdit = QLineEdit()
        self.desIpLineEdit.setFixedHeight(32)
        self.desIpLineEdit.setFixedWidth(100)
        self.desIpLineEdit.setFont(font)

        self.desPortLabel = QLabel()
        self.desPortLabel.setText("目的端口: ")
        self.desPortLabel.setFixedHeight(32)
        self.desPortLabel.setFixedWidth(60)
        self.desPortLabel.setAlignment(Qt.AlignCenter)

        self.desPortLineEdit = QLineEdit()
        self.desPortLineEdit.setFixedHeight(32)
        self.desPortLineEdit.setFixedWidth(40)
        self.desPortLineEdit.setFont(font)

        self.filterBtn = QPushButton()
        self.filterBtn.setText("设置过滤")
        self.filterBtn.setFixedHeight(32)
        self.filterBtn.setFixedWidth(100)

        self.HLayoutMiddle.addWidget(
            self.protocolLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.protocolComboBox, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcIpLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcIpLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcPortLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcPortLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desIpLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desIpLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desPortLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desPortLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.filterBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HwidgetMiddle.setLayout(self.HLayoutMiddle)
        self.HwidgetMiddle.setFixedHeight(40)

        # statistic
        self.statisticLabel = QLabel()
        self.statisticLabel.setFixedHeight(32)
        self.statisticLabel.setFixedWidth(100)
        self.statisticLabel.setText("统计功能 :")

        self.protoCountBtn = QPushButton()
        self.protoCountBtn.setText("协议统计")
        self.protoCountBtn.setFixedHeight(32)
        self.protoCountBtn.setFixedWidth(100)

        self.inCountBtn = QPushButton()
        self.inCountBtn.setText("流入流量统计")
        self.inCountBtn.setFixedHeight(32)
        self.inCountBtn.setFixedWidth(100)

        self.outCountBtn = QPushButton()
        self.outCountBtn.setText("流出流量统计")
        self.outCountBtn.setFixedHeight(32)
        self.outCountBtn.setFixedWidth(100)

        self.flowtimeBtn = QPushButton()
        self.flowtimeBtn.setText("流量时间统计")
        self.flowtimeBtn.setFixedHeight(32)
        self.flowtimeBtn.setFixedWidth(100)

        self.ipMapBtn = QPushButton()
        self.ipMapBtn.setText("IP所在地")
        self.ipMapBtn.setFixedHeight(32)
        self.ipMapBtn.setFixedWidth(100)

        self.statisitcHLayout = QHBoxLayout()
        self.statisticWidget = QWidget()
        self.statisitcHLayout.addWidget(
            self.statisticLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.protoCountBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.inCountBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.outCountBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.flowtimeBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.ipMapBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisticWidget.setLayout(self.statisitcHLayout)
        self.statisticWidget.setFixedHeight(40)

        # set package info
        # No Time Source Destination Protocol Length Info
        self.packageInfosTable = QTableWidget()
        self.packageInfosTable.verticalHeader().setVisible(False)
        self.packageInfosTable.setColumnCount(7)
        # self.packageInfosTable.setRowCount(50)
        self.packageInfosTable.setHorizontalHeaderLabels(
            ["序号", "时间", "源地址", "目的地址", "协议类型", "长度(bytes)", "信息"])
        self.packageInfosTable.setEditTriggers(
            QAbstractItemView.NoEditTriggers)
        self.packageInfosTable.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.packageInfosTable.setColumnWidth(0, 40)
        self.packageInfosTable.setColumnWidth(1, 140)
        self.packageInfosTable.setColumnWidth(2, 180)
        self.packageInfosTable.setColumnWidth(3, 180)
        self.packageInfosTable.setColumnWidth(4, 60)
        self.packageInfosTable.setColumnWidth(5, 80)
        self.packageInfosTable.setColumnWidth(6, 800)
        self.packageInfosTable.setFixedHeight(350)

        self.packageDetailWin = QTextEdit()
        self.packageDetailWin.setFixedHeight(250)
        self.packageDetailWin.setFixedWidth(345)
        # self.packageDetailWin.setStyleSheet(
        #    "border-right:5px solid #323232;border-top:2px solid #323232")
        self.packageDetailWin.setStyleSheet(
            "border-right:5px solid #ECECEC;border-top:2px solid #ECECEC")
        self.packageDetailWin.setReadOnly(True)
        self.packageDetailWin.setFont(QFont("Source Code Pro", 14))

        self.hexdumpWindow = QTextEdit()
        self.hexdumpWindow.setFixedHeight(250)
        self.hexdumpWindow.setFixedWidth(650)
        # self.hexdumpWindow.setStyleSheet("border-top:2px solid #323232")
        self.hexdumpWindow.setStyleSheet("border-top:2px solid #ECECEC")
        self.hexdumpWindow.setReadOnly(True)
        self.hexdumpWindow.setFont(QFont("Source Code Pro", 14))
        # set HLayoutBottom to HLayoutBottom
        self.HLayoutBottom.addWidget(self.packageDetailWin)
        self.HLayoutBottom.addWidget(self.hexdumpWindow)
        self.HwidgetBottom.setLayout(self.HLayoutBottom)

        # ------
        self.VLayout.addWidget(self.HwidgetTop)
        self.VLayout.addWidget(self.HwidgetMiddle)
        self.VLayout.addWidget(self.statisticWidget)
        self.VLayout.addWidget(self.packageInfosTable)
        self.VLayout.addWidget(self.HwidgetBottom)
        self.widget.setLayout(self.VLayout)
        return

    def setUpSnifferInfos(self):
        if(len(findalldevs()) != 0):
            self.eth = findalldevs()[0]
            logger.info("Set interface %s" % self.eth)
        else:
            self.eth = None
            logger.warning("There is no interface on this os")
        self.protocol = None
        self.srcIp = None
        self.srcPort = None
        self.desIp = None
        self.desPort = None
        self.packageInfos = []
        self.indexes = []
        self.stop_flag = False  # False: not stop; True: stop
        self.setfilter_flag = False  # False: have't set filter; True: have be setted
        self.filterString = ""
        self.pcapdecoder = PacketDecode()

    def setSignalConnect(self):
        self.quitBtn.clicked.connect(self.quitBtnHandle)
        self.chooseNICComboBox.activated.connect(self.chooseNICComboBoxHandle)
        self.beginBtn.clicked.connect(self.beginBtnHandle)
        self.stopBtn.clicked.connect(self.stopBtnHandle)
        self.clearBtn.clicked.connect(self.clearBtnHandle)
        self.saveBtn.clicked.connect(self.saveBtnHandle)
        self.loadBtn.clicked.connect(self.loadBtnHandle)

        self.filterBtn.clicked.connect(self.filterBtnHandle)

        self.protoCountBtn.clicked.connect(self.protoCountBtnHandle)
        self.inCountBtn.clicked.connect(self.inCountBtnHandle)
        self.outCountBtn.clicked.connect(self.outCountBtnHandle)
        self.flowtimeBtn.clicked.connect(self.flowtimeBtnHandle)
        self.ipMapBtn.clicked.connect(self.ipMapBtnHandle)

        self.packageInfosTable.clicked.connect(self.packageInfosTableHandle)
        self.packageInfosTable.doubleClicked.connect(self.extractHtmlHandle)

    def ipMapBtnHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if(pkts == []):
            QMessageBox.warning(self, "警告", "当前无pcap包",
                                QMessageBox.Yes, QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        d = get_ipmap(pkts, host_ip)
        view = QTableWidget()
        view.verticalHeader().setVisible(False)
        view.setColumnCount(3)
        view.setHorizontalHeaderLabels(["IP", "地理位置", "流量"])
        view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        view.setSelectionBehavior(QAbstractItemView.SelectRows)
        view.setColumnWidth(0, 160)
        view.setColumnWidth(1, 120)
        view.setColumnWidth(1, 180)
        font = QFont("Source Code Pro", 14)
        for i in range(len(d)):
            view.insertRow(i)
            tmp = QTableWidgetItem(d[i][0])
            tmp.setFont(font)
            view.setItem(i, 0, tmp)
            tmp = QTableWidgetItem(d[i][2])
            tmp.setFont(font)
            view.setItem(i, 1, tmp)
            tmp = QTableWidgetItem(str(d[i][1])+" bytes")
            tmp.setFont(font)
            view.setItem(i, 2, tmp)
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(480)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def extractHtmlHandle(self, index):
        row = index.row()
        row = self.indexes[row]
        if(self.packageInfos[row]['info']['Protocol'] != 'HTTP'):
            return
        pkt = self.packageInfos[row]['pkt']
        if(not pkt.haslayer(IP)):
            return
        ip = pkt.getlayer(IP).src
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if(pkts == []):
            return
        host_ip = get_host_ip(pkts)
        logger.info(logger.info("host_ip: %s", host_ip))
        d = extractHtml(pkts, host_ip)
        #ip_port_data_list.append({'data_id': data_id, 'ip_port': ip_port,'data': data,  "index_list": load_list})
        for i in range(0, len(d)):
            if(d[i]['ip_port'].startswith(ip) and d[i]['ip_port'].split(":")[1] == str(pkt.dport)):
                with open("./htmls/render.html", "w") as f:
                    f.write(d[i]['data'])
                QMessageBox.information(
                    self, "提醒", "网页存储在htmls/render.html", QMessageBox.Yes, QMessageBox.Yes)
                view = QPlainTextEdit()
                font = QFont("Source Code Pro", 14)
                view.setFont(font)
                view.setPlainText(d[i]['data'].strip())
                dialog = QDialog(self)
                dialog.setFixedHeight(600)
                dialog.setFixedWidth(1000)
                l = QHBoxLayout()
                l.addWidget(view)
                dialog.setLayout(l)
                dialog.show()
                return
                # 124.16.77.200:59307:HTTP
        QMessageBox.information(
            self, "提醒", "未提取到http内容", QMessageBox.Yes, QMessageBox.Yes)

    def flowtimeBtnHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if(pkts == []):
            QMessageBox.warning(self, "警告", "当前无pcap包",
                                QMessageBox.Yes, QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        in_data, out_data = time_flow(pkts, host_ip)
        in_x = in_data.keys()
        in_y = [in_data[k] for k in in_data.keys()]
        out_y = [out_data[k] for k in out_data.keys()]
        line = line_base(in_x, in_y, out_y)
        line.render("./htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def outCountBtnHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if(pkts == []):
            QMessageBox.warning(self, "警告", "当前无pcap包",
                                QMessageBox.Yes, QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        d = data_in_out_ip(pkts, host_ip)
        data_frames = [[ip, frame]
                       for ip, frame in zip(d['out_keyp'], d['out_packet'])]
        data_bytes = [[ip, byte]
                      for ip, byte in zip(d['out_keyl'], d['out_len'])]
        pie = pie_base(data_frames, data_bytes, "流出流量统计")
        pie.render("./htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def inCountBtnHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if(pkts == []):
            QMessageBox.warning(self, "警告", "当前无pcap包",
                                QMessageBox.Yes, QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        d = data_in_out_ip(pkts, host_ip)
        data_frames = [[ip, frame]
                       for ip, frame in zip(d['in_keyp'], d['in_packet'])]
        data_bytes = [[ip, byte]
                      for ip, byte in zip(d['in_keyl'], d['in_len'])]
        pie = pie_base(data_frames, data_bytes, "流入流量统计")
        pie.render("./htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def protoCountBtnHandle(self):
        if(self.packageInfos == []):
            QMessageBox.warning(self, "警告", "当前无pcap包",
                                QMessageBox.Yes, QMessageBox.Yes)
            return
        datas = unique_proto_statistic_frame(self.packageInfos)
        data_frames = []
        for k, v in datas.items():
            data_frames.append([k, v])
        datas = unique_proto_statistic_bytes(self.packageInfos)
        data_bytes = []
        for k, v in datas.items():
            data_bytes.append([k, v])
        pie = pie_base(data_frames, data_bytes, "协议统计")
        pie.render("./htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def packageInfosTableHandle(self, index):
        row = index.row()
        row = self.indexes[row]
        self.hexdumpWindow.setText(
            hexdump(self.packageInfos[row]['pkt'], dump=True))
        # detail show
        data = ""
        packageInfo = self.packageInfos[row]
        data += "Frame %d:\n\tlength: %d bytes\n\tinterface: %s\n" % (
            index.row()+1, packageInfo['info']['len'], packageInfo['eth'])
        data += PktInfoGet(packageInfo['pkt'])
        self.packageDetailWin.setText(data)

    def loadBtnHandle(self):
        logger.info("Load package begin")
        file, ok = QFileDialog.getOpenFileName(self)
        if(file == ''):
            logger.warning("Load file name is None")
            return
        self.clearBtnHandle()
        pkts = rdpcap(file)
        for i in range(len(pkts)):
            self.deal_package(pkts[i])
        logger.info("Load package done")

    def saveBtnHandle(self):
        logger.info("Save package begin")
        file, ok = QFileDialog.getSaveFileName(self)
        if(file == ''):
            logger.warning("Save file name is None")
            return
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        wrpcap(file, pkts)
        logger.info("Save package done")

    def clearBtnHandle(self):
        logger.info("Clean packages begin")
        self.packageInfos = []
        self.indexes = []
        count = self.packageInfosTable.rowCount()
        for i in range(count-1, -1, -1):
            self.packageInfosTable.removeRow(i)
        self.hexdumpWindow.clear()
        self.packageDetailWin.clear()
        logger.info("Clean packages done")

    def quitBtnHandle(self):
        self.stopBtnHandle()
        qApp = QApplication.instance()
        logger.info("Sniffer is shutting down")
        qApp.quit()

    def chooseNICComboBoxHandle(self):
        self.eth = self.chooseNICComboBox.currentText()
        logger.info("Set interface %s" % self.eth)

    def beginBtnHandle(self):
        logger.info("Begin sniff on interface %s" % self.eth)
        self.stop_flag = False
        th = threading.Thread(target=self.capture_packages)
        th.start()

    def capture_packages(self):
        logger.info("Capture begin")
        while(not self.stop_flag):
            sniff(filter=self.filterString,
                  prn=self.deal_package, iface=self.eth, count=5)
        logger.info("Capture finish")

    def deal_package(self, pkt):
        info = self.pcapdecoder.etherProtoParsing(pkt)
        self.packageInfos.append({'pkt': pkt, 'info': info, 'eth': self.eth})
        self.indexes.append(len(self.packageInfos)-1)
        self.showOnTable(info)

    def showOnTable(self, info):
        count = self.packageInfosTable.rowCount()
        self.packageInfosTable.insertRow(count)
        # ["序号", "时间", "源地址", "目的地址", "协议类型", "长度", "信息"]
        font = QFont("Source Code Pro", 14)
        tmp = QTableWidgetItem(str(count+1))
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 0, tmp)
        tmp = QTableWidgetItem(info['time'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 1, tmp)
        tmp = QTableWidgetItem(info['Source'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 2, tmp)
        tmp = QTableWidgetItem(info['Destination'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 3, tmp)
        tmp = QTableWidgetItem(info['Protocol'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 4, tmp)
        tmp = QTableWidgetItem(str(info['len']))
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 5, tmp)
        tmp = QTableWidgetItem(info['info'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 6, tmp)

    def stopBtnHandle(self):
        self.stop_flag = True
        logger.info("Stop sniff on interface %s" % self.eth)

    def get_ip(self, ip):
        ip = ip.replace("\r", "")
        ip = ip.replace("\t", "")
        ip = ip.replace("\n", "")
        ip = ip.replace(" ", "")
        if(ip == ""):
            return ""
        trueIp = re.search(
            r'^(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])$', ip)
        if(trueIp == None):
            QMessageBox.warning(self, "警告", "ip格式有误，请重新输入",
                                QMessageBox.Yes, QMessageBox.Yes)
            return None
        return trueIp.string

    def get_port(self, port):
        port = port.replace("\r", "")
        port = port.replace("\t", "")
        port = port.replace("\n", "")
        port = port.replace(" ", "")
        if(port == ""):
            return -1
        try:
            port = int(port)
            if(port >= 0 and port <= 65535):
                return port
        except:
            QMessageBox.warning(self, "警告", "端口格式有误，请重新输入",
                                QMessageBox.Yes, QMessageBox.Yes)
            return None
        return -1

    def filterBtnHandle(self):
        # 1.filter the data showed on the table
        # 2.set the para for sniffer
        d = {'all': "", 'arp only': "arp", 'tcp only': "tcp",
             'udp only': "udp", 'tcp or udp': '(tcp or udp)', 'ip only': "ip"}
        self.protocol = d[self.protocolComboBox.currentText()]
        logger.info("Set protocol: %s" % self.protocol)
        tmp_srcIp = ""
        tmp_srcPort = -1
        tmp_desIp = ""
        tmp_desPort = -1
        tmp_srcIp = self.get_ip(self.srcIpLineEdit.text())
        if(tmp_srcIp == None):
            logger.info("Set srcIp error" % self.srcIp)
            return
        tmp_srcPort = self.get_port(self.srcPortLineEdit.text())
        if(tmp_srcPort == None):
            logger.info("Set srcPort error" % self.srcIp)
            return
        tmp_desIp = self.get_ip(self.desIpLineEdit.text())
        if(tmp_desIp == None):
            logger.info("Set desIp error" % self.srcIp)
            return
        tmp_desPort = self.get_port(self.desPortLineEdit.text())
        if(tmp_desPort == None):
            logger.info("Set desPort error" % self.srcIp)
            return
        self.srcIp = tmp_srcIp
        self.srcPort = tmp_srcPort
        self.desIp = tmp_desIp
        self.desPort = tmp_desPort
        logger.info("Set srcIp: %s" % self.srcIp)
        logger.info("Set srcPort: %s" % self.srcPort)
        logger.info("Set desIp: %s" % self.desIp)
        logger.info("Set desPort: %s" % self.desPort)
        tmp = []
        tmp.append(self.protocol) if(self.protocol != "") else None
        tmp.append("src host %s" % self.srcIp) if(self.srcIp != "") else None
        tmp.append("src port %d" % self.srcPort) if(
            self.srcPort != -1) else None
        tmp.append("dst host %s" % self.desIp) if(self.desIp != "") else None
        tmp.append("dst port %d" % self.desPort) if(
            self.desPort != -1) else None
        self.filterString = " and ".join(tmp)
        logger.info("filter string is: %s" % self.filterString)

        # filter the packets have shown on the table
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        # d = {'all': "", 'arp only': "arp", 'tcp only': "tcp",
        #     'udp only': "udp", 'tcp or udp': '(tcp or udp)', 'ip only': "ip"}
        indexs = [i for i in range(len(pkts))]
        tmp = []
        if(self.protocol == ""):
            tmp = indexs
        elif(self.protocol == 'arp'):
            for i in indexs:
                if("ARP" in pkts[i].summary()):
                    tmp.append(i)
        elif(self.protocol == 'tcp'):
            for i in indexs:
                if(pkts[i].haslayer(TCP)):
                    tmp.append(i)
        elif(self.protocol == 'udp'):
            for i in indexs:
                if(pkts[i].haslayer(UDP)):
                    tmp.append(i)
        elif(self.protocol == '(tcp or udp)'):
            for i in indexs:
                if(pkts[i].haslayer(UDP) or pkts[i].haslayer(TCP)):
                    tmp.append(i)
        elif(self.protocol == 'ip'):
            for i in indexs:
                if(pkts[i].haslayer(IP)):
                    tmp.append(i)

        indexs = tmp
        tmp = []
        if(self.srcIp != ""):
            for i in indexs:
                if(pkts[i].haslayer(IP) and pkts[i].getlayer(IP).src == self.srcIp):
                    tmp.append(i)
        else:
            tmp = indexs
        indexs = tmp
        tmp = []
        if(self.srcPort != -1):
            for i in indexs:
                if(pkts[i].sport == self.srcPort):
                    tmp.append(i)
        else:
            tmp = indexs

        indexs = tmp
        tmp = []
        if(self.desIp != ""):
            for i in indexs:
                if(pkts[i].haslayer(IP) and pkts[i].getlayer(IP).dst == self.srcIp):
                    tmp.append(i)
        else:
            tmp = indexs

        indexs = tmp
        tmp = []
        if(self.desPort != -1):
            for i in indexs:
                if(pkts[i].dport == self.desPort):
                    tmp.append(i)
        else:
            tmp = indexs
        indexs = tmp

        self.indexes = indexs
        count = self.packageInfosTable.rowCount()
        for i in range(count-1, -1, -1):
            self.packageInfosTable.removeRow(i)
        self.hexdumpWindow.clear()
        self.packageDetailWin.clear()
        for i in self.indexes:
            self.showOnTable(self.packageInfos[i]['info'])


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("./res/img/icon.ico"))
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())

