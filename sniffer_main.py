from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from ui import Ui_MainWindow
from pcap import *
from qtpy.QtWebEngineWidgets import *
from analysis import *
from decode import PktInfoGet, PacketDecode
from pcap_extract import extractHtml

logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                    level=logging.DEBUG, filename="log", filemode="w")
logger = logging.getLogger(__name__)

class MainWindow(Ui_MainWindow, QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        logger.info("Sniffer is starting")
        self.setupUi(self)
        self.setSifferInfo()
        self.signalConnect()

        #分组消息窗口默认固定
        self.pktInfoTable.setColumnWidth(0, 50)
        self.pktInfoTable.setColumnWidth(1, 140)
        self.pktInfoTable.setColumnWidth(2, 180)
        self.pktInfoTable.setColumnWidth(3, 180)
        self.pktInfoTable.setColumnWidth(4, 60)
        self.pktInfoTable.setColumnWidth(5, 80)
        self.pktInfoTable.setColumnWidth(6, 800)

        devs = findalldevs()
        self.chooseNICComboBox.addItems(devs)

    def setSifferInfo(self):
        if (len(findalldevs()) != 0):
            #Windows 修改
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

    def signalConnect(self):
        #第1行
        self.chooseNICComboBox.activated.connect(self.chooseNICHandle)
        self.startCaptureBtn.clicked.connect(self.startBtnHandle)
        self.stopCapture.clicked.connect(self.stopBtnHandle)
        self.clearDataBtn.clicked.connect(self.clearDataBtnHandle)
        self.saveDataBtn.clicked.connect(self.saveDataBtnHandle)
        self.readDataBtn.clicked.connect(self.readDataBtnHandle)
        #第2,3
        self.filterBtn.clicked.connect(self.filterBtnHandle)
        self.ProtoCntBnt.clicked.connect(self.ProtoCntBntHandle)
        self.inFlowCntBnt.clicked.connect(self.inFlowCntBntHandle)
        self.outFlowCntBnt.clicked.connect(self.outFlowCntBntHandle)
        self.flowTimeCntBnt.clicked.connect(self.flowTimeCntBntHandle)
        self.ipMapBnt.clicked.connect(self.ipMapBntHandle)
        #窗体
        self.pktInfoTable.clicked.connect(self.pktInfoTableHandle)
        self.pktInfoTable.doubleClicked.connect(self.extracHtmlHandle)

    def chooseNICHandle(self):
        self.eth = self.chooseNICComboBox.currentText()
        logger.info("Set interface %s" % self.eth)

    def startBtnHandle(self):
        logger.info("Begin sniff on interface %s" % self.eth)
        self.stop_flag = False
        th = threading.Thread(target=self.capturePkt)
        th.start()

    def capturePkt(self):
        logger.info("Capture Start")
        while not self.stop_flag:
            sniff(filter=self.filterString,
                  prn=self.dealWithPkt,
                  iface=self.eth,
                  count=5)
        logger.info("Capture Finish")

    def dealWithPkt(self, pkt):
        info = self.pcapdecoder.etherProtoParsing(pkt)
        self.packageInfos.append({'pkt': pkt, 'info': info, 'eth': self.eth})
        self.indexes.append(len(self.packageInfos) - 1)
        self.displayInfo(info)

    def displayInfo(self, info):
        count = self.pktInfoTable.rowCount()
        self.pktInfoTable.insertRow(count)
        # ["序号", "时间", "源地址", "目的地址", "协议类型", "长度", "信息"]
        font = QFont("微软雅黑", 10)
        tmp = QTableWidgetItem(str(count + 1))
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 0, tmp)
        tmp = QTableWidgetItem(info['time'])
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 1, tmp)
        tmp = QTableWidgetItem(info['Source'])
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 2, tmp)
        tmp = QTableWidgetItem(info['Destination'])
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 3, tmp)
        tmp = QTableWidgetItem(info['Protocol'])
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 4, tmp)
        tmp = QTableWidgetItem(str(info['len']))
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 5, tmp)
        tmp = QTableWidgetItem(info['info'])
        tmp.setFont(font)
        self.pktInfoTable.setItem(
            count, 6, tmp)

    def stopBtnHandle(self):
        self.stop_flag = True
        logger.info("Stop sniff on interface %s" % self.eth)

    #重载closeEvent
    def closeEvent(self, qcloseevent):
        reply = QMessageBox.question(self,
                                     'Message',
                                     "确定退出吗?",
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.stopBtnHandle()
            qcloseevent.accept()
        else:
            qcloseevent.ignore()

    def clearDataBtnHandle(self):
        logger.info("Clean packages begin")
        self.packageInfos = []
        self.indexes = []
        count = self.pktInfoTable.rowCount()
        #倒序删除，正序可能无法删除完全
        for i in range(count - 1, -1, -1):
            self.pktInfoTable.removeRow(i)
        self.hexDumpWin.clear()
        self.pktDetailWin.clear()
        logger.info("Clean packages done")

    def saveDataBtnHandle(self):
        logger.info("Save package begin")
        file, ok = QFileDialog.getSaveFileName(self)
        if (file == ''):
            logger.warning("Save file name is None")
            return
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        wrpcap(file, pkts)
        logger.info("Save package done")

    def readDataBtnHandle(self):
        logger.info("Load package begin")
        file, ok = QFileDialog.getOpenFileName(self)
        if (file == ''):
            logger.warning("Load file name is None")
            return
        self.clearBtnHandle()
        pkts = rdpcap(file)
        for i in range(len(pkts)):
            self.deal_package(pkts[i])
        logger.info("Load package done")

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
        if (tmp_srcIp == None):
            logger.info("Set srcIp error" % self.srcIp)
            return
        tmp_srcPort = self.get_port(self.srcPortLineEdit.text())
        if (tmp_srcPort == None):
            logger.info("Set srcPort error" % self.srcIp)
            return
        tmp_desIp = self.get_ip(self.desIpLineEdit.text())
        if (tmp_desIp == None):
            logger.info("Set desIp error" % self.srcIp)
            return
        tmp_desPort = self.get_port(self.desPortLineEdit.text())
        if (tmp_desPort == None):
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
        tmp.append(self.protocol) if (self.protocol != "") else None
        tmp.append("src host %s" % self.srcIp) if (self.srcIp != "") else None
        tmp.append("src port %d" % self.srcPort) if (
                self.srcPort != -1) else None
        tmp.append("dst host %s" % self.desIp) if (self.desIp != "") else None
        tmp.append("dst port %d" % self.desPort) if (
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
        if (self.protocol == ""):
            tmp = indexs
        elif (self.protocol == 'arp'):
            for i in indexs:
                if ("ARP" in pkts[i].summary()):
                    tmp.append(i)
        elif (self.protocol == 'tcp'):
            for i in indexs:
                if (pkts[i].haslayer(TCP)):
                    tmp.append(i)
        elif (self.protocol == 'udp'):
            for i in indexs:
                if (pkts[i].haslayer(UDP)):
                    tmp.append(i)
        elif (self.protocol == '(tcp or udp)'):
            for i in indexs:
                if (pkts[i].haslayer(UDP) or pkts[i].haslayer(TCP)):
                    tmp.append(i)
        elif (self.protocol == 'ip'):
            for i in indexs:
                if (pkts[i].haslayer(IP)):
                    tmp.append(i)

        indexs = tmp
        tmp = []
        if (self.srcIp != ""):
            for i in indexs:
                if (pkts[i].haslayer(IP) and pkts[i].getlayer(IP).src == self.srcIp):
                    tmp.append(i)
        else:
            tmp = indexs
        indexs = tmp
        tmp = []
        if (self.srcPort != -1):
            for i in indexs:
                if (pkts[i].sport == self.srcPort):
                    tmp.append(i)
        else:
            tmp = indexs

        indexs = tmp
        tmp = []
        if (self.desIp != ""):
            for i in indexs:
                if (pkts[i].haslayer(IP) and pkts[i].getlayer(IP).dst == self.srcIp):
                    tmp.append(i)
        else:
            tmp = indexs

        indexs = tmp
        tmp = []
        if (self.desPort != -1):
            for i in indexs:
                if (pkts[i].dport == self.desPort):
                    tmp.append(i)
        else:
            tmp = indexs
        indexs = tmp

        self.indexes = indexs
        count = self.pktInfoTable.rowCount()
        for i in range(count - 1, -1, -1):
            self.pktInfoTable.removeRow(i)
        self.hexDumpWin.clear()
        self.pktDetailWin.clear()
        for i in self.indexes:
            self.showOnTable(self.packageInfos[i]['info'])

    def ProtoCntBntHandle(self):
        if(self.packageInfos == []):
            QMessageBox.warning(self, "Warning",
                                "当前无Pcap包",
                                QMessageBox.Yes,
                                QMessageBox.No)
            return
        datas = unique_proto_statistic_frame(self.packageInfos)
        data_frames = []
        for i, j in datas.items():
            data_frames.append([i, j])
            datas = unique_proto_statistic_bytes(self.packageInfos)
        data_byte = []
        for i, j in datas.items():
            data_byte.append([i, j])
        pie = pie_base(data_frames, data_byte, "协议统计")
        pie.render("./res/htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/res/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        t = QHBoxLayout()
        t.addWidget(view)
        dialog.setLayout(t)
        dialog.show()

    def inFlowCntBntHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if (pkts == []):
            QMessageBox.warning(self, "Warning",
                                "当前无pcap包",
                                QMessageBox.Yes,
                                QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        d = data_in_out_ip(pkts, host_ip)
        data_frames = [[ip, frame]
                       for ip, frame in zip(d['in_keyp'], d['in_packet'])]
        data_bytes = [[ip, byte]
                      for ip, byte in zip(d['in_keyl'], d['in_len'])]
        pie = pie_base(data_frames, data_bytes, "流入流量统计")
        pie.render("./res/htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/res/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def outFlowCntBntHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if (pkts == []):
            QMessageBox.warning(self, "Warning",
                                "当前无pcap包",
                                QMessageBox.Yes,
                                QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        d = data_in_out_ip(pkts, host_ip)
        data_frames = [[ip, frame]
                       for ip, frame in zip(d['out_keyp'], d['out_packet'])]
        data_bytes = [[ip, byte]
                      for ip, byte in zip(d['out_keyl'], d['out_len'])]
        pie = pie_base(data_frames, data_bytes, "流出流量统计")
        pie.render("./res/htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/res/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def flowTimeCntBntHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if (pkts == []):
            QMessageBox.warning(self, "Warning",
                                "当前无pcap包",
                                QMessageBox.Yes,
                                QMessageBox.Yes)
            return
        host_ip = get_host_ip(pkts)
        logger.info("host_ip: %s", host_ip)
        in_data, out_data = time_flow(pkts, host_ip)
        in_x = in_data.keys()
        in_y = [in_data[k] for k in in_data.keys()]
        out_y = [out_data[k] for k in out_data.keys()]
        line = line_base(in_x, in_y, out_y)
        line.render("./res/htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/res/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(1000)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def ipMapBntHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if (pkts == []):
            QMessageBox.warning(self,
                                "警告",
                                "当前无pcap包",
                                QMessageBox.Yes,
                                QMessageBox.Yes)
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
        font = QFont("微软雅黑", 12)
        for i in range(len(d)):
            view.insertRow(i)
            tmp = QTableWidgetItem(d[i][0])
            tmp.setFont(font)
            view.setItem(i, 0, tmp)
            tmp = QTableWidgetItem(d[i][2])
            tmp.setFont(font)
            view.setItem(i, 1, tmp)
            tmp = QTableWidgetItem(str(d[i][1]) + " bytes")
            tmp.setFont(font)
            view.setItem(i, 2, tmp)
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(480)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def pktInfoTableHandle(self, index):
        row = index.row()
        row = self.indexes[row]
        self.hexDumpWin.setText(
            hexdump(self.packageInfos[row]['pkt']), dump=True
        )
        data = ""
        pktinfo = self.packageInfos[row]
        data += "Frame %d:\n\tlength: %d bytes\n\tinterface: %s\n" % (
            index.row() + 1, pktinfo['info']['len'], pktinfo['eth']
        )
        data += PktInfoGet(pktinfo['pkt'])
        self.pktDetailWin.setText(data)

    def extracHtmlHandle(self, index):
        row = index.row()
        row = self.indexes[row]
        if self.packageInfos[row]['info']['Protocol'] != 'HTTP':
            return
        pkt = self.packageInfos[row]['pkt']
        if not pkt.haslayer(IP):
            return
        ip = pkt.getlayer(IP).src
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        if pkts == []:
            return
        host_ip = get_host_ip(pkts)
        logger.info(logger.info("host_ip: %s", host_ip))
        d = extractHtml(pkts, host_ip)
        for i in range(0, len(d)):
            if(d[i]['ip_port'].startswith(ip) and d[i]['ip_port'].split(":")[1] == str(pkt.dport)):
                with open("./res/htmls/render.html", "w") as f:
                    f.write(d[i]['data'])
                QMessageBox.information(
                    self, "提醒", "网页存储在/res/htmls/render.html", QMessageBox.Yes, QMessageBox.Yes)
                view = QPlainTextEdit()
                font = QFont("微软雅黑", 12)
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
            self, "提醒",
            "未提取到http内容",
            QMessageBox.Yes,
            QMessageBox.Yes)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("./res/img/icon.ico"))
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())