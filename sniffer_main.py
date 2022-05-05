import threading

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import ui
from pcap import *
from qtpy.QtWebEngineWidgets import *
from analysis import *
from decode import PktInfoGet, PacketDecode
from pcap_extract import extractHtml

logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                    level=logging.DEBUG, filename="log", filemode="w")
logger = logging.getLogger(__name__)

class MainWindow(QMainWindow, ui.Ui_MainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        logger.info("Sniffer is starting")
        self.initUi()
        self.signalConnect()
        self.setSifferInfo()

    def initUI(self):
        #分组消息窗口默认固定
        self.pktInfoTable.setColumnWidth(0, 50)
        self.pktInfoTable.setColumnWidth(1, 140)
        self.pktInfoTable.setColumnWidth(2, 180)
        self.pktInfoTable.setColumnWidth(3, 180)
        self.pktInfoTable.setColumnWidth(4, 60)
        self.pktInfoTable.setColumnWidth(5, 80)
        self.pktInfoTable.setColumnWidth(6, 800)

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
        self.chooseNICComboBox.activated.connect(self.chooseNICHandle)#
        self.startCaptureBtn.clicked.connect(self.startBtnHandle)#
        self.stopCapture.clicked.connect(self.stopBtnHandle)#
        self.clearDataBtn.clicked.connect(self.clearDataBtnHandle)
        self.saveDataBtn.clicked.connect(self.saveDataBtnHandle)
        self.readDataBtn.clicked.connect(self.readDataBtnHandle)
        #第2,3行
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

    def saveDataBtn(self):
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

    def readDataBtn(self):
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