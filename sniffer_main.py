from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import ui
from ui import *
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

    def signalConnect(self):



