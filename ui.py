# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1250, 800)
        MainWindow.setMinimumSize(QtCore.QSize(1250, 800))
        MainWindow.setMaximumSize(QtCore.QSize(1250, 800))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        MainWindow.setFont(font)
        MainWindow.setIconSize(QtCore.QSize(50, 50))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(10, 10, 1231, 761))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.TophorizontalLayout = QtWidgets.QHBoxLayout()
        self.TophorizontalLayout.setObjectName("TophorizontalLayout")
        self.chooseNIClabel = QtWidgets.QLabel(self.widget)
        self.chooseNIClabel.setMinimumSize(QtCore.QSize(50, 0))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.chooseNIClabel.setFont(font)
        self.chooseNIClabel.setObjectName("chooseNIClabel")
        self.TophorizontalLayout.addWidget(self.chooseNIClabel)
        self.chooseNICComboBox = QtWidgets.QComboBox(self.widget)
        self.chooseNICComboBox.setMinimumSize(QtCore.QSize(300, 0))
        self.chooseNICComboBox.setMaximumSize(QtCore.QSize(200, 16777215))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(9)
        self.chooseNICComboBox.setFont(font)
        self.chooseNICComboBox.setObjectName("chooseNICComboBox")
        self.chooseNICComboBox.addItem("")
        self.TophorizontalLayout.addWidget(self.chooseNICComboBox)
        self.startCaptureBtn = QtWidgets.QPushButton(self.widget)
        self.startCaptureBtn.setObjectName("startCaptureBtn")
        self.TophorizontalLayout.addWidget(self.startCaptureBtn)
        self.stopCapture = QtWidgets.QPushButton(self.widget)
        self.stopCapture.setObjectName("stopCapture")
        self.TophorizontalLayout.addWidget(self.stopCapture)
        self.clearDataBtn = QtWidgets.QPushButton(self.widget)
        self.clearDataBtn.setObjectName("clearDataBtn")
        self.TophorizontalLayout.addWidget(self.clearDataBtn)
        self.saveDataBtn = QtWidgets.QPushButton(self.widget)
        self.saveDataBtn.setObjectName("saveDataBtn")
        self.TophorizontalLayout.addWidget(self.saveDataBtn)
        self.readDataBtn = QtWidgets.QPushButton(self.widget)
        self.readDataBtn.setObjectName("readDataBtn")
        self.TophorizontalLayout.addWidget(self.readDataBtn)
        self.verticalLayout.addLayout(self.TophorizontalLayout)
        self.MidhorizontalLayout = QtWidgets.QHBoxLayout()
        self.MidhorizontalLayout.setObjectName("MidhorizontalLayout")
        self.proTypeLabel = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.proTypeLabel.setFont(font)
        self.proTypeLabel.setObjectName("proTypeLabel")
        self.MidhorizontalLayout.addWidget(self.proTypeLabel)
        self.proTypeChooseBox = QtWidgets.QComboBox(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.proTypeChooseBox.setFont(font)
        self.proTypeChooseBox.setObjectName("proTypeChooseBox")
        self.proTypeChooseBox.addItem("")
        self.proTypeChooseBox.addItem("")
        self.proTypeChooseBox.addItem("")
        self.proTypeChooseBox.addItem("")
        self.proTypeChooseBox.addItem("")
        self.proTypeChooseBox.addItem("")
        self.MidhorizontalLayout.addWidget(self.proTypeChooseBox)
        self.srcIPLabel = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.srcIPLabel.setFont(font)
        self.srcIPLabel.setObjectName("srcIPLabel")
        self.MidhorizontalLayout.addWidget(self.srcIPLabel)
        self.srcIPLineEdit = QtWidgets.QLineEdit(self.widget)
        self.srcIPLineEdit.setObjectName("srcIPLineEdit")
        self.MidhorizontalLayout.addWidget(self.srcIPLineEdit)
        self.srcPortLabel = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.srcPortLabel.setFont(font)
        self.srcPortLabel.setObjectName("srcPortLabel")
        self.MidhorizontalLayout.addWidget(self.srcPortLabel)
        self.srcPortLineEdit = QtWidgets.QLineEdit(self.widget)
        self.srcPortLineEdit.setText("")
        self.srcPortLineEdit.setObjectName("srcPortLineEdit")
        self.MidhorizontalLayout.addWidget(self.srcPortLineEdit)
        self.desIPLabel = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.desIPLabel.setFont(font)
        self.desIPLabel.setObjectName("desIPLabel")
        self.MidhorizontalLayout.addWidget(self.desIPLabel)
        self.desIPLineEdit = QtWidgets.QLineEdit(self.widget)
        self.desIPLineEdit.setObjectName("desIPLineEdit")
        self.MidhorizontalLayout.addWidget(self.desIPLineEdit)
        self.desPortLabel = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.desPortLabel.setFont(font)
        self.desPortLabel.setObjectName("desPortLabel")
        self.MidhorizontalLayout.addWidget(self.desPortLabel)
        self.lineEdit_3 = QtWidgets.QLineEdit(self.widget)
        self.lineEdit_3.setText("")
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.MidhorizontalLayout.addWidget(self.lineEdit_3)
        self.pushButton = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.MidhorizontalLayout.addWidget(self.pushButton)
        self.verticalLayout.addLayout(self.MidhorizontalLayout)
        self.analysisHLayout = QtWidgets.QHBoxLayout()
        self.analysisHLayout.setObjectName("analysisHLayout")
        self.analysisLabel = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.analysisLabel.setFont(font)
        self.analysisLabel.setObjectName("analysisLabel")
        self.analysisHLayout.addWidget(self.analysisLabel)
        self.ProtoCntBnt = QtWidgets.QPushButton(self.widget)
        self.ProtoCntBnt.setObjectName("ProtoCntBnt")
        self.analysisHLayout.addWidget(self.ProtoCntBnt)
        self.inFlowCntBnt = QtWidgets.QPushButton(self.widget)
        self.inFlowCntBnt.setObjectName("inFlowCntBnt")
        self.analysisHLayout.addWidget(self.inFlowCntBnt)
        self.outFlowCntBnt = QtWidgets.QPushButton(self.widget)
        self.outFlowCntBnt.setObjectName("outFlowCntBnt")
        self.analysisHLayout.addWidget(self.outFlowCntBnt)
        self.flowTimeCntBnt = QtWidgets.QPushButton(self.widget)
        self.flowTimeCntBnt.setObjectName("flowTimeCntBnt")
        self.analysisHLayout.addWidget(self.flowTimeCntBnt)
        self.ipMapBnt = QtWidgets.QPushButton(self.widget)
        self.ipMapBnt.setObjectName("ipMapBnt")
        self.analysisHLayout.addWidget(self.ipMapBnt)
        self.verticalLayout.addLayout(self.analysisHLayout)
        self.pktInfoTable = QtWidgets.QTableWidget(self.widget)
        self.pktInfoTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.pktInfoTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.pktInfoTable.setColumnCount(7)
        self.pktInfoTable.setObjectName("pktInfoTable")
        self.pktInfoTable.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setStrikeOut(False)
        item.setFont(font)
        self.pktInfoTable.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.pktInfoTable.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.pktInfoTable.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.pktInfoTable.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.pktInfoTable.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.pktInfoTable.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.pktInfoTable.setHorizontalHeaderItem(6, item)
        self.pktInfoTable.verticalHeader().setVisible(False)
        self.verticalLayout.addWidget(self.pktInfoTable)
        self.BomhorizontalLayout = QtWidgets.QHBoxLayout()
        self.BomhorizontalLayout.setObjectName("BomhorizontalLayout")
        self.pktDetailWin = QtWidgets.QTextEdit(self.widget)
        self.pktDetailWin.setMinimumSize(QtCore.QSize(0, 0))
        self.pktDetailWin.setMaximumSize(QtCore.QSize(450, 16777215))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.pktDetailWin.setFont(font)
        self.pktDetailWin.setStyleSheet("border-right:5px solid #ECECEC;border-top:2px solid #ECECEC")
        self.pktDetailWin.setReadOnly(True)
        self.pktDetailWin.setObjectName("pktDetailWin")
        self.BomhorizontalLayout.addWidget(self.pktDetailWin)
        self.hexDumpWin = QtWidgets.QTextEdit(self.widget)
        self.hexDumpWin.setMinimumSize(QtCore.QSize(0, 0))
        self.hexDumpWin.setStyleSheet("border-top:2px solid #ECECEC")
        self.hexDumpWin.setReadOnly(True)
        self.hexDumpWin.setObjectName("hexDumpWin")
        self.BomhorizontalLayout.addWidget(self.hexDumpWin)
        self.verticalLayout.addLayout(self.BomhorizontalLayout)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Sniffer"))
        self.chooseNIClabel.setText(_translate("MainWindow", "     选择网卡"))
        self.chooseNICComboBox.setCurrentText(_translate("MainWindow", "TEST"))
        self.chooseNICComboBox.setItemText(0, _translate("MainWindow", "TEST"))
        self.startCaptureBtn.setText(_translate("MainWindow", "开始抓包"))
        self.stopCapture.setText(_translate("MainWindow", "停止抓包"))
        self.clearDataBtn.setText(_translate("MainWindow", "清空数据"))
        self.saveDataBtn.setText(_translate("MainWindow", "保存数据"))
        self.readDataBtn.setText(_translate("MainWindow", "读取数据"))
        self.proTypeLabel.setText(_translate("MainWindow", "协议类型"))
        self.proTypeChooseBox.setItemText(0, _translate("MainWindow", "ALL"))
        self.proTypeChooseBox.setItemText(1, _translate("MainWindow", "ARP ONLY"))
        self.proTypeChooseBox.setItemText(2, _translate("MainWindow", "TCP ONLY"))
        self.proTypeChooseBox.setItemText(3, _translate("MainWindow", "UDP ONLY"))
        self.proTypeChooseBox.setItemText(4, _translate("MainWindow", "TCP OR UDP"))
        self.proTypeChooseBox.setItemText(5, _translate("MainWindow", "IP ONLY"))
        self.srcIPLabel.setText(_translate("MainWindow", "源IP地址"))
        self.srcIPLineEdit.setText(_translate("MainWindow", "112.123.414.212"))
        self.srcPortLabel.setText(_translate("MainWindow", "源端口"))
        self.desIPLabel.setText(_translate("MainWindow", "目的IP地址"))
        self.desIPLineEdit.setText(_translate("MainWindow", "112.123.414.212"))
        self.desPortLabel.setText(_translate("MainWindow", "源端口"))
        self.pushButton.setText(_translate("MainWindow", "设置过滤"))
        self.analysisLabel.setText(_translate("MainWindow", "流量统计"))
        self.ProtoCntBnt.setText(_translate("MainWindow", "协议统计"))
        self.inFlowCntBnt.setText(_translate("MainWindow", "流入流量统计"))
        self.outFlowCntBnt.setText(_translate("MainWindow", "流出流量统计"))
        self.flowTimeCntBnt.setText(_translate("MainWindow", "流量时间统计"))
        self.ipMapBnt.setText(_translate("MainWindow", "IP归属地"))
        item = self.pktInfoTable.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "No."))
        item = self.pktInfoTable.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))
        item = self.pktInfoTable.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Src."))
        item = self.pktInfoTable.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Des."))
        item = self.pktInfoTable.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Protocol Type"))
        item = self.pktInfoTable.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Length(bytes)"))
        item = self.pktInfoTable.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Info"))
        self.pktDetailWin.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'微软雅黑\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">TEST</p></body></html>"))
        self.hexDumpWin.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'微软雅黑\'; font-size:10pt;\">TES</span></p></body></html>"))
