#!/usr/bin/env python3
# coding:utf-8

import sys, os
if hasattr(sys, 'frozen'):
    os.environ['PATH'] = sys._MEIPASS + ";" + os.environ['PATH']
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QTimer,QCoreApplication
from PyQt5.QtGui import QIntValidator, QPalette, QBrush, QPixmap, QImage,QFont
import IPLineEdit
import socket, re
import img
from xml.etree import ElementTree as ET
from snmp import *

class MyWin(QWidget):
    def __init__(self):
        super(MyWin, self).__init__()
        self.UI()
    #界面设置
    def UI(self):
        self.setFixedSize(450, 580)
        self.setWindowTitle("数据发送")
        self.bg = QPixmap(":/source/bg.png")
        paletteShow = QPalette()
        paletteShow.setBrush(self.backgroundRole(), QBrush(self.bg))
        self.setPalette(paletteShow)
        self.Center()
        self.Grid()
        self.numtime = 0
        self.snmpset = None
        self.show()

    # 消息发送设置界面
    def SendSetting(self):
        setting = QGroupBox('发送设置')
        setting.setFixedWidth(260)
        g1 = QGridLayout()
        l1 = QLabel('协议:')
        l1.setFixedWidth(35)
        self.rbsyslog = QRadioButton('Syslog')
        self.rbsyslog.setFixedWidth(84)
        self.rbsnmp = QRadioButton('SNMP')
        self.rbsnmp.setFixedWidth(84)
        self.rbsyslog.setChecked(True)
        bg2 = QButtonGroup(self)
        bg2.addButton(self.rbsyslog)
        bg2.addButton(self.rbsnmp)
        bg2.buttonClicked.connect(self.Sendsetting)

        l2 = QLabel('方式:')
        bg1 = QButtonGroup(self)
        self.rbtimes = QRadioButton('按次数发送')
        self.rbspeed = QRadioButton('按速度发送')
        self.rbtimes.setChecked(True)
        bg1.addButton(self.rbtimes, 21)
        bg1.addButton(self.rbspeed, 22)
        bg1.buttonClicked.connect(self.SelectMethod)

        self.enum = QLineEdit()
        self.enum.setFixedWidth(40)
        self.enum.insert('1')
        self.etime = QLineEdit()
        self.etime.setFixedWidth(40)
        self.etime.insert('1')
        self.etime.setReadOnly(True)
        self.etime.setStyleSheet("background-color:#f0f0f0")
        l3 = QLabel('次/秒')
        l3.setAlignment(Qt.AlignLeft)
        l3.setFixedWidth(35)

        g1.addWidget(l1, 0, 0, 1, 1)
        g1.addWidget(self.rbsyslog, 0, 1, 1, 1)
        g1.addWidget(self.rbsnmp, 0, 2, 1, 1)
        g1.addWidget(l2, 1, 0, 1, 1)
        g1.addWidget(self.rbtimes, 1, 1, 1, 1)
        g1.addWidget(self.rbspeed, 1, 2, 1, 1)
        g1.addWidget(self.enum, 2, 1, 1, 1)
        g1.addWidget(self.etime, 2, 2, 1, 1)
        g1.addWidget(l3, 2, 3, 1, 1)

        setting.setLayout(g1)
        return setting

    # 次数和速度输入框状态调整
    def SelectMethod(self):
        if self.rbtimes.isChecked():
            self.enum.setReadOnly(False)
            self.enum.setStyleSheet("background-color:#ffffff")
            self.etime.setReadOnly(True)
            self.etime.setStyleSheet("background-color:#f0f0f0")
        elif self.rbspeed.isChecked():
            self.enum.setReadOnly(True)
            self.enum.setStyleSheet("background-color:#f0f0f0")
            self.etime.setReadOnly(False)
            self.etime.setStyleSheet("background-color:#ffffff")

    #发包协议调整
    def Sendsetting(self):
        if self.rbsnmp.isChecked():
            try:
                if self.snmpset is None:
                    self.snmpset = SnmpSetting(self)
                else:
                    # print(self.snmpset.authinfo)
                    self.snmpset = SnmpSetting(self,self.snmpset.authinfo)
            except Exception as e:
                print(e)


    # 发送控制界面
    def SendControl(self):
        control = QGroupBox('发送控制')
        v2 = QVBoxLayout()

        h1 = QHBoxLayout()
        self.initbutton = QPushButton('初始化通信')
        self.initbutton.setFixedSize(68, 25)
        self.initbutton.clicked.connect(self.InitConnection)

        self.sendbutton = QPushButton('发送')
        self.sendbutton.clicked.connect(self.sendData)
        self.sendbutton.setFixedSize(68, 25)

        h1.addWidget(self.initbutton)
        h1.addWidget(self.sendbutton)

        h2 = QHBoxLayout()
        self.quitbutton = QPushButton('退出通信')
        self.quitbutton.setFixedSize(68, 25)
        self.quitbutton.clicked.connect(self.QuitConnection)

        self.stopbutton = QPushButton('停止')
        self.stopbutton.setFixedSize(68, 25)
        self.stopbutton.clicked.connect(self.stopData)
        h2.addWidget(self.quitbutton)
        h2.addWidget(self.stopbutton)

        h3 = QHBoxLayout()
        l1 = QLabel('本地IP:')
        l1.setFixedSize(40, 13)
        l1.setAlignment(Qt.AlignHCenter)
        localIP = MyLabel(self)
        localIP.setText(socket.gethostbyname(socket.gethostname()))

        # localIP = QLabel('255.255.255.255')
        localIP.setFont(QFont('微软雅黑', 8, QFont.Bold))
        localIP.setTextInteractionFlags(Qt.TextSelectableByMouse)
        localIP.setFixedSize(95, 15)
        localIP.setAlignment(Qt.AlignLeft)
        h3.addWidget(l1)
        h3.addWidget(localIP)

        v2.addLayout(h1)
        v2.addLayout(h2)
        v2.addLayout(h3)

        control.setLayout(v2)
        return control

    # 初始化通信
    def InitConnection(self):
        self.udplist = []
        self.iplist = []
        item = QTreeWidgetItemIterator(self.tree)
        if self.rbsyslog.isChecked():
            if item.value() != None:
                while item.value():
                    try:
                        ip, port = item.value().text(1), int(item.value().text(2))
                        addr = (ip, port)
                        self.iplist.append(addr)
                        udpsend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        udpsend.connect(addr)
                        self.udplist.append(udpsend)
                    except Exception as e:
                        print(e)
                        MyWin.QMessageBoxInfo('端口占用', port + '端口被占用！')
                    item = item.__iadd__(1)
                self.initbutton.setEnabled(False)
                self.quitbutton.setEnabled(True)
                self.rbsyslog.setEnabled(False)
                self.rbsnmp.setEnabled(False)
                self.rbtimes.setEnabled(False)
                self.rbspeed.setEnabled(False)
                self.addbutton.setEnabled(False)
                self.editbutton.setEnabled(False)
                self.deletebutton.setEnabled(False)
                self.deleteall.setEnabled(False)
                self.tree.setEnabled(False)
            else:
                MyWin.QMessageBoxInfo('端口', '请输入IP和端口!')
        elif self.rbsnmp.isChecked():
            self.initbutton.setEnabled(False)
            self.quitbutton.setEnabled(True)
            self.rbsyslog.setEnabled(False)
            self.rbsnmp.setEnabled(False)
            self.rbtimes.setEnabled(False)
            self.rbspeed.setEnabled(False)
            self.addbutton.setEnabled(False)
            self.editbutton.setEnabled(False)
            self.deletebutton.setEnabled(False)
            self.deleteall.setEnabled(False)
            self.tree.setEnabled(False)


    # 退出通信设置
    def QuitConnection(self):
        if not self.sendbutton.isEnabled():
            MyWin.QMessageBoxInfo('数据发送', '请停止数据的发送!')
        else:
            self.quitbutton.setEnabled(False)
            self.initbutton.setEnabled(True)
            self.rbsyslog.setEnabled(True)
            self.rbsnmp.setEnabled(True)
            self.rbtimes.setEnabled(True)
            self.rbspeed.setEnabled(True)
            self.addbutton.setEnabled(True)
            self.editbutton.setEnabled(True)
            self.deletebutton.setEnabled(True)
            self.deleteall.setEnabled(True)
            self.tree.setEnabled(True)
            if self.rbsyslog.isChecked():
                try:
                    for udpsend in self.udplist:
                        udpsend.close()
                except:
                    pass

    # 发送数据控制，分为按次数和按时间发送
    def sendData(self):
        if self.initbutton.isEnabled():
            MyWin.QMessageBoxInfo("初始化通信", "请初始化通信!")
        else:
            try:
                if self.etime.isReadOnly():
                    if self.rbsyslog.isChecked():
                        if self.combox.currentText() == '从文件':
                            if self.filename.text() == '':
                                MyWin.QMessageBoxInfo('文件', '请加入文件!')
                            else:
                                self.sendAllData()
                        else:
                            self.sendAllData()
                    elif self.rbsnmp.isChecked():
                        if self.combox.currentText() == '从文件':
                            if self.filename.text() == '':
                                MyWin.QMessageBoxInfo('文件', '请加入文件!')
                            else:
                                self.sendsnmp()
                        else:
                            self.sendsnmp()
                elif self.enum.isReadOnly():
                    self.timer = QTimer(self)
                    if self.rbsyslog.isChecked():
                        self.timer.timeout.connect(self.sendAllData)
                    elif self.rbsnmp.isChecked():
                        self.timer.timeout.connect(self.sendsnmp)
                    if self.combox.currentText() == '从文件':
                        if self.filename.text() == '':
                            MyWin.QMessageBoxInfo('文件', '请加入文件!')
                        else:
                            self.sendbutton.setEnabled(False)
                            self.stopbutton.setEnabled(True)
                            self.timer.start(1000)
                    else:
                        self.sendbutton.setEnabled(False)
                        self.stopbutton.setEnabled(True)
                        self.timer.start(1000)
            except Exception as e:
                print(e)

    ##停止数据发送设置
    def stopData(self):
        self.sendbutton.setEnabled(True)
        self.stopbutton.setEnabled(False)
        try:
            self.timer.stop()
        except:
            pass


    # 消息设置界面
    def InfoSetting(self):
        info = QGroupBox('消息设置')
        v3 = QVBoxLayout()
        Hlayout1 = QHBoxLayout()
        Hlayout2 = QHBoxLayout()
        Hlayout3 = QHBoxLayout()

        l1 = QLabel('消息来源:')
        l1.setFixedHeight(13)
        l1.setAlignment(Qt.AlignBottom)
        self.combox = QComboBox()
        self.combox.addItem('从文件')
        self.combox.addItem('从文本框')
        self.combox.currentTextChanged.connect(self.InfoSrouce)

        l2 = QLabel('选择日志样本:')
        l1.setAlignment(Qt.AlignLeft)
        self.loglist = ['自定义', 'VenusIDS','Kill', 'Solaris', 'Snort', 'Linux', 'PIX']
        self.selectlog = QComboBox()
        for log in self.loglist:
            self.selectlog.addItem(log)
        self.selectlog.setEnabled(False)
        self.selectlog.currentTextChanged.connect(self.ChangeLog)

        self.clearButton = QPushButton('清除')
        self.clearButton.clicked.connect(self.ClearInfo)
        self.clearButton.setFixedWidth(50)
        self.clearButton.setEnabled(False)
        self.filename = QLineEdit()

        Hlayout1.addWidget(l1)
        Hlayout1.addWidget(self.combox)
        Hlayout1.addWidget(l2)
        Hlayout1.addWidget(self.selectlog)
        Hlayout1.addWidget(self.clearButton)

        self.browsebutton = QPushButton('浏览')
        self.browsebutton.setFixedWidth(50)
        self.browsebutton.clicked.connect(self.OpenFile)

        Hlayout2.addWidget(self.filename)
        Hlayout2.addWidget(self.browsebutton)

        self.showText = QTextEdit()
        self.showText.setPlainText('请输入要发送的报文，以英文;结尾')
        self.showText.setToolTip("请输入要发送的报文，以英文;结尾")
        self.showText.setReadOnly(True)
        self.showText.setStyleSheet("background-color:#f0f0f0")
        self.showText.setStyleSheet("border-image:url(:/source/bgs.png)")

        Hlayout3.addWidget(self.showText)

        v3.addLayout(Hlayout1)
        v3.addLayout(Hlayout2)
        v3.addLayout(Hlayout3)

        info.setLayout(v3)
        return info

    # 清除报文输入框
    def ClearInfo(self):
        self.showText.clear()

    # 输入源状态设置
    def InfoSrouce(self, txt):
        if txt == '从文件':
            self.showText.setReadOnly(True)
            self.showText.setStyleSheet("background-color:#f0f0f0")
            self.showText.setStyleSheet("border-image:url(:/source/bgs.png)")
            self.filename.setReadOnly(False)
            self.filename.setFocus()
            self.filename.setStyleSheet("background-color:#ffffff")
            self.clearButton.setEnabled(False)
            self.browsebutton.setEnabled(True)
            self.selectlog.setEnabled(False)
        elif txt == '从文本框':
            self.filename.setReadOnly(True)
            self.filename.setStyleSheet("background-color:#f0f0f0")
            self.showText.setReadOnly(False)
            # self.showText.clear()
            self.showText.setFocus()
            self.showText.setStyleSheet("background-color:#ffffff")
            self.showText.setStyleSheet("border-image:url(:/source/bgs.png)")
            self.clearButton.setEnabled(True)
            self.browsebutton.setEnabled(False)
            self.selectlog.setEnabled(True)

    #预置日志加载到文本框
    def ChangeLog(self, txt):
        tree = ET.ElementTree(file='SampleLog.xml')
        for elem in tree.iter():
            if elem.tag == 'Sample' and elem.attrib['Name'] == txt:
                self.showText.clear()
                self.showText.insertPlainText(elem.text)

    # 打开文件设置
    def OpenFile(self):
        try:
            file = MyWin.GetFileName('日志文件', r'D:/source/log', \
                                     "Log Files (*.log);;Text Files (*.txt)")
            if file != '':
                if self.filename.text() != file[0]:
                    self.filename.clear()
                    self.filename.insert(file[0])
                    MyWin.QMessageBoxInfo("加载文件", "加载文件成功!")
        except:
            pass

    # 目标端设置界面
    def DestSetting(self):
        # ipall = [('0', '10.91.3.247', '20514'), ('1', '10.91.3.104', '20514'), ('2', '10.95.44.19', '20514')]
        ipall = self.GetIPdata()
        dest = QGroupBox('目标端设置')
        g4 = QGridLayout()
        self.tree = QTreeWidget()
        self.tree.setFont(QFont('微软雅黑', 8, QFont.Bold))
        # self.tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        # self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setStyleSheet("border-image:url(:/source/bgs.png)")
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(['序号', '目标IP地址', '目标端口'])
        self.tree.setColumnWidth(0, 90)
        self.tree.setColumnWidth(1, 110)
        self.tree.setColumnWidth(2, 130)

        for ipinfo in ipall:
            item = QTreeWidgetItem(self.tree)
            item.setText(0, ipinfo[0])
            item.setText(1, ipinfo[1])
            item.setText(2, ipinfo[2])

        self.tree.itemDoubleClicked.connect(self.SelectEditdestSetting)

        self.addbutton = QPushButton('添加')
        self.addbutton.setFixedWidth(66)
        self.addbutton.clicked.connect(self.AdddestSetting)

        self.editbutton = QPushButton('编辑')
        self.editbutton.setFixedWidth(66)
        self.editbutton.clicked.connect(self.EditdestSetting)

        self.deletebutton = QPushButton('删除')
        self.deletebutton.setFixedWidth(66)
        self.deletebutton.clicked.connect(self.DeletedestSetting)

        self.deleteall = QPushButton('全删')
        self.deleteall.setFixedWidth(66)
        self.deleteall.clicked.connect(self.DeltedestAll)

        g4.addWidget(self.tree, 0, 0, 4, 2)
        g4.addWidget(self.addbutton, 0, 2, 1, 1)
        g4.addWidget(self.editbutton, 1, 2, 1, 1)
        g4.addWidget(self.deletebutton, 2, 2, 1, 1)
        g4.addWidget(self.deleteall, 3, 2, 1, 1)
        dest.setLayout(g4)

        return dest

    # 添加目标端口和IP设置
    def AdddestSetting(self):
        iplist = []
        item = QTreeWidgetItemIterator(self.tree)
        while item.value():
            iplist.append(item.value().text(1))
            item = item.__iadd__(1)
        ipaddr = Destdialog(self)
        if ipaddr.ipinfo is not None:
            if ipaddr.ipinfo[0] in iplist:
                pass
            else:
                item = QTreeWidgetItem(self.tree)
                item.setText(0, str(len(iplist)))
                item.setText(1, ipaddr.ipinfo[0])
                item.setText(2, ipaddr.ipinfo[1])
                self.AddIPdata(ipaddr.ipinfo[0], ipaddr.ipinfo[1])

    #配置文件中获取IP和端口信息
    def GetIPdata(self):
        tree = ET.ElementTree(file="TestSerialConf.xml")
        ipdata = []
        num = 0
        for elem in tree.iter():
            if elem.tag == "Server":
                ipdata.append(tuple([str(num), elem.attrib['IP'], elem.attrib['Port']]))
                num += 1
        return ipdata

    #添加IP和端口信息到配置文件
    def AddIPdata(self, ipaddr=None, port=None):
        if ipaddr is not None:
            tree = ET.ElementTree(file="TestSerialConf.xml")
            for elem in tree.iter():
                if elem.tag == "Target":
                    el = ET.SubElement(elem, 'Server')
                    el.attrib['IP'] = ipaddr
                    el.attrib['Port'] = port
                    el.tail = '\n'
            tree.write("TestSerialConf.xml", encoding="utf-8")

    #从配置文件中删除IP和端口信息
    def DeleteIPdata(self, ipaddr=None):
        if ipaddr is not None:
            tree = ET.parse("TestSerialConf.xml")
            root = tree.getroot()
            target = root.findall('Target')[0]
            for elem in target.findall('Server'):
                if elem.get('IP') == ipaddr:
                    target.remove(elem)
            tree.write("TestSerialConf.xml", encoding="utf-8")

    #编辑存在的IP和端口信息
    def EditIPdata(self, oldipaddr=None, newipaddr=None, oldport=None, newport=None):
        if oldipaddr is not None:
            tree = ET.ElementTree(file="TestSerialConf.xml")
            for elem in tree.iter():
                if elem.tag == 'Server' and elem.attrib['IP'] == oldipaddr:
                    elem.attrib['IP'] = newipaddr
                    elem.attrib['Port'] = newport
            tree.write("TestSerialConf.xml", encoding="utf-8")

    #删除配置文件中所有IP和端口信息
    def DeleteAllIPdata(self):
        tree = ET.parse("TestSerialConf.xml")
        root = tree.getroot()
        target = root.findall('Target')[0]
        for elem in target.findall('Server'):
            target.remove(elem)
        tree.write("TestSerialConf.xml", encoding="utf-8")

    # 编辑双击选中IP和端口
    def SelectEditdestSetting(self, item):
        # print(item.text(1), item.text(2))
        ipaddr = Destdialog(self, item.text(1), item.text(2))
        oldipaddr = item.text(1)
        oldport = item.text(2)
        if ipaddr.ipinfo is not None:
            item.setText(1, ipaddr.ipinfo[0])
            item.setText(2, ipaddr.ipinfo[1])
            newip = item.text(1)
            newport = item.text(2)
            self.EditIPdata(oldipaddr, newip, oldport, newport)

    # 编辑界面IP和端口
    def EditdestSetting(self):
        if self.tree.selectedItems() != []:
            ipaddr = Destdialog(self, self.tree.selectedItems()[0].text(1), \
                                self.tree.selectedItems()[0].text(2))
            oldipaddr = self.tree.selectedItems()[0].text(1)
            oldport = self.tree.selectedItems()[0].text(2)
            if ipaddr.ipinfo is not None:
                self.tree.selectedItems()[0].setText(1, ipaddr.ipinfo[0])
                self.tree.selectedItems()[0].setText(2, ipaddr.ipinfo[1])
                newip = self.tree.selectedItems()[0].text(1)
                newport = self.tree.selectedItems()[0].text(2)
                self.EditIPdata(oldipaddr, newip, oldport, newport)

    # 删除添加的IP和端口
    def DeletedestSetting(self):
        items = []
        if self.tree.selectedItems() != []:
            self.DeleteIPdata(self.tree.selectedItems()[0].text(1))
            self.tree.takeTopLevelItem(int(self.tree.selectedItems()[0].text(0)))

            item = QTreeWidgetItemIterator(self.tree)
            while item.value():
                items.append(item.value())
                item = item.__iadd__(1)
            for name, num in zip(items, range(len(items))):
                name.setText(0, str(num))

    # 删除所有IP和端口
    def DeltedestAll(self):
        self.tree.clear()
        self.DeleteAllIPdata()

    # 发送统计界面
    def Sumdata(self):
        sumdata = QGroupBox('发送统计')
        sumdata.setFixedHeight(70)
        g5 = QGridLayout()
        l1 = QLabel('累计发送:')
        l1.setFixedHeight(20)
        self.allnum = QLabel('0')

        l2 = QLabel('本次发送:')
        self.thisnum = QLabel('0')

        l3 = QLabel('实际速度:')
        l3.setFixedHeight(20)
        self.actspeed = QLabel('0 条/秒')

        l4 = QLabel('累计时间:')
        self.sumtime = QLabel('0天0时0分0秒')

        g5.addWidget(l1, 0, 0, 1, 1)
        g5.addWidget(self.allnum, 0, 1, 1, 1)
        g5.addWidget(l2, 0, 2, 1, 1)
        g5.addWidget(self.thisnum, 0, 3, 1, 1)
        g5.addWidget(l3, 1, 0, 1, 1)
        g5.addWidget(self.actspeed, 1, 1, 1, 1)
        g5.addWidget(l4, 1, 2, 1, 1)
        g5.addWidget(self.sumtime, 1, 3, 1, 1)

        sumdata.setLayout(g5)
        return sumdata

    # 发送syslog协议的数据包
    def sendAllData(self):
        try:
            datanum = 0
            if self.etime.isReadOnly():
                num = int(self.enum.text())
            elif self.enum.isReadOnly():
                try:
                    num = int(self.etime.text())
                except:
                    num = 0
            self.thisnum.setText(str(num))
            item = QTreeWidgetItemIterator(self.tree)
            if not isinstance(item.value(), QTreeWidgetItem):
                MyWin.QMessageBoxInfo('端口和IP', '请输入IP和端口!')
            else:
                if self.combox.currentText() == '从文件':
                    while num > 0:
                        with open(self.filename.text(), 'r', encoding='utf8') as f:
                            for data in f.readlines():
                                for udpsend, addr in zip(self.udplist, self.iplist):
                                    udpsend.sendto(data.strip().encode(encoding="utf-8"), addr)
                                datanum += 1
                        num -= 1
                elif self.combox.currentText() == '从文本框':
                    while num > 0:
                        if self.selectlog.currentText() == '自定义':
                            textlist = str(self.showText.toPlainText()).split(';')
                            # print(len(textlist))
                            for text in textlist:
                                for udpsend, addr in zip(self.udplist, self.iplist):
                                    udpsend.sendto(text.encode(encoding="utf-8"), addr)
                                datanum += 1
                            self.actspeed.setText(str(datanum) + ' 条/秒')
                        else:
                            text = str(self.showText.toPlainText())
                            for udpsend, addr in zip(self.udplist, self.iplist):
                                udpsend.sendto(text.encode(encoding="utf-8"), addr)
                            datanum += 1
                        num -= 1
                self.numtime += 1
                self.TimeShow(self.numtime)
                self.actspeed.setText(str(datanum) + ' 条/秒')
                # print(int(self.thisnum.text())*datanum)
                try:
                    if self.etime.isReadOnly():
                        self.allnum.setText(str(datanum + int(self.allnum.text())))
                    elif self.enum.isReadOnly():
                        self.allnum.setText(str(datanum + int(self.allnum.text())))
                except:
                    self.allnum.setText(str(int(self.allnum.text())))
        except Exception as e:
            print(e)

    #发送snmp协议的数据包
    def sendsnmp(self):
        try:
            datanum = 0
            if self.etime.isReadOnly():
                num = int(self.enum.text())
            elif self.enum.isReadOnly():
                try:
                    num = int(self.etime.text())
                except:
                    num = 0
            self.thisnum.setText(str(num))
            item = QTreeWidgetItemIterator(self.tree)
            if not isinstance(item.value(), QTreeWidgetItem):
                MyWin.QMessageBoxInfo('端口和IP', '请输入IP和端口!')
            else:
                if self.combox.currentText() == '从文件':
                    while num > 0:
                        with open(self.filename.text(), 'r') as f:
                            for data in f.readlines():
                                send_msg(self.snmpset.authinfo, item.value().text(1), int(item.value().text(2)),data)
                                # print(self.snmpset.authinfo)
                                datanum += 1
                        num -= 1
                elif self.combox.currentText() == '从文本框':
                    while num > 0:
                        if self.selectlog.currentText() == '自定义':
                            textlist = str(self.showText.toPlainText()).split(';')
                            # print(len(textlist))
                            for text in textlist:
                                send_msg(self.snmpset.authinfo, item.value().text(1), int(item.value().text(2)),text)
                                datanum += 1
                            self.actspeed.setText(str(datanum) + ' 条/秒')
                        else:
                            text = str(self.showText.toPlainText())
                            send_msg(self.snmpset.authinfo, item.value().text(1), int(item.value().text(2)), text)
                            datanum += 1
                        num -= 1
                self.numtime += 1
                self.TimeShow(self.numtime)
                self.actspeed.setText(str(datanum) + ' 条/秒')
                # print(int(self.thisnum.text())*datanum)
                try:
                    if self.etime.isReadOnly():
                        self.allnum.setText(str(datanum + int(self.allnum.text())))
                    elif self.enum.isReadOnly():
                        self.allnum.setText(str(datanum + int(self.allnum.text())))
                except:
                    self.allnum.setText(str(int(self.allnum.text())))
        except Exception as e:
            print(e)

    # 累计时间展示
    def TimeShow(self, num):
        if num < 60:
            self.sumtime.setText('0天0时0分' + str(num) + '秒')
        elif num >= 60 and num < 3600:
            self.sumtime.setText('0天0时' + str(int(num / 60)) + '分' + str(num % 60) + '秒')
        elif num >= 3600 and num < 86400:
            self.sumtime.setText(
                '0天' + str(int(num / 3600)) + '时' + str(int((num % 3600) / 60)) + '分' + str((num % 3600) % 60) + '秒')
        elif num >= 86400:
            self.sumtime.setText(str(int(num / 86400)) + '天' + str(int((num % 86400) / 3600)) + '时' + str(
                int(((num % 86400) % 3600) / 60)) + '分' + str(((num % 86400) % 3600) % 60) + '秒')

    # 界面布局
    def Grid(self):
        grid = QGridLayout()
        grid.addWidget(self.SendSetting(), 0, 0, 1, 2)
        grid.addWidget(self.SendControl(), 0, 2, 1, 1)
        grid.addWidget(self.InfoSetting(), 1, 0, 1, 3)
        grid.addWidget(self.DestSetting(), 2, 0, 1, 3)
        grid.addWidget(self.Sumdata(), 3, 0, 1, 3)

        self.setLayout(grid)

    #界面居中显示
    def Center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    #静态提示信息接口
    @staticmethod
    def QMessageBoxInfo(title, txt):
        message = QMessageBox()
        message.setWindowTitle(title)
        message.setText(txt)
        message.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        bty = message.button(QMessageBox.Yes)
        bty.setText('确定')
        btn = message.button(QMessageBox.No)
        btn.setText('取消')
        message.exec_()
        if message.clickedButton() == bty:
            return 'yes'
        elif message.clickedButton() == btn:
            return 'no'

    #获取本地文件接口
    @staticmethod
    def GetFileName(title, initialdir, filetypes):
        filedialog = QFileDialog()
        filedialog.setAcceptMode(QFileDialog.AcceptOpen)
        filedialog.setFileMode(QFileDialog.ExistingFiles)
        filedialog.setOption(QFileDialog.ReadOnly, True)
        filedialog.setWindowTitle(title)
        filedialog.setWindowState(Qt.WindowActive)
        filedialog.setDirectory(initialdir)
        filedialog.setNameFilter(filetypes)
        filedialog.exec_()
        return filedialog.selectedFiles()

#目标端添加IP和端口配置界面
class Destdialog(QDialog):
    def __init__(self, parent=None, ip=None, portset=None):
        super(Destdialog, self).__init__(parent)
        self.UI(ip, portset)
        self.setWindowFlag(Qt.WindowMinimizeButtonHint)
        self.ipinfo = None
        self.setModal(True)
        self.exec_()

    #界面UI
    def UI(self, ip, portset):
        self.setWindowTitle('目标信息')
        self.setFixedSize(320, 80)
        self.setAutoFillBackground(True)
        img = QPixmap(":/source/bgd.png")
        paletteShow = QPalette()
        paletteShow.setBrush(self.backgroundRole(), QBrush(QPixmap(img)))
        self.setPalette(paletteShow)
        g5 = QGridLayout()
        l1 = QLabel('IP地址:')
        self.ipaddr = IPLineEdit.Ip4Edit()
        l2 = QLabel('端口:')
        self.port = QLineEdit()

        validator = QIntValidator(0, 65535)
        self.port.setValidator(validator)
        if ip is not None and portset is not None:
            self.ipaddr.setText(ip)
            self.port.insert(portset)
        else:
            self.ipaddr.setText('10.91.3.247')
            self.port.insert('20514')
        self.okbutton = QPushButton('确定')
        self.okbutton.clicked.connect(self.getData)
        cancelbutton = QPushButton('取消')
        cancelbutton.clicked.connect(self.close)
        g5.addWidget(l1, 0, 0, 1, 1)
        g5.addWidget(self.ipaddr, 0, 1, 1, 1)
        g5.addWidget(l2, 0, 2, 1, 1)
        g5.addWidget(self.port, 0, 3, 1, 1)
        g5.addWidget(self.okbutton, 1, 1, 1, 1)
        g5.addWidget(cancelbutton, 1, 3, 1, 1)

        self.setLayout(g5)

    #获取配置信息
    def getData(self):
        self.ipinfo = (self.ipaddr.text(), self.port.text())
        if self.ipinfo is None:
            MyWin.QMessageBoxInfo('IP地址为空', 'IP地址为空！')
            # self.ipinfo = None
        elif re.match(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$', \
                self.ipinfo[0]) is None or self.ipinfo[0] == '0.0.0.0':
            MyWin.QMessageBoxInfo("IP格式错误", self.ipinfo[0] + "不是合法IP地址！")
            self.ipinfo = None
        elif self.port.text() == "" or int(self.port.text()) > 65535 or int(self.port.text()) < 0:
            MyWin.QMessageBoxInfo('端口错误', "   请输入合法端口\n端口范围(0-65535)")
            self.ipinfo = None
        else:
            self.close()

    #Enter保存功能
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Enter:
            self.okbutton.clicked.connect(self.getData)
        super(Destdialog, self).keyPressEvent(event)


class MyLabel(QLabel):
    def __init__(self,parent=None):
        super(MyLabel, self).__init__(parent)




    def mouseDoubleClickEvent(self,e):
        self.setSelection(0,len(self.text()))

#snm协议配置界面
class SnmpSetting(QDialog):
    def __init__(self,parent=None,info = {}):
        super(SnmpSetting, self).__init__(parent)
        try:
            self.authinfo = info
            self.UI()
            self.setWindowFlag(Qt.WindowMinimizeButtonHint)
            self.setModal(True)
            self.exec_()

        except Exception as e:
            print(e)

    def UI(self):
        try:
            self.setWindowTitle('SNMP配置')
            self.setFixedSize(260, 140)
            self.setAutoFillBackground(True)
            img = QPixmap(":/source/bgd.png")
            paletteShow = QPalette()
            paletteShow.setBrush(self.backgroundRole(), QBrush(QPixmap(img)))
            self.setPalette(paletteShow)
            grid = QGridLayout()

            usrLabel = QLabel("用户名:")
            usrLabel.setFixedWidth(60)
            self.usrname = QLineEdit()

            authLabel = QLabel("认证方式:")
            authLabel.setFixedWidth(60)
            self.authselect = QComboBox()
            self.authselect.addItem("SHA")
            self.authselect.addItem("MD5")
            self.authselect.addItem("不认证")
            self.authselect.setFixedWidth(83)
            self.authselect.currentTextChanged.connect(self.authSelect)
            self.authkey = QLineEdit()

            priLabel = QLabel("加密方式:")
            priLabel.setFixedWidth(60)
            self.priselect = QComboBox()
            self.priselect.addItem("DES")
            self.priselect.addItem("不加密")
            self.priselect.currentTextChanged.connect(self.priSelect)
            self.prikey = QLineEdit()

            if self.authinfo == {}:
                self.authinfo['authmthod'] = '不认证'
                self.authselect.setCurrentText("不认证")
                self.authinfo['primethod'] = '不加密'
                self.priselect.setCurrentText("不加密")
                self.authpro = None
                self.pripro = None
            else:
                self.usrname.insert(self.authinfo.get('user',''))
                self.authselect.setCurrentText(self.authinfo['authmthod'])
                self.priselect.setCurrentText(self.authinfo['primethod'])
                self.authkey.insert(self.authinfo.get('authkey', ''))
                self.prikey.insert(self.authinfo.get('privkey',''))
                self.authpro = self.authinfo.get('authProtocol', None)
                self.pripro = self.authinfo.get('privProtocol', None)


            self.okbutton = QPushButton('确定')
            self.okbutton.clicked.connect(self.getData)
            cancelbutton = QPushButton('取消')
            cancelbutton.clicked.connect(self.close)

            statusdis = QLabel("适用于 SNMPv3 版本")


            grid.addWidget(usrLabel, 0, 0, 1, 1)
            grid.addWidget(self.usrname, 0, 1, 1, 2)
            grid.addWidget(authLabel, 1, 0, 1, 1)
            grid.addWidget(self.authselect, 1 ,1 ,1 ,1)
            grid.addWidget(self.authkey, 1, 2, 1, 1)
            grid.addWidget(priLabel ,2 ,0 ,1 ,1)
            grid.addWidget(self.priselect ,2 ,1 ,1 ,1)
            grid.addWidget(self.prikey ,2 ,2 ,1 ,1)
            grid.addWidget(self.okbutton, 3, 1, 1, 1)
            grid.addWidget(cancelbutton, 3 , 2 ,1, 1)
            grid.addWidget(statusdis, 4 , 0, 1, 3)

            self.setLayout(grid)

        except Exception as e:
            print(e)

    def authSelect(self, txt):
        if txt == 'SHA':
            self.authpro = 'usmHMACSHAAuthProtocol'
            self.authinfo['authmthod'] = 'SHA'

        elif txt == 'MD5':
            self.authpro = 'usmHMACMD5AuthProtocol'
            self.authinfo['authmthod'] = 'MD5'

        elif txt == "不认证":
            self.authkey.clear()
            self.authinfo['authmthod'] = '不认证'
            self.authpro = None

    def priSelect(self, txt):
        if txt == 'DES':
            self.pripro = 'usmDESPrivProtocol'
            self.authinfo['primethod'] = "DES"
        elif txt == "不加密":
            self.prikey.clear()
            self.authinfo['primethod'] = "不加密"
            self.pripro = None

    def getData(self):
        try:
            if self.authselect.currentText() != "不认证" and self.authkey.text() == "":
                MyWin.QMessageBoxInfo('认证方式', '认证密码为空!')
            else:
                self.authinfo['authProtocol'] = self.authpro
                self.authinfo['authkey'] = self.authkey.text().strip()
            if self.priselect.currentText() != "不加密" and self.prikey.text() == "":
                MyWin.QMessageBoxInfo('加密方式', '加密密码为空!')
            else:
                self.authinfo['privProtocol'] = self.pripro
                self.authinfo['privkey'] = self.prikey.text().strip()
            if self.usrname.text().strip() == "":
                MyWin.QMessageBoxInfo('用户名', '用户名为空!')
            else:
                self.authinfo['user'] = self.usrname.text().strip()
                self.close()

        except Exception as e:
            print(e)


    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Enter:
            self.okbutton.clicked.connect(self.getData)
            super(SnmpSetting, self).keyPressEvent(event)


QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
app = QApplication(sys.argv)
win = MyWin()
sys.exit(app.exec_())
