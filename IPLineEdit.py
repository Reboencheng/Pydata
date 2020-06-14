#!/usr/bin/env python
#coding:utf-8

from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt,QRegExp
from PyQt5.QtGui import QIntValidator,QValidator,QRegExpValidator
import sys

class IpPartEdit(QLineEdit):
    def __init__(self,parent= None):
        super(IpPartEdit, self).__init__(parent)
        self.nextTab = None
        self.preTab = None
        self.setMaxLength(3)
        self.setFrame(False)
        self.setAlignment(Qt.AlignCenter)

        validator = QIntValidator(0, 255, self)
        self.setValidator(validator)
        self.textEdited.connect(self.text_edited)

    def set_nextTabEdit(self, nextTab):
        self.nextTab = nextTab

    def set_preTabEdit(self, preTab):
        self.preTab = preTab



    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Period:
            if self.nextTab:
                self.nextTab.setFocus()
                self.nextTab.selectAll()
        if event.key() == Qt.Key_Backspace:
            if self.preTab and self.text() == '':
                self.preTab.setFocus()
                self.preTab.selectAll()
        if event.key() == Qt.Key_Left:
            if self.preTab:
                self.preTab.setFocus()
                self.preTab.selectAll()
        if event.key() == Qt.Key_Right:
            if self.nextTab:
                self.nextTab.setFocus()
                self.nextTab.selectAll()
        super(IpPartEdit, self).keyPressEvent(event)


    def text_edited(self):
        validator = QIntValidator(0, 255, self)
        ipaddr = self.text()
        state = validator.validate(ipaddr, 0)
        if state[0] == QValidator.Intermediate:
            self.backspace()
        if state[0] == QValidator.Acceptable:
            if len(ipaddr) > 1:
                ipnum = int(ipaddr)
                if ipnum > 255 or len(ipaddr) == 3:
                    if self.nextTab:
                        self.nextTab.setFocus()
                        self.nextTab.selectAll()




class Ip4Edit(QLineEdit):
    def __init__(self,parent = None):
        super(Ip4Edit, self).__init__(parent)
        self.IpAddressWidget()


    def IpAddressWidget(self):
        m_Separator = '.'
        self.ip_part  = [0,0,0,0]
        for i in range(4):
            self.ip_part[i] = IpPartEdit()
            self.ip_part[i].setAlignment(Qt.AlignCenter)

        self.m_Label = [0,0,0]
        for i in range(3):
            self.m_Label[i] = QLabel(m_Separator)
            self.m_Label[i].setFixedWidth(5)
            self.m_Label[i].setAlignment(Qt.AlignCenter)
        layout = QHBoxLayout()
        for i in range(3):
            layout.addWidget(self.ip_part[i])
            layout.addWidget(self.m_Label[i])
        layout.addWidget(self.ip_part[3])
        layout.setSpacing(0)
        layout.setContentsMargins(2, 2, 2, 2)
        self.setLayout(layout)
        QWidget.setTabOrder(self.ip_part[0], self.ip_part[1])
        QWidget.setTabOrder(self.ip_part[1], self.ip_part[2])
        QWidget.setTabOrder(self.ip_part[2], self.ip_part[3])
        self.ip_part[0].set_nextTabEdit(self.ip_part[1])
        self.ip_part[1].set_nextTabEdit(self.ip_part[2])
        self.ip_part[2].set_nextTabEdit(self.ip_part[3])

        # # self.ip_part[0].set_preTabEdit(self.ip_part[3])
        self.ip_part[3].set_preTabEdit(self.ip_part[2])
        self.ip_part[2].set_preTabEdit(self.ip_part[1])
        self.ip_part[1].set_preTabEdit(self.ip_part[0])




    def setText(self, text):
        regexp = QRegExp('^((2[0-4]\d|25[0-5]|[01]?\d\d?).){3}(2[0-4]\d||25[0-5]|[01]?\d\d?)$')
        validator = QRegExpValidator(regexp, self)
        stat = validator.validate(text, 0)[0]


        if stat == validator.Acceptable:
            iplist = text.split('.')
            for ipline, i in zip(self.ip_part, range(len(iplist))):
                ipline.insert(iplist[i])

    def clearAll(self):
        for ipedit in self.ip_part:
            ipedit.clear()

    def text(self):
        ipAddress = ''
        for LineEidt, i in zip(self.ip_part, range(len(self.ip_part))):
            if i == 3:
                ipAddress += LineEidt.text()
            else:
                ipAddress += LineEidt.text()+'.'
        return ipAddress


if __name__ == '__main__':
    app = QApplication(sys.argv)
    form = Ip4Edit()
    form.setText('')
    form.show()
    sys.exit(app.exec_())
