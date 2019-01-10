# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'opening_screen.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_OpeningScreen(object):
    def setupUi(self, OpeningScreen):
        OpeningScreen.setObjectName("OpeningScreen")
        OpeningScreen.resize(404, 273)
        self.centralwidget = QtWidgets.QWidget(OpeningScreen)
        self.centralwidget.setObjectName("centralwidget")
        self.enter = QtWidgets.QPushButton(self.centralwidget)
        self.enter.setGeometry(QtCore.QRect(140, 110, 111, 44))
        self.enter.setObjectName("enter")
        self.nickname = QtWidgets.QLineEdit(self.centralwidget)
        self.nickname.setGeometry(QtCore.QRect(40, 40, 321, 44))
        self.nickname.setObjectName("nickname")
        OpeningScreen.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(OpeningScreen)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 404, 42))
        self.menubar.setObjectName("menubar")
        OpeningScreen.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(OpeningScreen)
        self.statusbar.setObjectName("statusbar")
        OpeningScreen.setStatusBar(self.statusbar)

        self.retranslateUi(OpeningScreen)
        QtCore.QMetaObject.connectSlotsByName(OpeningScreen)

    def retranslateUi(self, OpeningScreen):
        _translate = QtCore.QCoreApplication.translate
        OpeningScreen.setWindowTitle(_translate("OpeningScreen", "Giriş Ekranı"))
        self.enter.setText(_translate("OpeningScreen", "Giriş"))
        self.nickname.setPlaceholderText(_translate("OpeningScreen", "Kullanıcı Adı"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    OpeningScreen = QtWidgets.QMainWindow()
    ui = Ui_OpeningScreen()
    ui.setupUi(OpeningScreen)
    OpeningScreen.show()
    sys.exit(app.exec_())

