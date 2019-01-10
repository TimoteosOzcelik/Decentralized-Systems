# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'new_microblog.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_NewMicroblog(object):
    def setupUi(self, NewMicroblog):
        NewMicroblog.setObjectName("NewMicroblog")
        NewMicroblog.resize(613, 351)
        self.yayinla = QtWidgets.QPushButton(NewMicroblog)
        self.yayinla.setGeometry(QtCore.QRect(230, 280, 151, 44))
        self.yayinla.setObjectName("yayinla")
        self.blog = QtWidgets.QPlainTextEdit(NewMicroblog)
        self.blog.setGeometry(QtCore.QRect(50, 30, 521, 241))
        self.blog.setObjectName("blog")

        self.retranslateUi(NewMicroblog)
        QtCore.QMetaObject.connectSlotsByName(NewMicroblog)

    def retranslateUi(self, NewMicroblog):
        _translate = QtCore.QCoreApplication.translate
        NewMicroblog.setWindowTitle(_translate("NewMicroblog", "Yeni Blog Yayınla"))
        self.yayinla.setText(_translate("NewMicroblog", "Yayınla"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    NewMicroblog = QtWidgets.QDialog()
    ui = Ui_NewMicroblog()
    ui.setupUi(NewMicroblog)
    NewMicroblog.show()
    sys.exit(app.exec_())

