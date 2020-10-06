# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'untitled.ui'
#
# Created by: PyQt5 UI code generator 5.15.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(519, 419)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icons/76_512_Kl0_icon.ico"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setAutoFillBackground(True)
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonFollowStyle)
        MainWindow.setDocumentMode(False)
        MainWindow.setUnifiedTitleAndToolBarOnMac(False)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.encrypte_tab = QtWidgets.QTabWidget(self.centralwidget)
        self.encrypte_tab.setEnabled(True)
        self.encrypte_tab.setGeometry(QtCore.QRect(0, 0, 511, 391))
        self.encrypte_tab.setAutoFillBackground(False)
        self.encrypte_tab.setTabPosition(QtWidgets.QTabWidget.North)
        self.encrypte_tab.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.encrypte_tab.setElideMode(QtCore.Qt.ElideNone)
        self.encrypte_tab.setUsesScrollButtons(False)
        self.encrypte_tab.setDocumentMode(False)
        self.encrypte_tab.setTabsClosable(False)
        self.encrypte_tab.setMovable(False)
        self.encrypte_tab.setTabBarAutoHide(False)
        self.encrypte_tab.setObjectName("encrypte_tab")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.path_enrty = QtWidgets.QLineEdit(self.tab_3)
        self.path_enrty.setGeometry(QtCore.QRect(100, 50, 221, 20))
        self.path_enrty.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        self.path_enrty.setText("")
        self.path_enrty.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.path_enrty.setDragEnabled(True)
        self.path_enrty.setObjectName("path_enrty")
        self.encrypte_Button = QtWidgets.QPushButton(self.tab_3)
        self.encrypte_Button.setGeometry(QtCore.QRect(230, 190, 75, 23))
        self.encrypte_Button.setObjectName("encrypte_Button")
        self.picture_preview = QtWidgets.QLabel(self.tab_3)
        self.picture_preview.setGeometry(QtCore.QRect(350, 140, 111, 81))
        self.picture_preview.setFrameShape(QtWidgets.QFrame.Panel)
        self.picture_preview.setFrameShadow(QtWidgets.QFrame.Plain)
        self.picture_preview.setText("")
        self.picture_preview.setScaledContents(True)
        self.picture_preview.setWordWrap(False)
        self.picture_preview.setObjectName("picture_preview")
        self.pass_entry1 = QtWidgets.QLineEdit(self.tab_3)
        self.pass_entry1.setGeometry(QtCore.QRect(60, 150, 151, 20))
        self.pass_entry1.setInputMask("")
        self.pass_entry1.setText("")
        self.pass_entry1.setMaxLength(32)
        self.pass_entry1.setFrame(True)
        self.pass_entry1.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_entry1.setClearButtonEnabled(False)
        self.pass_entry1.setObjectName("pass_entry1")
        self.error_label = QtWidgets.QLabel(self.tab_3)
        self.error_label.setGeometry(QtCore.QRect(70, 220, 191, 16))
        self.error_label.setText("")
        self.error_label.setObjectName("error_label")
        self.picture_preview_label = QtWidgets.QLabel(self.tab_3)
        self.picture_preview_label.setGeometry(QtCore.QRect(360, 230, 111, 20))
        self.picture_preview_label.setTextFormat(QtCore.Qt.AutoText)
        self.picture_preview_label.setObjectName("picture_preview_label")
        self.browseButton = QtWidgets.QPushButton(self.tab_3)
        self.browseButton.setGeometry(QtCore.QRect(330, 50, 51, 21))
        self.browseButton.setObjectName("browseButton")
        self.pass_entry2 = QtWidgets.QLineEdit(self.tab_3)
        self.pass_entry2.setGeometry(QtCore.QRect(60, 190, 151, 20))
        self.pass_entry2.setMaxLength(32)
        self.pass_entry2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_entry2.setObjectName("pass_entry2")
        self.showpasses = QtWidgets.QToolButton(self.tab_3)
        self.showpasses.setGeometry(QtCore.QRect(210, 150, 25, 21))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("icons/2540381_200_OCO_icon.ico"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.showpasses.setIcon(icon1)
        self.showpasses.setCheckable(False)
        self.showpasses.setAutoRaise(False)
        self.showpasses.setObjectName("showpasses")
        self.encrypte_tab.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.path_enrty_2 = QtWidgets.QLineEdit(self.tab_4)
        self.path_enrty_2.setGeometry(QtCore.QRect(20, 70, 221, 20))
        self.path_enrty_2.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        self.path_enrty_2.setText("")
        self.path_enrty_2.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.path_enrty_2.setDragEnabled(True)
        self.path_enrty_2.setObjectName("path_enrty_2")
        self.browseButton_2 = QtWidgets.QPushButton(self.tab_4)
        self.browseButton_2.setGeometry(QtCore.QRect(250, 70, 51, 21))
        self.browseButton_2.setObjectName("browseButton_2")
        self.pass_entry_dec = QtWidgets.QLineEdit(self.tab_4)
        self.pass_entry_dec.setGeometry(QtCore.QRect(30, 170, 151, 20))
        self.pass_entry_dec.setInputMask("")
        self.pass_entry_dec.setText("")
        self.pass_entry_dec.setMaxLength(32)
        self.pass_entry_dec.setFrame(True)
        self.pass_entry_dec.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_entry_dec.setClearButtonEnabled(False)
        self.pass_entry_dec.setObjectName("pass_entry_dec")
        self.show_pass = QtWidgets.QToolButton(self.tab_4)
        self.show_pass.setGeometry(QtCore.QRect(180, 170, 25, 21))
        self.show_pass.setIcon(icon1)
        self.show_pass.setCheckable(False)
        self.show_pass.setAutoRaise(False)
        self.show_pass.setObjectName("show_pass")
        self.decryptebutton = QtWidgets.QPushButton(self.tab_4)
        self.decryptebutton.setEnabled(False)
        self.decryptebutton.setGeometry(QtCore.QRect(220, 170, 75, 23))
        self.decryptebutton.setObjectName("decryptebutton")
        self.dec_pass_label = QtWidgets.QLabel(self.tab_4)
        self.dec_pass_label.setGeometry(QtCore.QRect(30, 200, 181, 16))
        self.dec_pass_label.setText("")
        self.dec_pass_label.setObjectName("dec_pass_label")
        self.save = QtWidgets.QPushButton(self.tab_4)
        self.save.setEnabled(False)
        self.save.setGeometry(QtCore.QRect(310, 70, 75, 21))
        self.save.setAutoDefault(False)
        self.save.setObjectName("save")
        self.picture_preview_decrypte = QtWidgets.QLabel(self.tab_4)
        self.picture_preview_decrypte.setGeometry(QtCore.QRect(340, 140, 111, 81))
        self.picture_preview_decrypte.setFrameShape(QtWidgets.QFrame.Panel)
        self.picture_preview_decrypte.setFrameShadow(QtWidgets.QFrame.Plain)
        self.picture_preview_decrypte.setText("")
        self.picture_preview_decrypte.setScaledContents(True)
        self.picture_preview_decrypte.setWordWrap(False)
        self.picture_preview_decrypte.setObjectName("picture_preview_decrypte")
        self.label = QtWidgets.QLabel(self.tab_4)
        self.label.setGeometry(QtCore.QRect(350, 230, 91, 16))
        self.label.setObjectName("label")
        self.encrypte_tab.addTab(self.tab_4, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.encrypte_tab.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "pic locker"))
        self.path_enrty.setPlaceholderText(_translate("MainWindow", "entre your path file"))
        self.encrypte_Button.setText(_translate("MainWindow", "encrypte"))
        self.pass_entry1.setPlaceholderText(_translate("MainWindow", "password"))
        self.picture_preview_label.setText(_translate("MainWindow", "picture preview"))
        self.browseButton.setText(_translate("MainWindow", "browse"))
        self.pass_entry2.setPlaceholderText(_translate("MainWindow", "re entre password"))
        self.showpasses.setText(_translate("MainWindow", "..."))
        self.encrypte_tab.setTabText(self.encrypte_tab.indexOf(self.tab_3), _translate("MainWindow", "encrypte"))
        self.path_enrty_2.setPlaceholderText(_translate("MainWindow", "entre your path file"))
        self.browseButton_2.setText(_translate("MainWindow", "browse"))
        self.pass_entry_dec.setPlaceholderText(_translate("MainWindow", "password"))
        self.show_pass.setText(_translate("MainWindow", "..."))
        self.decryptebutton.setText(_translate("MainWindow", "decrypte"))
        self.save.setText(_translate("MainWindow", "save"))
        self.label.setText(_translate("MainWindow", "picture preview"))
        self.encrypte_tab.setTabText(self.encrypte_tab.indexOf(self.tab_4), _translate("MainWindow", "decrypte"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
