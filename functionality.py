from pyqt5_project import*
import sys,ntpath,os,shutil
from PyQt5.QtWidgets import QFileDialog
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
class Firstapp(Ui_MainWindow):

    def __init__(self,window):
        global filename,state,state2
        filename= None
        state="hide"
        state2="hide"
        self.setupUi(window)
        self.browseButton.clicked.connect(lambda:self.importf(1))
        self.browseButton_2.clicked.connect(lambda:self.importf(2))
        self.pass_entry2.textChanged.connect(lambda:self.checkPasswordMatches(1))
        self.pass_entry_dec.textChanged.connect(lambda:self.checkPasswordMatches(2))
        self.showpasses.clicked.connect(lambda:self.showpassf(1))
        self.show_pass.clicked.connect(lambda:self.showpassf(2))
        self.encrypte_Button.clicked.connect(self.encrypte)
        self.decryptebutton.clicked.connect(self.decrypte)
        self.save.clicked.connect(self.savef)
        

    def showpassf(self,num):
        global state,state2
        if num==1:
           if state=="hide":
              self.pass_entry1.setEchoMode(QtWidgets.QLineEdit.Normal)
              self.pass_entry2.setEchoMode(QtWidgets.QLineEdit.Normal)
              state="show"
           else:   
              self.pass_entry1.setEchoMode(QtWidgets.QLineEdit.Password)
              self.pass_entry2.setEchoMode(QtWidgets.QLineEdit.Password)
              state="hide"
        else:
            if state2=="hide":
                self.pass_entry_dec.setEchoMode(QtWidgets.QLineEdit.Normal)
                state2="show"
            else:
                self.pass_entry_dec.setEchoMode(QtWidgets.QLineEdit.Password)
                state2="hide"
        


    def encrypte(self):
        global pic_path,getOpenFileName
        password_provided =  self.pass_entry1.text() # This is input in the form of a string
        password = password_provided.encode()  # Convert to type bytes
        salt =bytes(os.urandom(16))  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        pass_hash= hashlib.pbkdf2_hmac(
               'sha256', # The hash digest algorithm for HMAC
               password_provided.encode('utf-8'), # Convert the password to bytes
               salt, # Provide the salt
               100000 # It is recommended to use at least 100,000 iterations of SHA-256 
               )
        kdf = PBKDF2HMAC(
               algorithm=hashes.SHA256(),
               length=32,
               salt=salt,
               iterations=100000,
               backend=default_backend()
               )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        file = open(pic_path,'rb+')
        fdata=file.read()
        f = Fernet(key)
        encrypted = f.encrypt(fdata)  # Encrypt the bytes. The returning object is of type bytes
        file.close()
        os.remove(pic_path)
        try:
                os.mkdir(os.getcwd()+"/encrypted")
        except:
                pass
        pic_path=os.getcwd()+"/encrypted/"+name
        fileencrypted=open(os.path.splitext(pic_path)[0]+'.cod','wb+')
        fileencrypted.write(salt)
        fileencrypted.write(pass_hash)
        fileencrypted.write(encrypted)
        fileencrypted.close()
        self.error_label.setText("file encrypted scessfully")
    def importf(self,num):
        global filename,pic_path,name
        if num==1:
           home = str(Path.home())
           myPath = os.path.join(home, "Pictures")
           filename, _filter= QFileDialog.getOpenFileName(MainWindow,"chose an image ",myPath,"image files (*.jpg *.jpeg *.gif *.png)")  
           try:
                name= ntpath.basename(filename)
                try:
                        os.mkdir(os.getcwd()+"/files")
                except:
                      pass
                pic_path=os.getcwd()+'/files/' + name
                os.rename(filename,pic_path)
                self.path_enrty.setText(filename)
                self.picture_preview.setPixmap(QtGui.QPixmap(pic_path))
           except:
                pass
        else:
            encrypted_path=os.getcwd()+'/encrypted/'
            filename, _filter= QFileDialog.getOpenFileName(MainWindow,"chose an encrypted file ",encrypted_path,"encrypted files (*.cod)")
            self.path_enrty_2.setText(filename)
            if filename=='':
                pass
            else:
                self.decryptebutton.setEnabled(True)
            
    def checkPasswordMatches(self,num):
        global filename
        if len(self.pass_entry1.text())<8:
             self.error_label.setStyleSheet('color: red')
             self.error_label.setText("Password must be at least 8 character")
             self.encrypte_Button.setEnabled(False)
        elif self.pass_entry1.text() != self.pass_entry2.text() :
             self.error_label.setStyleSheet('color: red')
             self.error_label.setText("the password doesn't match")
             self.encrypte_Button.setEnabled(False)
        elif filename== None:
             self.error_label.setText("please chose your file")
             self.encrypte_Button.setEnabled(False)
        else:
             self.error_label.setStyleSheet('color: green')
             self.error_label.setText("match!!")
             self.encrypte_Button.setEnabled(True)


    def decrypte(self):
        global name,dec_file_path
        file= open(filename,'rb')
        name= ntpath.basename(filename)
        decrypted_picpath=os.getcwd()+'/files/'+name
        salt= file.read(16)
        password_hash= file.read(32)
        encrypted=file.read()
        given_pass= self.pass_entry_dec.text()
        password= given_pass.encode()
        key_given=hashlib.pbkdf2_hmac(
               'sha256', # The hash digest algorithm for HMAC
               given_pass.encode('utf-8'), # Convert the password to bytes
               salt, # Provide the salt
               100000 # It is recommended to use at least 100,000 iterations of SHA-256 
               )
        if password_hash==key_given :
            kdf = PBKDF2HMAC(
                  algorithm=hashes.SHA256(),
                  length=32,
                  salt=salt,
                  iterations=100000,
                  backend=default_backend()
                  )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            decrypted = f.decrypt(encrypted)  # Decrypt the bytes. The returning object is of type bytes
            dec_file_path= os.path.splitext(decrypted_picpath)[0]+'.jpeg'
            decfile= open(dec_file_path,'wb')
            decfile.write(decrypted)
            decfile.close()
            file.close()
            self.dec_pass_label.setText("the file has been decrypted scessfully. ")
            self.dec_pass_label.setStyleSheet('color: green')
            self.picture_preview_decrypte.setPixmap(QtGui.QPixmap(dec_file_path))
            self.save.setEnabled(True)
        else:
            self.dec_pass_label.setText("the password is incorect")
            self.dec_pass_label.setStyleSheet('color: red')

            
    def savef(self):
        global dec_file_path
        user_path=str(Path.home())
        desktop= os.path.join(user_path, "Desktop")
        pic_name= ntpath.basename(dec_file_path)
        saving_path, _filter = QFileDialog.getSaveFileName(MainWindow,"chose a folder",desktop+"/"+pic_name,"JPEG Image (*.jpg *.jpeg  *.png)")
        shutil.move(dec_file_path,saving_path)
        self.dec_pass_label.setText("file saved scessfully.")

            


        
        
        

app = QtWidgets.QApplication(sys.argv)   
MainWindow = QtWidgets.QMainWindow()
ui=Firstapp(MainWindow)
MainWindow.show()
app.exec_()
