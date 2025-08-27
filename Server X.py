#pip install wheel
#pip install pyinstaller
#Copy Puton X.py in C:\1\
#pyinstaller --onedir --onefile --name=Klient "C:\1\Puton X.py"
import uuid
import logging
import time
mac = uuid.getnode()
mac_address = "%012X"%mac
print ("MAC: " + mac_address)

import socket
ip = socket.gethostbyname(socket.getfqdn())
print ("IP: " + ip)

import socket
print("Имя хоста: " + socket.gethostname())
import time
import time as time_

import socket
print ("Полное имя хоста: " + socket.gethostbyaddr(socket.gethostname())[0]) #возвращает полное имя хоста

import os
system_name = os.getenv('COMPUTERNAME', 'defaultValue')
print ("Системное имя: " + system_name)


import socket
# '0.0.0.0' — это означает, что прослушиваются вообще все интерфейсы
host = '0.0.0.0'
port = 11719
addr = (host,port) 
#Настройка файла логера
logging.basicConfig(filename="sample.log", level=logging.INFO)
logging.debug("This is a debug message")
logging.info("Informational message")


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#s.bind(('0.0.0.0',11719)) 
s.bind(addr)

#Бесконечный цикл работы программы
while True:
   	#message = s.recv(128)
        print("Ждем данные")
        conntent, addr = s.recvfrom(1024)
        milsek = int((round(time_.time() * 1000)))
        Tim=time.strftime('%H:%M:%S')
        message=str(Tim)+'.'+str(milsek)+str(addr)+' '+str(conntent);
        mess = b'Hello, server!'
        #s.send(mess)
        print(message)
        logging.info(message)
        print(" ")
   
