import dearpygui.dearpygui as dpg #pip install dearpygui
import subprocess
import sys #100017
import time #2
from math import sin, cos
import threading
import time
import socket
import datetime
#pip install modbus-tk
import sys
import modbus_tk
import modbus_tk.defines as cst
from modbus_tk import modbus_tcp
revForPO = "7";
StertCmdForModBus = "set_values 1 3 1 4 5 6 7 8 7 "+revForPO;
CmdDateForModBus = "1 3 1 4 5 6 7 8 7 "+revForPO;
cmdForModBus = StertCmdForModBus

def mServer(arg):
    host = '127.0.0.1'  # Или 'localhost'
    port = 11719
    print(f"Запускаю сервер на {host}:{port}")
    while True:
        b_mess = bytearray([8, 2, 0, 0, 111, 99])  # Команда на чтение данных из платы
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET для IPv4, SOCK_STREAM для TCP
        server_socket.bind((host, port))
        server_socket.listen(1)  # Начинаем слушать входящие соединения (1 - максимальное количество подключений в очереди)
        print(f"Сервер слушает на {host}:{port}")
        client_socket, address = server_socket.accept()
        print(f"Подключен клиент с адресом {address}")
        while True:
            data = client_socket.recv(1024).decode()  # Получаем данные от клиента (1024 байта)
            if not data:
                break  # Если данных нет, клиент отключился
            print(f"Получено от клиента: {data}")
            Tim = datetime.utcnow().strftime('%H:%M:%S.%f')
            print(Tim + ":" + AreeyBinToStrHex(data.encode()))
            # client_socket.send("Сообщение получено!".encode()) # Отправляем ответ
            client_socket.send(b_mess)  # Отправляем ответ

        client_socket.close()
        server_socket.close()
        print(f"  ")



ip_point = '192.168.50.208'
#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socketZRU = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socketZRU.settimeout(3.0)
socketZRU.connect((ip_point, 3019))  # Подключаемся к нашему серверу  .arp -a

def hex_0x00(nums):
    result = ""
    if nums <= 15:
        result += "0%x" % nums
    else:
        result += "%x" % nums
    return result


def StrHexToAreeyBin(dateInStr):  # разбиваем данные
    result = "";
    for g in range(len(dateInStr)):
        result = result + " 0x" + (hex_0x00(dateInStr[g]));
    return result


def AreeyBinToStrHex(dateInBIN):
    result = "";
    for g in range(len(dateInBIN)):
        result = result + " 0x" + (hex_0x00(dateInBIN[g]));
    return result

dpg.create_context()
input_text_tag = None
input_text_tag_str_buf = ""
sindatax = []
sindatay = []

Amplituda = 128
DI_16_OUT = 128

Amplituda_Ch1 = 128
Amplituda_Ch2 = 128
Amplituda_Ch3 = 128
Amplituda_Ch4 = 128
Amplituda_Ch5 = 128
Amplituda_Ch6 = 128
Amplituda_Ch7 = 128
Amplituda_Ch8 = 128

Phase_Ch1 = 128
Phase_Ch2 = 128
Phase_Ch3 = 128
Phase_Ch4 = 128
Phase_Ch5 = 128
Phase_Ch6 = 128
Phase_Ch7 = 128
Phase_Ch8 = 128

Frequency = 2560
Ofset = 0.5

count = 0

def update_IFO():
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
    print ("   ")
start = 0;
def update_series():
    global count, Amplituda_Ch1, Frequency, Ofset
    AmplForCh = [Amplituda_Ch1]
    count=count+10
    cos_AM = [Amplituda_Ch1, Amplituda_Ch2, Amplituda_Ch3, Amplituda_Ch4, Amplituda_Ch5, Amplituda_Ch6, Amplituda_Ch7,
              Amplituda_Ch8, ]
    cos_Ph = [Phase_Ch1, Phase_Ch2, Phase_Ch3, Phase_Ch4, Phase_Ch5, Phase_Ch6, Phase_Ch7, Phase_Ch8, ]

    for index in range(8):
        cosdatax = []
        cosdatay = []
        for i in range(0, 500):
            cosdatax.append(i / 1000)
            cosdatay.append(Ofset + (cos_AM[index] / 255) * cos(Frequency / 100 * (i + count) / 1000+cos_Ph[index]))

        ch=index+1;
        tip = " In "
        dpg.set_value('series_tag_ch'+str(ch)+tip, [cosdatax, cosdatay])
        tip = " Out "
        dpg.set_value('series_tag_ch' + str(ch) + tip, [cosdatax, cosdatay])
        #dpg.set_item_label('series_tag_ch1', "0.5 + 0.5 * cos(x)")
start = 0;

def threaded_function_sin_mon(arg): #В потоке читаем СОКЕТ
    global start;
    while (1):
        if (start):
            time.sleep(0.002);  # Ждем 0,02сек
            update_series();

tCOM = threading.Thread(target=threaded_function_sin_mon, args=(15,))  # Настраиваем поток
tCOM.daemon = True

def modBServ (arg):
    global cmdForModBus,input_text_tag_str_buf;
    try:
        time.sleep(1)
        #Create the server
        server = modbus_tcp.TcpServer()
        server.start()
        slave_1 = server.add_slave(1)
        slave_1.add_block('1', cst.COILS, 0, 32)
        slave_1.add_block('2', cst.DISCRETE_INPUTS, 0, 32)
        slave_1.add_block('3', cst.HOLDING_REGISTERS, 0, 32)
        slave_1.add_block('4', cst.ANALOG_INPUTS, 0, 32)
        print(f"Stert modbus_tcp.TcpServer")
        for g in range(4):
            print(" ")
            print(f"cmd modbus_tcp "+str(g))
            cmd = 'set_values 1 '+str(g+1)+' 0 1 '+revForPO+' 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 '+str(g)
            args = cmd.split(' ')
            slave_id = int(args[1])
            name = args[2]
            address = int(args[3])
            values = []
            #print(cmd)
            #input_text_tag_str_buf = "\n" + cmd + input_text_tag_str_buf
            #dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения
            for val in args[4:]:
                if (val != " "):
                    if (val != ""):
                        values.append(int(val))
            slave = server.get_slave(slave_id)
            slave.set_values(name, address, values)
            values = slave.get_values(name, address, len(values))
        countSeck = 0
        while True:
            time.sleep(0.1)
            countSeck=countSeck+1;
            cmdForModBus = 'set_values 1 ' + str( g + 1) + ' 0 '+str(countSeck)+' '+revForPO+' 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 ' + str(g)
            if (cmdForModBus != ""):
                #cmd = "set_values 1 0 1 4 5 6 7 8 9 10"
                #args = cmd.split(' ')
                cmd = cmdForModBus# sys.stdin.readline()
                input_text_tag_str_buf = "\n" + cmd + input_text_tag_str_buf
                dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения
                args = cmd.split(' ')
                if cmd.find('quit') == 0:
                    print(f"modbus_tcp 3")
                    sys.stdout.write('bye-bye\\r\\n')
                    break

                elif args[0] == 'add_slave':
                    print(f"modbus_tcp 4")
                    slave_id = int(args[1])
                    server.add_slave(slave_id)
                    sys.stdout.write('done: slave %d added\\r\\n' % slave_id)
                    cmdForModBus = ""

                elif args[0] == 'add_block':
                    print(f"modbus_tcp 5")
                    slave_id = int(args[1])
                    name = args[2]
                    block_type = int(args[3])
                    starting_address = int(args[4])
                    length = int(args[5])
                    slave = server.get_slave(slave_id)
                    slave.add_block(name, block_type, starting_address, length)
                    sys.stdout.write('done: block %s added\\r\\n' % name)
                    cmdForModBus = ""

                elif args[0] == 'set_values':
                    slave_id = int(args[1])
                    name = args[2]
                    address = int(args[3])
                    values = []
                    #print(args[4:])
                    for val in args[4:]:
                        if (val != " "):
                            if (val != ""):
                                values.append(int(val))
                    slave = server.get_slave(slave_id)
                    slave.set_values(name, address, values)
                    #values = slave.get_values(name, address, len(values))
                    cmdForModBus = ""

                elif args[0] == 'get_values':
                    #вернуть значения n элементов по указанному адресу указанного блока
                    print(f"modbus_tcp 7")
                    slave_id = int(args[1])
                    name = args[2]
                    address = int(args[3])
                    length = int(args[4])
                    slave = server.get_slave(slave_id)
                    values = slave.get_values(name, address, length)
                    sys.stdout.write('done: values read: %s\\r\\n' % str(values))
                    cmdForModBus = ""
                else:
                    sys.stdout.write("unknown command %s\\r\\n" % args[0])
                    cmdForModBus = ""
                if (True):
                    #вернуть значения n элементов по указанному адресу указанного блока
                    values1 = server.get_slave(1).get_values('1', 0, 25)
                    values2 = server.get_slave(1).get_values('2', 0, 25)
                    values3 = server.get_slave(1).get_values('3', 0, 25)
                    values4 = server.get_slave(1).get_values('4', 0, 25)
                    input_text_tag_str_buf = "\n"+"\n" + "get_values "+str(values1) +"\n" + "get_values "+str(values2)+"\n" + "get_values "+str(values3) + input_text_tag_str_buf
                    dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения
    finally:
        print(f"Ошибка команды для сервер")
        #server.stop()

tServer = threading.Thread(target=modBServ, args=(15,))  # Настраиваем поток
tServer.daemon = True
#########
import numpy as np
vm=0;
incVm=0
def threaded_function(arg): #В потоке читаем СОКЕТ
    global ignorirofvat, crcvar1, line ,input_text_tag_str_buf,vm ,incVm #Ищем среди глобальных
    print('Работаю по LAN...')
    count = 0;
    valueList1 = [];
    valueList2 = [];
    y1 = [];
    up_down = 0;
    tmr = datetime.datetime.now();
    oltT = time.time();
    while (1):              #В бесконечном цикле
        #time.sleep(0.01)
        if (start):            #setPWM.set(0);
            freq = int(Frequency);
            All_Ch = (count.to_bytes(2,byteorder="little")+
                      freq.to_bytes(2, byteorder="little")+

                      Amplituda_Ch1.to_bytes(1, byteorder="little")+
                      Amplituda_Ch2.to_bytes(1, byteorder="little")+
                      Amplituda_Ch3.to_bytes(1, byteorder="little")+
                      Amplituda_Ch4.to_bytes(1, byteorder="little")+
                      Amplituda_Ch5.to_bytes(1, byteorder="little")+
                      Amplituda_Ch6.to_bytes(1, byteorder="little")+
                      Amplituda_Ch7.to_bytes(1, byteorder="little")+
                      Amplituda_Ch8.to_bytes(1, byteorder="little")+

                      Phase_Ch1.to_bytes(1, byteorder="little") +
                      Phase_Ch2.to_bytes(1, byteorder="little") +
                      Phase_Ch3.to_bytes(1, byteorder="little") +
                      Phase_Ch4.to_bytes(1, byteorder="little") +
                      Phase_Ch5.to_bytes(1, byteorder="little") +
                      Phase_Ch6.to_bytes(1, byteorder="little") +
                      Phase_Ch7.to_bytes(1, byteorder="little") +
                      Phase_Ch8.to_bytes(1, byteorder="little") +

                      DI_16_OUT.to_bytes(2, byteorder="little"));
            # format_f = bytes(
            #     [ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      ch1,
            #      0x00, 0x00]);
            lenDat = len(All_Ch);
            #socketZRU.sendall(np.array([ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1]))  # Отправляем фразу.
            while ((time.time()-oltT)<0.001):
                pass

            socketZRU.sendall(All_Ch)  # Отправляем фразу.
            timSend = time.time();
            data = socketZRU.recv(lenDat)  # Получаем данные из сокета.

            count = count + 1;
            if (count>25000):count=0;
            if (True):
                strADC = "";
                i = 0;
                ADC_Arr = [];
                for n in range(10):
                    arry = data[0+i:2+i];
                    ADC_Arr.append(int.from_bytes(arry, 'little'))
                    strADC=strADC+" " + str(ADC_Arr[-1])# Берем последний элемент списка
                    i=i+2;
                #miliSek =(oltT - tmr).microseconds/1000
                #print(str(count) + " " + str(ADC_Arr[1])+" "+str(miliSek) +"("+str(int((ADC_Arr[1]/miliSek)*60000)) +")")# time.sleep(0.02)
                #print(str((oltT - tmr).microseconds/1000) + " милиСек: 1000 штук принял")

            vm=vm+1;
            if (vm == 100):
                vm=0;
                incVm=incVm+1;
                input_text_tag_str_buf =  (str(count).rjust(5)+ ")  "
                  + str(ADC_Arr[1]).rjust(5) + " "
                  + str(ADC_Arr[2]).rjust(5) + " "
                  + str(ADC_Arr[3]).rjust(5) + " "
                  + str(ADC_Arr[4]).rjust(5) + " "
                  + str(ADC_Arr[5]).rjust(5) + " "
                  + str(ADC_Arr[6]).rjust(5) + " "
                  + str(ADC_Arr[7]).rjust(5) + " "
                  + str(ADC_Arr[8]).rjust(5) + " "
                  + str(timSend - oltT))+"\\n" + input_text_tag_str_buf
                print(str(incVm)+" - "+str(len(input_text_tag_str_buf)))
                input_text_tag_str_buf = input_text_tag_str_buf[:25000]
                dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения
            oltT=timSend
            #print()
            #time.sleep(3)  # Ждем 1.001 сек
            #print(time.time()-oltT)

t = threading.Thread(target=threaded_function, args=(15,)) # Настраиваем поток
t.daemon = True

##########

for i in range(0, 500):
    sindatax.append(i / 1000)
    sindatay.append(0.5 + 0.5 * sin(50 * i / 1000))

def update_series_start():
    global start;
    start = 1;

def update_series_stop():
    global start;
    start = 0;


def slider_callback_Set_P_Ch1(sender, app_data, user_data):
    global Phase_Ch1
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch1 = app_data
def slider_callback_Set_P_Ch2(sender, app_data, user_data):
    global Phase_Ch2
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch2 = app_data
def slider_callback_Set_P_Ch3(sender, app_data, user_data):
    global Phase_Ch3
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch3 = app_data
def slider_callback_Set_P_Ch4(sender, app_data, user_data):
    global Phase_Ch4
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch4 = app_data
def slider_callback_Set_P_Ch5(sender, app_data, user_data):
    global Phase_Ch5
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch5 = app_data
def slider_callback_Set_P_Ch6(sender, app_data, user_data):
    global Phase_Ch6
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch6 = app_data
def slider_callback_Set_P_Ch7(sender, app_data, user_data):
    global Phase_Ch7
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch7 = app_data
def slider_callback_Set_P_Ch8(sender, app_data, user_data):
    global Phase_Ch8
    #print(f"Значение ползунка: {app_data}")
    Phase_Ch8 = app_data


def slider_callback_Set_A_Ch1(sender, app_data, user_data):
    global Amplituda_Ch1
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch1 = app_data
def slider_callback_Set_A_Ch2(sender, app_data, user_data):
    global Amplituda_Ch2
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch2 = app_data
def slider_callback_Set_A_Ch3(sender, app_data, user_data):
    global Amplituda_Ch3
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch3 = app_data
def slider_callback_Set_A_Ch4(sender, app_data, user_data):
    global Amplituda_Ch4
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch4 = app_data
def slider_callback_Set_A_Ch5(sender, app_data, user_data):
    global Amplituda_Ch5
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch5 = app_data
def slider_callback_Set_A_Ch6(sender, app_data, user_data):
    global Amplituda_Ch6
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch6 = app_data
def slider_callback_Set_A_Ch7(sender, app_data, user_data):
    global Amplituda_Ch7
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch7 = app_data
def slider_callback_Set_A_Ch8(sender, app_data, user_data):
    global Amplituda_Ch8
    #print(f"Значение ползунка: {app_data}")
    Amplituda_Ch8 = app_data




def slider_callback_Set_A(sender, app_data, user_data):
    global Amplituda
    #print(f"Значение ползунка: {app_data}")
    Amplituda = app_data

def slider_callback_Set_F(sender, app_data, user_data):
    global Frequency
    #print(f"Значение ползунка: {app_data}")
    Frequency = app_data

def slider_callback_Set_Ofset(sender, app_data, user_data):
    global Ofset
    #print(f"Значение ползунка: {app_data}")
    Ofset = app_data

#with dpg.font_registry():
#    with dpg.font(f'C:\\\\Windows\\\\Fonts\\\\arialbi.ttf', 9, default_font=True, id="Default font"):
#        dpg.add_font_range_hint(dpg.mvFontRangeHint_Cyrillic)

with dpg.font_registry():
    with dpg.font(f'C:\\\\Windows\\\\Fonts\\\\arialbi.ttf', 20, default_font=True, tag="Default font") as f:
        dpg.add_font_range_hint(dpg.mvFontRangeHint_Cyrillic)

dpg.bind_font("Default font")

with dpg.window(label="Data log.", width=700, height=500, pos=[0, 300]):
    input_text_tag = dpg.add_input_text(
        hint="Some description",
        multiline=True,
        width=700, height=500,
    )
def get_IP_Loc ():
    import socket
    global input_text_tag_str_buf
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
    input_text_tag_str_buf ="\n" + "IP loc: " + str(s.getsockname()[0])+", IP point: "+ ip_point+ input_text_tag_str_buf
    s.close()
    dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения

def update_lan():
    def threaded_function(arg):  # В потоке читаем СОКЕТ
        global ignorirofvat, crcvar1, line, input_text_tag_str_buf, vm  # Ищем среди глобальных
        print('Работаю по LAN...')
        count = 0;
        valueList1 = [];
        valueList2 = [];
        y1 = [];
        up_down = 0;
        tmr = datetime.datetime.now();
        oltT = time.time();
        while (1):  # В бесконечном цикле
            # time.sleep(0.01)
            if (start):  # setPWM.set(0);

                ch1 = count.to_bytes(2, byteorder="little")
                All_Ch = ch1 + ch1 + ch1 + ch1 + ch1 + ch1 + ch1 + ch1 + ch1 + ch1 + ch1;
                # format_f = bytes(
                #     [ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      ch1,
                #      0x00, 0x00]);
                lenDat = len(All_Ch);
                # socketZRU.sendall(np.array([ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1, ch1]))  # Отправляем фразу.
                while ((time.time() - oltT) < 0.001):
                    pass

                socketZRU.sendall(All_Ch)  # Отправляем фразу.
                data = socketZRU.recv(lenDat)  # Получаем данные из сокета.
                timSend = time.time();
                count = count + 1;
                if (True):
                    strADC = "";
                    i = 0;
                    ADC_Arr = [];
                    for n in range(10):
                        arry = data[0 + i:2 + i];
                        ADC_Arr.append(int.from_bytes(arry, 'little'))
                        strADC = strADC + " " + str(ADC_Arr[-1])  # Берем последний элемент списка
                        i = i + 2;
                    # miliSek =(oltT - tmr).microseconds/1000
                    # print(str(count) + " " + str(ADC_Arr[1])+" "+str(miliSek) +"("+str(int((ADC_Arr[1]/miliSek)*60000)) +")")# time.sleep(0.02)
                    # print(str((oltT - tmr).microseconds/1000) + " милиСек: 1000 штук принял")

                vm = vm + 1;
                if (vm == 100):
                    vm = 0;
                    input_text_tag_str_buf = (str(count).rjust(5) + ")  "
                                              + str(ADC_Arr[1]).rjust(5) + " "
                                              + str(ADC_Arr[2]).rjust(5) + " "
                                              + str(ADC_Arr[3]).rjust(5) + " "
                                              + str(ADC_Arr[4]).rjust(5) + " "
                                              + str(ADC_Arr[5]).rjust(5) + " "
                                              + str(ADC_Arr[6]).rjust(5) + " "
                                              + str(ADC_Arr[7]).rjust(5) + " "
                                              + str(ADC_Arr[8]).rjust(5) + " "
                                              + str(timSend - oltT)) + "\\n" + input_text_tag_str_buf
                    dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения
                oltT = timSend
                # print()
                # time.sleep(3)  # Ждем 1.001 сек
                # print(time.time()-oltT)

def _log(sender, app_data, user_data):
    global cmdForModBus,input_text_tag_str_buf, StertCmdForModBus
    #cmdForModBus = app_data;
    if (sender == "input1"): cmdForModBus ="set_values 1 1 "+app_data;  print(cmdForModBus);
    if (sender == "input2"): cmdForModBus ="set_values 1 2 "+app_data;  print(cmdForModBus);
    if (sender == "input3"): cmdForModBus ="set_values 1 3 "+app_data;  print(cmdForModBus);
    if (sender == "input4"): cmdForModBus ="set_values 1 4 "+app_data;  print(cmdForModBus);
    rez =f"sender: {sender}, \t app_data: {app_data}, \t user_data: {user_data}"
    print(rez)
    #input_text_tag_str_buf = rez+"\n"+input_text_tag_str_buf[:25000]
    #dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения

with dpg.window(label="Setting:"):
        #with dpg.group(horizontal=True):
        dpg.add_button(label="Get IP_Loc", callback=get_IP_Loc)
        dpg.add_button(label="Update INFO", callback=update_IFO)
        dpg.add_button(label="Start thread", callback=update_series_start)
        dpg.add_button(label="Stop thread", callback=update_series_stop)
        dpg.add_slider_float(label="A", default_value=Amplituda,
                             min_value=0.0, max_value=255.0,
                             callback=slider_callback_Set_A,
                             width=200, height=30)
        dpg.add_slider_float(label="F", default_value=Frequency,
                             min_value=2500, max_value=3000,
                             callback=slider_callback_Set_F,
                             width=200, height=30)

        dpg.add_slider_float(label="Set", default_value = Ofset,
                             min_value=-2.0, max_value=2.0,
                             callback=slider_callback_Set_Ofset,
                             width=200, height=30)
        dpg.add_slider_float(label="w", default_value = Ofset,
                             min_value=0, max_value=360,
                             callback=slider_callback_Set_Ofset,
                             width=200, height=30)

with dpg.window(label="Setting AM:", pos=[250, 0]):
    dpg.add_slider_int(label="Ch1", default_value=Amplituda_Ch1,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch1,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch2", default_value=Amplituda_Ch2,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch2,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch3", default_value=Amplituda_Ch3,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch3,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch4", default_value=Amplituda_Ch4,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch4,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch5", default_value=Amplituda_Ch5,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch5,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch6", default_value=Amplituda_Ch6,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch6,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch7", default_value=Amplituda_Ch7,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch7,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch8", default_value=Amplituda_Ch8,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_A_Ch8,
                         width=200, height=30)

with dpg.window(label="Setting Phas:", pos=[500, 0]):
    dpg.add_slider_int(label="Ch1", default_value=Phase_Ch1,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch1,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch2", default_value=Phase_Ch2,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch2,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch3", default_value=Phase_Ch3,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch3,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch4", default_value=Phase_Ch4,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch4,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch5", default_value=Phase_Ch5,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch5,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch6", default_value=Phase_Ch6,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch6,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch7", default_value=Phase_Ch7,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch7,
                         width=200, height=30)
    dpg.add_slider_int(label="Ch8", default_value=Phase_Ch8,
                         min_value=0, max_value=255,
                         callback=slider_callback_Set_P_Ch8,
                         width=200, height=30)

with dpg.window(label="Plot In", tag="win_In" , width=800, height=1200, pos=[750, 0]):
    # create plot ch1
    ch = 0
    for index in range(8):
         ch=ch+1;
         tip = " In "
         with dpg.group(horizontal=True):
             with dpg.plot( height=120, width=400, no_title=True):
                # optionally create legend
                dpg.add_plot_legend()

                # REQUIRED: create x and y axes
                dpg.add_plot_axis(dpg.mvXAxis, label="t")
                dpg.add_plot_axis(dpg.mvYAxis, label="A"+" Ch"+str(ch)+tip, tag="y_axis"+str(ch)+tip)

                # series belong to a y axis
                #dpg.add_line_series(sindatax, sindatay, label="0.5 + 0.5 * sin(x)", parent="y_axis"+str(ch), tag="series_tag_ch"+str(ch))
                dpg.add_line_series(sindatax, sindatay, parent="y_axis"+str(ch)+tip, tag="series_tag_ch"+str(ch)+tip)
             tip = " Out "
             with dpg.plot( height=120, width=400, no_title=True):
                # optionally create legend
                dpg.add_plot_legend()

                # REQUIRED: create x and y axes
                dpg.add_plot_axis(dpg.mvXAxis, label="t")
                dpg.add_plot_axis(dpg.mvYAxis, label="A"+" Ch"+str(ch)+tip, tag="y_axis"+str(ch)+tip)

                # series belong to a y axis
                #dpg.add_line_series(sindatax, sindatay, label="0.5 + 0.5 * sin(x)", parent="y_axis"+str(ch), tag="series_tag_ch"+str(ch))
                dpg.add_line_series(sindatax, sindatay, parent="y_axis"+str(ch)+tip, tag="series_tag_ch"+str(ch)+tip)

with dpg.window(label="ModBus:" , width=600, height=200, pos=[0, 100]):
    #with dpg.group(horizontal=True):
    # slave_1.add_block('1', cst.COILS, 0, 10)
    # slave_1.add_block('2', cst.DISCRETE_INPUTS, 0, 10)
    # slave_1.add_block('3', cst.HOLDING_REGISTERS, 0, 10)
    # slave_1.add_block('4', cst.ANALOG_INPUTS, 0, 10)
    with dpg.group(horizontal=True):
        with dpg.group(horizontal=True):
          dpg.add_text("Address:")
          dpg.add_input_text( tag="Address", default_value="0001", hint="Write CMD", width=50, callback=_log)
          dpg.add_button(label="Set", callback=get_IP_Loc)
        with dpg.group(horizontal=True):
              dpg.add_text("ID Device:")
              dpg.add_input_text(tag="ID_Device", default_value="01", hint="Write CMD", width=50, callback=_log)
              dpg.add_button(label="Set", callback=get_IP_Loc)
    with dpg.group(horizontal=True):
      dpg.add_text("1:COILS")
      dpg.add_input_text( tag="input1", default_value=CmdDateForModBus, hint="Write CMD", width=230, callback=_log)
      dpg.add_button(label="Set", callback=get_IP_Loc)
      dpg.add_button(label="Get", callback=get_IP_Loc)
    with dpg.group(horizontal=True):
      dpg.add_text("2:DISCRETE_INPUTS")
      dpg.add_input_text( tag="input2", default_value=CmdDateForModBus, hint="Write CMD", width=230, callback=_log)
      dpg.add_button(label="Set", callback=get_IP_Loc)
      dpg.add_button(label="Get", callback=get_IP_Loc)
    with dpg.group(horizontal=True):
      dpg.add_text("3:HOLDING_REGISTERS")
      dpg.add_input_text( tag="input3", default_value=CmdDateForModBus, hint="Write CMD", width=230, callback=_log)
      dpg.add_button(label="Set", callback=get_IP_Loc)
      dpg.add_button(label="Get", callback=get_IP_Loc)
    with dpg.group(horizontal=True):
      dpg.add_text("4:ANALOG_INPUTS")
      dpg.add_input_text(tag="input4", default_value=CmdDateForModBus, hint="Write CMD", width=230, callback=_log)
      dpg.add_button(label="Set", callback=get_IP_Loc)
      dpg.add_button(label="Get", callback=get_IP_Loc)


dpg.create_viewport(title='ZruMod '+' : Rev '+revForPO, width=1900, height=1200,x_pos = 0, y_pos = 0)
dpg.setup_dearpygui()
dpg.show_viewport()
#tCOM.start()  # Запускаем
#t.start()  #Запускаем поток
tServer.start()
dpg.start_dearpygui()

dpg.destroy_context()











