import dearpygui.dearpygui as dpg
from math import sin, cos
import threading
import time

dpg.create_context()

sindatax = []
sindatay = []


count = 0
def update_series():
    global count
    cosdatax = []
    cosdatay = []
    count=count+10
    for i in range(0, 500):
        cosdatax.append(i / 1000)
        cosdatay.append(0.5 + 0.5 * cos(50 * (i+count) / 1000))

    for index in range(8):
        ch=index+1;
        tip = " In "
        dpg.set_value('series_tag_ch'+str(ch)+tip, [cosdatax, cosdatay])
        tip = " Out "
        dpg.set_value('series_tag_ch' + str(ch) + tip, [cosdatax, cosdatay])
        #dpg.set_item_label('series_tag_ch1', "0.5 + 0.5 * cos(x)")
start = 0;

def threaded_function(arg): #В потоке читаем СОКЕТ
    global start;
    while (1):
        if (start):
            time.sleep(0.002);  # Ждем 0,02сек
            update_series();

tCOM = threading.Thread(target=threaded_function, args=(15,))  # Настраиваем поток
tCOM.daemon = True
tCOM.start()  # Запускаем

for i in range(0, 500):
    sindatax.append(i / 1000)
    sindatay.append(0.5 + 0.5 * sin(50 * i / 1000))

def update_series_start():
    global start;
    start = 1;

def update_series_stop():
    global start;
    start = 0;

import socket
import uuid     #Чтоб узнать MAC
import binascii #для CRC32
import zlib     #для CRC32

def SendMess():
    Tim = time.strftime('%H:%M:%S')  # вставляем время
    #host = '255.255.255.255'
    host = '10.14.23.21'
    port = 11719
    addr = (host, port)
    hostmae = socket.gethostname()
    ip = socket.gethostbyname(socket.getfqdn())
    mac = uuid.getnode()
    mac = "%012X" % mac
    b = bytearray([8, 2, 0, 0, 111, 99])  # Команда на чтение данных из платы
    data_raw = b
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = Tim.encode() + b' ' + ip.encode() + b'@beg' + data_raw + b'@end Ok! #crc';
    # message=Tim+' '+hostmae+' '+ip+' '+mac+' '+str(data_raw)+' Ok!';
    # message.encode() - конвертируем строку в байтовую строку
    crc32 = binascii.crc32(message)
    # print (hex(crc32%(1<<32)))
    message = message + b' ' + str(crc32).encode()
    # print ('SendMess')
    sock.sendto(message, addr)
    # print (message)
    crc= str(crc32)
    # crc.=str(crc32)
    print("жду ответа")
    #conn, addr = sock.recvfrom(1024)
    #print(conn)
    #print(addr)
    print("" "")
    sock.close()  # закрываем сокет

def ReadMessLan():
        print('Жду данные')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(('0.0.0.0', 11719))
        conn, addr = s.recvfrom(1024)
        print(conn)
        print(addr)
        print("" "")
        s.close()

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

count = 1;
from datetime import datetime
def send_mess ():
    b_mess = bytearray([8, 2, 0, 0, 111, 99])  # Команда на чтение данных из платы
    global count
    import socket
    host = '127.0.0.1'
    port = 11719
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Подключено к серверу {host}:{port}")
    message = "Привет, сервер N "+str(count);
    count=count+1;
    #client_socket.send(message.encode())  # Отправляем данные
    client_socket.send(b_mess)  # Отправляем данные
    data = client_socket.recv(1024)  # Получаем ответ от сервера
    print(f"Получено от сервера: {data.decode()}")
    Tim = datetime.utcnow().strftime('%H:%M:%S.%f')
    print(Tim + ":" + AreeyBinToStrHex(data))
    client_socket.close()
    print(f"  ")


def send_mess_forr_Socket():
    global start;
    start = 0;
    send_mess ();##SendMess();#ReadMessLan();
    print("Send for socket...");


with dpg.font_registry():
    with dpg.font(f'C:\\Windows\\Fonts\\arialbi.ttf', 9, default_font=True, id="Default font"):
        dpg.add_font_range_hint(dpg.mvFontRangeHint_Cyrillic)

with dpg.window(label="Setting:"):
        #with dpg.group(horizontal=True):
        dpg.add_button(label="Update Series", callback=update_series)
        dpg.add_button(label="Start thread", callback=update_series_start)
        dpg.add_button(label="Stop thread", callback=update_series_stop)
        dpg.add_button(label="SendMess", callback=send_mess_forr_Socket)
with dpg.window(label="Plot In", tag="win_In" , width=400, height=1200, pos=[550, 0]):
    # create plot ch1
    tip = " In "
    for index in range(8):
         ch=index+1;
         with dpg.plot( height=120, width=400, no_title=True):
            # optionally create legend
            dpg.add_plot_legend()

            # REQUIRED: create x and y axes
            dpg.add_plot_axis(dpg.mvXAxis, label="t")
            dpg.add_plot_axis(dpg.mvYAxis, label="A"+" Ch"+str(ch)+tip, tag="y_axis"+str(ch)+tip)

            # series belong to a y axis
            #dpg.add_line_series(sindatax, sindatay, label="0.5 + 0.5 * sin(x)", parent="y_axis"+str(ch), tag="series_tag_ch"+str(ch))
            dpg.add_line_series(sindatax, sindatay, parent="y_axis"+str(ch)+tip, tag="series_tag_ch"+str(ch)+tip)

with dpg.window(label="Plot Out", tag="win_Out" , width=400, height=1200, pos=[120, 0]):
    # create plot ch1
    for index in range(8):
         ch=index+1;
         tip= " Out "
         with dpg.plot( height=120, width=400, no_title=True):
            # optionally create legend
            dpg.add_plot_legend()

            # REQUIRED: create x and y axes
            dpg.add_plot_axis(dpg.mvXAxis, label="t")
            dpg.add_plot_axis(dpg.mvYAxis, label="A"+" Ch"+str(ch)+tip, tag="y_axis"+str(ch)+tip)

            # series belong to a y axis
            #dpg.add_line_series(sindatax, sindatay, label="0.5 + 0.5 * sin(x)", parent="y_axis"+str(ch), tag="series_tag_ch"+str(ch))
            dpg.add_line_series(sindatax, sindatay, parent="y_axis"+str(ch)+tip, tag="series_tag_ch"+str(ch)+tip)
dpg.create_viewport(title='Custom Title', width=800, height=600)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()