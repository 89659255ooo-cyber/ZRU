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
#from modbus_tk import modbus_tcp
import struct

revForPO = "26";
StertCmdForModBus = "set_values 1 3 1 4 5 6 7 8 7 "+revForPO;
CmdDateForModBus = "1 3 1 4 5 6 7 8 7 "+revForPO;
cmdForModBus = StertCmdForModBus
wrRegAddr = 0
###################################################################

# !/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python

 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr

 This is distributed under GNU LGPL license, see license.txt
"""

import socket
import select
import struct

from modbus_tk import LOGGER
from modbus_tk.hooks import call_hooks
from modbus_tk.modbus import (
    Databank, Master, Query, Server,
    InvalidArgumentError, ModbusInvalidResponseError, ModbusInvalidRequestError
)
from modbus_tk.utils import threadsafe_function, flush_socket, to_data


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


# -------------------------------------------------------------------------------
class ModbusInvalidMbapError(Exception):
    """Exception raised when the modbus TCP header doesn't correspond to what is expected"""

    def __init__(self, value):
        Exception.__init__(self, value)


# -------------------------------------------------------------------------------
class TcpMbap(object):
    """Defines the information added by the Modbus TCP layer"""

    def __init__(self):
        """Constructor: initializes with 0"""
        self.transaction_id = 0
        self.protocol_id = 0
        self.length = 0
        self.unit_id = 0

    def clone(self, mbap):
        """Set the value of each fields from another TcpMbap instance"""
        self.transaction_id = mbap.transaction_id
        self.protocol_id = mbap.protocol_id
        self.length = mbap.length
        self.unit_id = mbap.unit_id

    def _check_ids(self, request_mbap):
        """
        Check that the ids in the request and the response are similar.
        if not returns a string describing the error
        """
        error_str = ""

        if request_mbap.transaction_id != self.transaction_id:
            error_str += "Invalid transaction id: request={0} - response={1}. ".format(
                request_mbap.transaction_id, self.transaction_id)

        if request_mbap.protocol_id != self.protocol_id:
            error_str += "Invalid protocol id: request={0} - response={1}. ".format(
                request_mbap.protocol_id, self.protocol_id
            )

        if request_mbap.unit_id != self.unit_id:
            error_str += "Invalid unit id: request={0} - response={1}. ".format(request_mbap.unit_id, self.unit_id)

        return error_str

    def check_length(self, pdu_length):
        """Check the length field is valid. If not raise an exception"""
        following_bytes_length = pdu_length + 1
        if self.length != following_bytes_length:
            return "Response length is {0} while receiving {1} bytes. ".format(self.length, following_bytes_length)
        return ""

    def check_response(self, request_mbap, response_pdu_length):
        """Check that the MBAP of the response is valid. If not raise an exception"""
        error_str = self._check_ids(request_mbap)
        error_str += self.check_length(response_pdu_length)
        if len(error_str) > 0:
            raise ModbusInvalidMbapError(error_str)

    def pack(self):
        """convert the TCP mbap into a string"""
        return struct.pack(">HHHB", self.transaction_id, self.protocol_id, self.length, self.unit_id)

    def unpack(self, value):
        """extract the TCP mbap from a string"""
        (self.transaction_id, self.protocol_id, self.length, self.unit_id) = struct.unpack(">HHHB", value)


class TcpQuery(Query):
    """Subclass of a Query. Adds the Modbus TCP specific part of the protocol"""

    # static variable for giving a unique id to each query
    _last_transaction_id = 0

    def __init__(self):
        """Constructor"""
        super(TcpQuery, self).__init__()
        self._request_mbap = TcpMbap()
        self._response_mbap = TcpMbap()

    @threadsafe_function
    def _get_transaction_id(self):
        """returns an identifier for the query"""
        if TcpQuery._last_transaction_id < 0xffff:
            TcpQuery._last_transaction_id += 1
        else:
            TcpQuery._last_transaction_id = 0
        return TcpQuery._last_transaction_id

    def build_request(self, pdu, slave):
        """Add the Modbus TCP part to the request"""
        if (slave < 0) or (slave > 255):
            raise InvalidArgumentError("{0} Invalid value for slave id".format(slave))
        self._request_mbap.length = len(pdu) + 1
        self._request_mbap.transaction_id = self._get_transaction_id()
        self._request_mbap.unit_id = slave
        mbap = self._request_mbap.pack()
        return mbap + pdu

    def parse_response(self, response):
        """Extract the pdu from the Modbus TCP response"""
        if len(response) > 6:
            mbap, pdu = response[:7], response[7:]
            self._response_mbap.unpack(mbap)
            self._response_mbap.check_response(self._request_mbap, len(pdu))
            return pdu
        else:
            raise ModbusInvalidResponseError("Response length is only {0} bytes. ".format(len(response)))

    def parse_request(self, request):
        """Extract the pdu from a modbus request"""
        if len(request) > 6:
            mbap, pdu = request[:7], request[7:]
            self._request_mbap.unpack(mbap)
            error_str = self._request_mbap.check_length(len(pdu))
            if len(error_str) > 0:
                raise ModbusInvalidMbapError(error_str)
            return self._request_mbap.unit_id, pdu
        else:
            raise ModbusInvalidRequestError("Request length is only {0} bytes. ".format(len(request)))

    def build_response(self, response_pdu):
        """Build the response"""
        self._response_mbap.clone(self._request_mbap)
        self._response_mbap.length = len(response_pdu) + 1
        return self._response_mbap.pack() + response_pdu


class TcpMaster(Master):
    """Subclass of Master. Implements the Modbus TCP MAC layer"""

    def __init__(self, host="127.0.0.1", port=502, timeout_in_sec=5.0):
        """Constructor. Set the communication settings"""
        super(TcpMaster, self).__init__(timeout_in_sec)
        self._host = host
        self._port = port
        self._sock = None

    def _do_open(self):
        """Connect to the Modbus slave"""
        if self._sock:
            self._sock.close()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_timeout(self.get_timeout())
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        call_hooks("modbus_tcp.TcpMaster.before_connect", (self,))
        self._sock.connect((self._host, self._port))
        call_hooks("modbus_tcp.TcpMaster.after_connect", (self,))

    def _do_close(self):
        """Close the connection with the Modbus Slave"""
        if self._sock:
            call_hooks("modbus_tcp.TcpMaster.before_close", (self,))
            self._sock.close()
            call_hooks("modbus_tcp.TcpMaster.after_close", (self,))
            self._sock = None
            return True

    def set_timeout(self, timeout_in_sec):
        """Change the timeout value"""
        super(TcpMaster, self).set_timeout(timeout_in_sec)
        if self._sock:
            self._sock.setblocking(timeout_in_sec > 0)
            if timeout_in_sec:
                self._sock.settimeout(timeout_in_sec)

    def _send(self, request):
        """Send request to the slave"""
        retval = call_hooks("modbus_tcp.TcpMaster.before_send", (self, request))
        if retval is not None:
            request = retval
        try:
            flush_socket(self._sock, 3)
        except Exception as msg:
            # if we can't flush the socket successfully: a disconnection may happened
            # try to reconnect
            LOGGER.error('Error while flushing the socket: {0}'.format(msg))
            self._do_open()
        self._sock.send(request)

    def _recv(self, expected_length=-1):
        """
        Receive the response from the slave
        Do not take expected_length into account because the length of the response is
        written in the mbap. Used for RTU only
        """
        response = to_data('')
        length = 255
        while len(response) < length:
            rcv_byte = self._sock.recv(1)
            if rcv_byte:
                response += rcv_byte
                if len(response) == 6:
                    to_be_recv_length = struct.unpack(">HHH", response)[2]
                    length = to_be_recv_length + 6
            else:
                break
        retval = call_hooks("modbus_tcp.TcpMaster.after_recv", (self, response))
        print(" - " + AreeyBinToStrHex(response))
        if retval is not None:
            return retval
        return response

    def _make_query(self):
        """Returns an instance of a Query subclass implementing the modbus TCP protocol"""
        return TcpQuery()


class TcpServer(Server):
    """
    This class implements a simple and mono-threaded modbus tcp server
    !! Change in 0.5.0: By default the TcpServer is not bound to a specific address
    for example: You must set address to 'loaclhost', if youjust want to accept local connections
    """

    def __init__(self, port=502, address='', timeout_in_sec=1, databank=None, error_on_missing_slave=True):
        """Constructor: initializes the server settings"""
        databank = databank if databank else Databank(error_on_missing_slave=error_on_missing_slave)
        super(TcpServer, self).__init__(databank)
        self._sock = None
        self._sa = (address, port)
        self._timeout_in_sec = timeout_in_sec
        self._sockets = []

    def _make_query(self):
        """Returns an instance of a Query subclass implementing the modbus TCP protocol"""
        return TcpQuery()

    def _get_request_length(self, mbap):
        """Parse the mbap and returns the number of bytes to be read"""
        if len(mbap) < 6:
            raise ModbusInvalidRequestError("The mbap is only %d bytes long", len(mbap))
        length = struct.unpack(">HHH", mbap[:6])[2]
        return length

    def _do_init(self):
        """initialize server"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self._timeout_in_sec:
            self._sock.settimeout(self._timeout_in_sec)
        self._sock.setblocking(0)
        self._sock.bind(self._sa)
        self._sock.listen(10)
        self._sockets.append(self._sock)

    def _do_exit(self):
        """clean the server tasks"""
        # close the sockets
        for sock in self._sockets:
            try:
                sock.close()
            except Exception as msg:
                LOGGER.warning("Error while closing socket, Exception occurred: %s", msg)
        self._sockets = []
        self._sock.close()
        self._sock = None

    def _do_run(self):
        """called in a almost-for-ever loop by the server"""
        # check the status of every socket
        inputready = select.select(self._sockets, [], [], 1.0)[0]

        # handle data on each a socket
        for sock in inputready:
            try:
                if sock == self._sock:
                    # handle the server socket
                    client, address = self._sock.accept()
                    client.setblocking(0)
                    LOGGER.debug("%s is connected with socket %d...", str(address), client.fileno())
                    self._sockets.append(client)
                    call_hooks("modbus_tcp.TcpServer.on_connect", (self, client, address))
                else:
                    if len(sock.recv(1, socket.MSG_PEEK)) == 0:
                        # socket is disconnected
                        LOGGER.debug("%d is disconnected" % (sock.fileno()))
                        call_hooks("modbus_tcp.TcpServer.on_disconnect", (self, sock))
                        sock.close()
                        self._sockets.remove(sock)
                        break

                    # handle all other sockets
                    sock.settimeout(1.0)
                    request = to_data("")
                    is_ok = True

                    # read the 7 bytes of the mbap
                    while (len(request) < 7) and is_ok:
                        new_byte = sock.recv(1)
                        if len(new_byte) == 0:
                            is_ok = False
                        else:
                            request += new_byte

                    retval = call_hooks("modbus_tcp.TcpServer.after_recv", (self, sock, request))
                    if retval is not None:
                        request = retval

                    if is_ok:
                        # read the rest of the request
                        length = self._get_request_length(request)
                        while (len(request) < (length + 6)) and is_ok:
                            new_byte = sock.recv(1)
                            if len(new_byte) == 0:
                                is_ok = False
                            else:
                                request += new_byte

                    if is_ok:
                        response = ""
                        # parse the request
                        try:
                            response = self._handle(request)
                            input_soket = AreeyBinToStrHex(request) + " - " + AreeyBinToStrHex(response);
                            file = open("otusKey_maserModBas.txt", "a+")
                            file.write(input_soket+'\n');
                            file.close();
                            print(input_soket)
                            pass;
                        except Exception as msg:
                            LOGGER.error("Error while handling a request, Exception occurred: %s", msg)

                        # send back the response
                        if response:
                            try:
                                retval = call_hooks("modbus_tcp.TcpServer.before_send", (self, sock, response))
                                if retval is not None:
                                    response = retval
                                sock.send(response)
                                call_hooks("modbus_tcp.TcpServer.after_send", (self, sock, response))
                            except Exception as msg:
                                is_ok = False
                                LOGGER.error(
                                    "Error while sending on socket %d, Exception occurred: %s", sock.fileno(), msg
                                )
            except Exception as excpt:
                LOGGER.warning("Error while processing data on socket %d: %s", sock.fileno(), excpt)
                call_hooks("modbus_tcp.TcpServer.on_error", (self, sock, excpt))
                sock.close()
                self._sockets.remove(sock)


##################################################################




import requests
import os
def send_text_file(bot_token, chat_id, file_path, caption=None):
    """
    Отправляет текстовый файл в чат Telegram

    :param bot_token: Токен бота
    :param chat_id: ID чата
    :param file_path: Путь к файлу на диске
    :param caption: Подпись к файлу (опционально)
    :return: Ответ от Telegram API
    """
    file_path = "otusKey_maserModBas.txt"
    if os.path.isfile(file_path):
        print(f"Файл '{file_path}' существует.")
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        file_path = "otusKey_maserModBas.txt"
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': chat_id}

            if caption:
                data['caption'] = caption
            try:
              response = requests.post(url, files=files, data=data)
            except:
                return "Ошибка отправки файла otusKey_maserModBas.txt"
        return response.json()

    else:
        print(f"Файл '{file_path}' не существует.")

file_path = "otusKey_maserModBas.txt" # Укажите путь к вашему файлу
file_size = 0
if os.path.exists(file_path):
   file_size = os.path.getsize(file_path)

print(f"Размер файла {file_path}: {file_size} байт")

# Для преобразования в другие единицы (например, килобайты):
print(f"Размер файла в КБ: {file_size / 1024:.2f} КБ")

razmer =file_size / 1024;

if (razmer > 10000):
    if os.path.exists(file_path):
        # Если файл существует, удаляем его
        os.remove(file_path)
        print(f"Файл {file_path} успешно удален.")
    else:
        # Если файл не существует, выводим сообщение
        print(f"Файл {file_path} не найден.")

resulSendFile = ""
if os.path.isfile(file_path):
    # Использование
    bot_token = "8260178816:AAGaDtqkJsN7-xT2ClRg46aT1pXb-tm4c3g"
    chat_id = -1002485189388  # ID чата
    resulSendFile = send_text_file(bot_token, chat_id, file_path, "Вот ваш текстовый файл! 📄")
    print(resulSendFile)

# Укажите путь к файлу

# Проверяем, существует ли файл
if (resulSendFile != "Ошибка отправки файла otusKey_maserModBas.txt"):
        if os.path.exists(file_path):
            # Если файл существует, удаляем его
            os.remove(file_path)
            print(f"Файл {file_path} успешно удален.")
        else:
            # Если файл не существует, выводим сообщение
            print(f"Файл {file_path} не найден.")

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
# wrRegAddr = 500
def modBServ (arg):
    global cmdForModBus,input_text_tag_str_buf;
    try:
        countSeck = 1
        time.sleep(1)
        #Create the server
        server = TcpServer(address="0.0.0.0")
        server.start()
        slave_1 = server.add_slave(1)
        slave_1.add_block('1', cst.COILS, 0, 32)
        slave_1.add_block('2', cst.DISCRETE_INPUTS, 0, 0x60*2) #96
        slave_1.add_block('3', cst.HOLDING_REGISTERS, wrRegAddr, 0x60*2)
        slave_1.add_block('4', cst.ANALOG_INPUTS, wrRegAddr, 0x60*2)
        print(f"Stert modbus_tcp.TcpServer")

        #floatValueTobytes = struct.pack('d', floatValue) # Упаковка float в 8 байт
        #unpacked_float = struct.unpack('d', floatValueTobytes)[0]# Упаковка 8 байт d float
        number = 123457869
        int_byte_array = number.to_bytes(4, byteorder='little')

        floatValue = 19.307232;  # 0x419a7536 big-endian, 0x36759a41 little-endian
        floatValueTobytes = struct.pack('<f', floatValue) # Упаковка float в 4 байта  little-endian
        unpacked_float = struct.unpack('<f', floatValueTobytes)[0]# Упаковка  4 х байт в float  little-endian
        reg3 = (0x6720,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3);
        #print(type(reg3) )
        reg_list = []
        hexValueFloat = floatValueTobytes.hex()
        #3 значения
        #reg_list.append(number.to_bytes(4, byteorder='little')[0]) #counter
        #reg_list.append((int(countSeck)).to_bytes(4, byteorder='little')[0])  # counter
        #reg_list.append((int(revForPO)).to_bytes(4, byteorder='little')[0])   # version
        addVAlue=[number,countSeck,int(revForPO)]
        for i in range(3):
            int_byte_array=addVAlue[i].to_bytes(4, byteorder='little')
            firstReg = int_byte_array[0:2]
            int_value_be = int.from_bytes(firstReg, byteorder='little')
            reg_list.append(int_value_be)
            lostReg = int_byte_array[2:4]
            int_value_be = int.from_bytes(lostReg, byteorder='little')
            reg_list.append(int_value_be)

        number = 12345
        int_byte_array = number.to_bytes(4, byteorder='little')
        for i in range(13):
                int_byte_array=number.to_bytes(4, byteorder='little')
                firstReg = int_byte_array[0:2]
                int_value_be = int.from_bytes(firstReg, byteorder='little')
                reg_list.append(int_value_be)
                lostReg = int_byte_array[2:4]
                int_value_be = int.from_bytes(lostReg, byteorder='little')
                reg_list.append(int_value_be)
        for i in range(80):
            firstReg = floatValueTobytes[0:2]
            int_value_be = int.from_bytes(firstReg, byteorder='little')
            reg_list.append(int_value_be)
            lostReg = floatValueTobytes[2:4]
            int_value_be = int.from_bytes(lostReg, byteorder='little')
            reg_list.append(int_value_be)

        empty_tuple = tuple(reg_list)
        out1 = server.get_slave(1).set_values("1", 0, (0x6720,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
        out2 = server.get_slave(1).set_values("2", 0, empty_tuple)
        out3 = server.get_slave(1).set_values("3", wrRegAddr, empty_tuple)
        out4 = server.get_slave(1).set_values("4", wrRegAddr, empty_tuple)

        count = 0
        old_addstr = ""
        addstr = ""
        while True:
            time.sleep(0.1)
            countSeck=countSeck+1;
            cmdForModBus = 'set_values 1 3 0 '+str(countSeck)+' '+revForPO+' 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25'
            cmdForModBus = "" 
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
                    reg_list = []
                    int_byte_array = countSeck.to_bytes(4, byteorder='little')
                    reg_list.append(int_byte_array[0])
                    reg_list.append(int_byte_array[1])
                    reg_list.append(int_byte_array[2])
                    reg_list.append(int_byte_array[3])
                    server.get_slave(1).set_values("1", 0, tuple(reg_list))
                    server.get_slave(1).set_values("2", 0, tuple(reg_list))
                    server.get_slave(1).set_values("3", wrRegAddr, tuple(reg_list))
                    server.get_slave(1).set_values("4", wrRegAddr, tuple(reg_list))
                    #вернуть значения n элементов по указанному адресу указанного блока
                    tmr = time.strftime('%H:%M:%S') #Изменение надписи метки
                    values1 = server.get_slave(1).get_values('1', 0, 25)
                    values2 = server.get_slave(1).get_values('2', 0, 25)
                    #### чтение значений регистров
                    values3 = server.get_slave(1).get_values('3', wrRegAddr, 0x60*2)

                    chunk_size = 2
                    result = [values3[i:i + chunk_size] for i in range(0, len(values3), chunk_size)]
                    #print(result)
                    reg_list_read = []
                    nomer = 0;
                    for my_tuple in result:
                        nomer=nomer+2
                        if (nomer < (17*2)):
                            b1 = my_tuple[0].to_bytes(2, 'little')
                            b2 = my_tuple[1].to_bytes(2, 'little')
                            byte_data_int = b1 + b2
                            int_value = int.from_bytes(byte_data_int, byteorder='little', signed=False) #little #big
                            reg_list_read.append(int_value)
                        else:
                            b1 = my_tuple[0].to_bytes(2, 'little')
                            b2 = my_tuple[1].to_bytes(2, 'little')
                            byte_data_float = b1 + b2
                            float_value = struct.unpack('f', byte_data_float)[0]
                            reg_list_read.append(float_value)

                    ############################################################
                    values4 = server.get_slave(1).get_values('4', wrRegAddr, 0x60*2)

                    chunk_size = 2
                    result = [values4[i:i + chunk_size] for i in range(0, len(values4), chunk_size)]
                    #print(result)
                    reg_list_write = []
                    nomer = 0;
                    for my_tuple in result:
                        nomer=nomer+2
                        if (nomer < (17*2)):
                            b1 = my_tuple[0].to_bytes(2, 'little')
                            b2 = my_tuple[1].to_bytes(2, 'little')
                            byte_data_int = b1 + b2
                            int_value = int.from_bytes(byte_data_int, byteorder='little', signed=False) #little #big
                            reg_list_write.append(int_value)
                        else:
                            b1 = my_tuple[0].to_bytes(2, 'little')
                            b2 = my_tuple[1].to_bytes(2, 'little')
                            byte_data_float = b1 + b2
                            float_value = struct.unpack('f', byte_data_float)[0]
                            reg_list_write.append(float_value)

                    ############################################################
                    string_values3 = "";
                    for reg in reg_list_read:
                        string_values3 = string_values3+" "+ str(reg);

                    string_values4 = "";
                    for reg in reg_list_read:
                        string_values4 = string_values4+" "+ str(reg);

                    input_text_tag_str_buf = "\n" + "\n" + tmr+" get_values_1 " + str(values1) + "\n" + tmr+" get_values_2 " + str(
                        values2) + "\n" + tmr+" get_values_3 " + string_values3 + "\n" + tmr+" get_values_4 " + string_values4 + input_text_tag_str_buf
                    dpg.set_value(input_text_tag, input_text_tag_str_buf)  # Изменение значения\

                    tmr = ':'
                    addstr = "\n" + "\n" + tmr+" get_values_1 " + str(values1) + "\n" + tmr+" get_values_2 " + str(
                        values2) + "\n" + tmr+" get_values_3 " + str(values3) + "\n" + tmr+" get_values_4 " + str(
                        values4)

                    if (addstr != old_addstr):
                        count=count+1
                        # file = open("otusKey_maserModBas.txt", "a+")
                        # file.write(input_text_tag_str_buf+'\n');
                        # file.close();
                        old_addstr = addstr
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
    with dpg.font(f'C:\\\\Windows\\\\Fonts\\\\arialbi.ttf', 12, default_font=True, tag="Default font") as f:
        dpg.add_font_range_hint(dpg.mvFontRangeHint_Cyrillic)

dpg.bind_font("Default font")

with dpg.window(label="Data log.", width=1000, height=500, pos=[0, 300]):
    input_text_tag = dpg.add_input_text(
        hint="Some description",
        multiline=True,
        width=1000, height=500,
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
