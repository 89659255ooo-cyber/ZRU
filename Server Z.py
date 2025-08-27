import socket
from datetime import datetime

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

host = '127.0.0.1'  # Или 'localhost'
port = 11719
print(f"Запускаю сервер на {host}:{port}")
while True:
    b_mess = bytearray([8, 2, 0, 0, 111, 99])  # Команда на чтение данных из платы
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET для IPv4, SOCK_STREAM для TCP
    server_socket.bind((host, port))
    server_socket.listen(1) # Начинаем слушать входящие соединения (1 - максимальное количество подключений в очереди)
    print(f"Сервер слушает на {host}:{port}")
    client_socket, address = server_socket.accept()
    print(f"Подключен клиент с адресом {address}")
    while True:
            data = client_socket.recv(1024).decode() # Получаем данные от клиента (1024 байта)
            if not data:
                break # Если данных нет, клиент отключился
            print(f"Получено от клиента: {data}")
            Tim = datetime.utcnow().strftime('%H:%M:%S.%f')
            print(Tim + ":" + AreeyBinToStrHex(data.encode()))
            #client_socket.send("Сообщение получено!".encode()) # Отправляем ответ
            client_socket.send(b_mess) # Отправляем ответ
            
    client_socket.close()
    server_socket.close()
    print(f"  ")
