import socket
import struct
# HOST = '193.168.8.2'
HOST = 'pets.ewi.utwente.nl'
PORT = 51666
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect((HOST, PORT))


def recv_one_message(sock):
    lengthbuf = recvall(sock, 4)
    length, = struct.unpack('!I', lengthbuf)
    return recvall(sock, length)

def recvall(sock, count):
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf

def send_one_message(sock, data):
    length = len(data)
    sock.sendall(struct.pack('!I', length))
    sock.sendall(data)


# clientsocket.sendall(email)
send_one_message(clientsocket, email)
while True:
        buf = recv_one_message(clientsocket)
        # data = clientsocket.recv(4096)
        if len(buf) > 0:
            print "Received response:\n" + str(buf)
            break


