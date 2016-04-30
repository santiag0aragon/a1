# -*- coding: utf-8 -*-
import urllib2
import socket
import struct
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import random
import string


def pack_message(message):
    key_cache = 'keys/public_key_Cache.pem'
    key_c = 'keys/public_key_C.pem'
    key_b = 'keys/public_key_B.pem'
    key_a = 'keys/public_key_A.pem'
    e1 = create_message(key_cache, message)
    e2 = create_message(key_c, e1)
    e3 = create_message(key_b, e2)
    e4 = create_message(key_a, e3)

    return e4
#  Cache encyption
def create_message(key_path, message):
    key_rsa = open(key_path, 'rb').read()
    k_aes, iv = generate_key_iv()
    msg = '%s%s' % (k_aes, iv)
    e1_rsa = rsa_encrypt(key_rsa, msg)
    e1_aes = aes_encrypt(k_aes, iv, message)
    e1 = '%s%s' % (e1_rsa, e1_aes)
    return e1


def generate_key_iv():
    N = 5
    key_size = 16  # AES128
    iterations = 10000
    key = b''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))
    salt = Random.new().read(key_size)  # salt the hash
    iv = Random.new().read(AES.block_size)
    derived_key = PBKDF2(key, salt, key_size, iterations)

    return derived_key, iv


def rsa_encrypt(key, message):
    keyPub = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(keyPub)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def aes_encrypt(key, iv, message):
    # key_size = 32 #AES256
    # iterations = 10000
    # key = b'password'
    BS = 16
    add_padding = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    print len(message)
    p_msg = add_padding(message)
    print len(p_msg)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(p_msg)


def recv_one_message(sock):
    lengthbuf = recvall(sock, 4)
    length, = struct.unpack('!I', lengthbuf)
    return recvall(sock, length)


def recvall(sock, count):
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf:
            return None
        buf += newbuf
        count -= len(newbuf)
    return buf


def send_one_message(sock, data):
    length = len(data)
    sock.sendall(struct.pack('!I', length))
    sock.sendall(data)


def parseLog():
    log_add = 'http://pets.ewi.utwente.nl:59973/log/clients'
    return urllib2.urlopen(log_add).read()


def connect():
    HOST = 'pets.ewi.utwente.nl'
    PORT = 51666
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((HOST, PORT))
    send_one_message(clientsocket, 'email')
    while True:
            buf = recv_one_message(clientsocket)
            # data = clientsocket.recv(4096)
            if len(buf) > 0:
                print "Received response:\n" + str(buf)
                break

# print parseLog()
# print create_message()
# print generate_key_iv()
message ='''
es simplemente el texto de relleno de las imprentas y archivos de texto. Lorem Ipsum ha sido el texto de relleno estándar de las industrias desde el año 1500, cuando un impresor (N. del T. persona que se dedica a la imprenta) desconocido usó una galería de textos y los mezcló de tal manera que logró hacer un libro de textos especimen. No sólo sobrevivió 500 años, sino que tambien ingresó como texto de relleno en documentos electrónicos, quedando esencialmente igual al original. Fue popularizado en los 60s con la creación de las hojas "Letraset", las cuales contenian pasajes de Lorem Ipsum, y más recientemente con software de autoedición, como por ejemplo Aldus PageMaker, el cual incluye versiones de Lorem Ipsum.
'''
k_aes, iv = generate_key_iv()
e1_aes = aes_encrypt(k_aes, iv, message)

