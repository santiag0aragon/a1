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
from datetime import datetime

import numpy as np
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
import pandas
from collections import Counter
from time import sleep


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


def generate_not_random_key_iv():
    N = 5
    key_size = 16
    iterations = 1
    key = b'J6EXO'
    salt = b'??K7|3˾?PP?x?'
    iv = b'a'*16
    derived_key = PBKDF2(key, salt, key_size, iterations)

    return derived_key, iv


def generate_key_iv():
    N = 5
    key_size = 16  # AES128
    iterations = 1000
    key = b''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))
    salt = Random.new().read(key_size)

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
    p_msg = add_padding(message)
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

def message_num():
    log = parseClientLog()
    times = list()

    if log is not None and log != '':
        for entry in log.split('\n'):
            if entry != '':
                times.append(parse_entry(entry)['date'].strftime('%H:%M:%S'))
    return len(times)


def cache_num():
    log = parseCacheLog()
    times = list()

    if log is not None and log != '':
        for entry in log.split('\n'):
            if entry != '':
                times.append(parse_entry(entry)['date'].strftime('%H:%M:%S'))
    return len(times)


def parseClientLog():
    log_add = 'http://pets.ewi.utwente.nl:59973/log/clients'
    try:
        log = urllib2.urlopen(log_add).read()
        if log == '':
            print 'Empty log...'
            pass
        return log
    except Exception, e:
        print 'No log found '
        return ''


def parseCacheLog():
    log_add = 'http://pets.ewi.utwente.nl:59973/log/cache'
    try:
        log = urllib2.urlopen(log_add).read()
        if log == '':
            print 'Empty log...'
            pass
        return log
    except Exception, e:
        print 'No log found '
        return None


def start(mix_num):
    stop()
    log_add = 'http://pets.ewi.utwente.nl:59973/cmd/mix%s' % mix_num
    urllib2.urlopen(log_add)
    print 'Mixer %s started...' % mix_num


def stop():
    log_add = 'http://pets.ewi.utwente.nl:59973/cmd/reset'
    urllib2.urlopen(log_add)
    sleep(2)
    print 'Mixer stoped'


def parse_entry(entry):
    e =  entry.split(' ')
    date = datetime.strptime(e[0],"%Y-%m-%dT%H:%M:%S.%f")
    participant = e[2]
    message = e[3]
    return {'date': date, 'participant': participant, 'message': message}


def second_freq(log):
    times = list()
    if log is not None and log != '':
        for entry in log.split('\n'):
            if entry != '':
                times.append(parse_entry(entry)['date'].strftime('%H:%M:%S'))

        counts = Counter(times)
        df = pandas.DataFrame.from_dict(counts, orient='index')
        df =  df.sort_index()
        df.plot(kind='bar')
        plt.xlabel('Time')
        plt.ylabel('Frequency')
        plt.axis([0, len(counts)+1, 0, max(counts.values())+1])
        plt.grid(True)
        plt.show()


def send_message(recipient, message):
    message = '%s\t%s' % (recipient, message)
    HOST = 'pets.ewi.utwente.nl'
    PORT = 51666
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((HOST, PORT))
    e4 = pack_message(message)
    send_one_message(clientsocket, e4)


def check_for_tim():
    log = parseCacheLog()
    if log is not None and log != '':
        for entry in log.split('\n'):
            if entry != '':
                e = parse_entry(entry)
                if e['participant'] == 'Tim':
                    return True
    return False

def one_a():
    start(1)
    # sleep(3)
    send_message('OWAIS','That is not secret message')
    sleep(10)
    stop()

def one_b():
    start(1)
    send_message('TIM     ','s1750542  a1736574')
    sleep(10)
    stop()

def one_c():
    start(1)
    for x in range(120):
        send_message('ME ', 'message #%s'% ( x))
        print 'injecting message #%s\r' % ( x),
    second_freq(parseCacheLog())
    stop()

def first_client():
    log = parseClientLog()
    e = parse_entry(log.split('\n')[0])['participant']
    # print parse_entry(log.split('\n')[0])
    return e



def not_me():
    log = parseCacheLog()
    if log is not None and log != '':
        for entry in log.split('\n'):
            if entry != '':
                e = parse_entry(entry)
                if e['participant'] != 'ME':
                    return e['participant']

def n_1_a():
    start(3)
    sleep(.05)
    send_message('ME ', '-'*7)
    send_message('ME ', '-'*7)
    send_message('ME ', '-'*7)
    send_message('ME ', '-'*7)
    send_message('ME ', '-'*7)
    send_message('ME ', '-'*7)
    send_message('ME ', '-'*7)
    log = parseClientLog()
    if log == '':
        message_sent = 7
        while cache_num() < 6:
            pass
        stop()
        sleep(2)
        if not check_for_tim() and not_me() is not  None:
            rec = not_me()
            sen = first_client()
            print '%s is communicating with %s' %(sen, rec)
            n_1_a()
        elif not_me() is  None:
            n_1_a()
        else:
            rec = not_me()
            sen = first_client()
            print '%s is communicating with %s' %(sen,rec)
    else:
        n_1_a()



n_1_a()
