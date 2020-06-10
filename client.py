#!/usr/bin/env python3
# coding: utf-8

import socket
import pyDHE
import hashlib
from Crypto import Random
from Crypto.Util.number import long_to_bytes
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES

class Client():    

    def __init__(self, pseudo,challengeSalt):
        self.pseudo = pseudo
        self.challengeSalt = challengeSalt

    def connect(self, hote, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((hote, port))
            print("Connected")
        except:
            print("Error : Can't connect to server")

    def negotiate(self):
        self.dh = pyDHE.new(14)
        self.sock.send(long_to_bytes(self.dh.getPublicKey()))
        data = self.sock.recv(1024)
        self.dh.update(bytes_to_long(data))
        fullKey = self.dh.getFinalKey()
        self.key = hashlib.sha256((str(fullKey)).encode()).hexdigest()[:32]
        return self.dh.getFinalKey()

    def init(self):
        self.sendMessage(self.pseudo)

    def sendMessage(self,message):
        cipher = AES.new(self.key.encode(), AES.MODE_GCM,self.nounce)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        self.sock.send(ciphertext)
    
    def sendUnsecureMessage(self,message):
        self.sock.send(message.encode())
    
    def disconnect(self):
        self.sock.close()
        print("Disconnected")

    def setNounce(self,nounce):
        self.nounce = nounce

    def challenge(self, password, randomString):
        temp = hashlib.sha256((password + self.challengeSalt).encode()).hexdigest()
        return hashlib.sha256((randomString.decode() + str(temp) ).encode()).hexdigest()



if __name__ == "__main__":
    client = Client("admin","ERGH7U2S")

    client.connect("localhost",1235)
    # Key exchange
    print("Negotiating key")
    DH_key = client.negotiate()

    # Receive the nounce
    data = client.sock.recv(1024)
    client.setNounce(data)
    print("Nounce received !")

    client.init()
    
    # Asking password
    data = client.sock.recv(1024)
    print(data.decode() + '\n')
    password = input()
    client.sendMessage(password)

    # Challenge
    print("Challenge started !")
    randomString = client.sock.recv(1024) # Receive the random string
    client.sendUnsecureMessage(client.challenge(password, randomString))
    print("Challenge passed !")

    # MOTD
    data = client.sock.recv(1024)
    print("MOTD :  " + data.decode() + '\n')

    while True:
        message = input()
        client.sendMessage(message)
        data = client.sock.recv(1024)
        cipher = AES.new(client.key.encode(), AES.MODE_GCM,client.nounce)
        message = cipher.decrypt(data)
        print("Message recu : " + message.decode() + '\n')
        

    client.disconnect()