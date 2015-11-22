# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Finally,
# the server sends the client a message with a status code.
# Author: fokumdt 2015-10-18

#!/usr/bin/python3

import socket
import math
import random
import simplified_AES


def expMod(b,n,m):
    #"""Computes the modular exponent of a number returns (b^n mod m)"""
    if n==0:
        return 1
    elif n%2==0:
        return expMod((b*b)%m, n/2, m)
    else:
        return(b*expMod(b,n-1,m))%m

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    # Fill in the code to do RSA encryption.............
    c = expMod(m, e, n)
    return c

def RSAdecrypt(c, d, n):
    #"""Decryption side of RSA"""
    # Write code to RSA decryption..............    
    c = expMod(c, d, n)
    return c

def serverHello():
    #"""Sends server hello message"""
    status = "100 Hello"
    return status

def sendSessionKey(s):
    #"""Sends server session key"""
    status = "112 SessionKey " + str(s)
    return status

def sendTransformedNonce(xform):
    #"""Sends server nonce encrypted with session key"""
    status = "130 " + str(xform)
    return status

def computeSessionKey():
    #"""Computes this node's session key"""
    sessionKey = random.randint(1, 32768)
    return sessionKey
    
def main():
    """Driver function for the project"""
    serverHost = 'localhost'        # The remote host
    serverPort = 9011              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(serverHost, serverPort)
    s.connect((serverHost, serverPort))
    msg = serverHello()
    s.sendall(bytes(msg,'utf-8'))  # Sending bytes encoded in utf-8 format.
    data = s.recv(1024).decode('utf-8')
    print (data)
    strStatus = "105 Hello"
    if data and data.find(strStatus) < 0:
        print("Invalid data received. Closing")
    else:
        # Write appropriate code to parse received string and extract
        data = data.split(" ")[-2:]#converts string to an array to extract the last 2 words
        # the modulus and exponent for public key encryption.
        n =  int(data[0])# Modulus for public key encryption
        e =  int(data[1])# Exponent for public key encryption
        print("Server's public key: ("+ str(n)+","+str(e)+")")
        symmetricKey = computeSessionKey()
        encSymmKey = RSAencrypt(symmetricKey, e, n)#encrypt session key using private key
        msg = sendSessionKey(encSymmKey)
        s.sendall(bytes(msg,'utf-8'))
        data = s.recv(1024).decode('utf-8')
        print (data)
        strStatus = "113 Nonce"
        if data and data.find(strStatus) < 0:
            print("Invalid data received. Closing")
        else:
            # Write code to parse received string and extract encrypted nonce
            # from the server. The nonce has been encrypted with the server's
            # private key.
            encNonce = int(data.split(" ")[-1])#turns string to array to extract last part of string 
            print("Encrypted nonce: "+ str(encNonce))
            nonce = RSAdecrypt(encNonce, e, n) # decrypt message using public key
            print("Decrypted nonce: "+ str(nonce))
            """Setting up for Simplified AES encryption"""
            plaintext = nonce
            simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.
            ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
            msg = sendTransformedNonce(ciphertext)
            s.sendall(bytes(msg,'utf-8'))
            data = s.recv(1024).decode('utf-8')
            if data:
                print(data)
    s.close()

if __name__ == "__main__":
    main()
