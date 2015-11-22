# Server to implement simplified RSA algorithm. 
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted 
# with the session key. 

# Author: fokumdt 2015-11-02

#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES

def expMod(b,n,m):
    """Computes the modular exponent of a number"""
    """returns (b^n mod m)"""
    if n==0:
        return 1
    elif n%2==0:
        return expMod((b*b)%m, n/2, m)
    else:
        return(b*expMod(b,n-1,m))%m

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    # Fill in the code to do RSA encryption..............
    c = expMod(m, e, n)
    return c

def RSAdecrypt(c, d, n):
    """Decryption side of RSA"""
    # Fill in the code to do RSA decryption....................
    c = expMod(c, d, n)
    return c

def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""
    while v:
        u, v = v, u % v
    return abs(u)

def ext_Euclid(m,n):
    """Extended Euclidean algorithm"""
    # Provide the rest of the code to use the extended Euclidean algorithm
    # Refer to the project specification........................
    a1, a2, a3 = 1, 0, m
    b1, b2, b3 = 0, 1, n
    while (True):
        if b3 == 0:    return a3
        if b3 == 1:    return b2
        q =  math.floor(a3/b3)
        t1, t2, t3 = a1 - q * b1, a2 - q * b2, a3 - q * b3
        a1, a2, a3 = b1, b2, b3
        b1, b2, b3 = t1, t2, t3


def generateNonce():
    """This method returns a 16-bit random integer derived from hashing the
        #current time. This is used to test for liveness"""
    hash = hashlib.sha1()
    hash.update(str(time.time()).encode('utf-8'))
    return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

def genKeys(p, q):
    """Generate n, phi(n), e, and d."""
    # Fill in code to generate the server's public and private keys.
    # Make sure to use the Extended Euclidean algorithm...............................
    n = p * q
    phi = (p-1)*(q-1)
    #e = e_finder(n, phi)
    while True:
        e = random.randint(1, phi)
        if gcd_iter(e, phi) == 1:
            break
    d = ext_Euclid(phi, e)
    if d <0:
        d+=phi
    return  n, e, d

def d_finder(e,ph):
    d = 1
    while (True):
        if (d*e)%ph == 1:
            return d
        else:
            d+=1

def e_finder(n,phi):
    e = 1
    while True:
        if ( gcd_iter(e, phi) == 1):
            return e
        else:
            e = e +1

def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    status = "105 Hello "+ str(n) + " " + str(e)
    return status

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    status = "113 Nonce "+ str(nonce)
    return status

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
    from the client."""
    #Enter code to compare the nonce and the decryptedNonce. This method
    # should return a string of "200 OK" if the parameters match otherwise
    # it should return "400 Error Detected"
    if nonce == decryptedNonce:
        return "200 OK"
    else:
        return "400 Error Detected"

HOST = 'localhost'                 # Symbolic name meaning all available interfaces
PORT = 9011         # Arbitrary non-privileged port
strHello = "100 Hello"
strHelloResp = "105 Hello"
strSessionKey = "112 SessionKey"
strSessionKeyResp = "113 Nonce"
strNonceResp = "130"
strServerStatus = ""
print ("Enter prime numbers. One should be between 907 and 1013, and the other\
     between 53 and 67")
p = int(input('Enter P : '))
q = int(input('Enter Q: '))
# You should delete the next three lines. They are included so your program can
# run to completion
#n = 67871
#e = 5
#d= 26717
n, e, d = genKeys(p, q)
print("n: " + str(n))
print("e: " + str(e))
print("d: " + str(d))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# The next line is included to allow for quicker reuse of a socket.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', PORT))
s.listen(1)


conn, addr = s.accept()
data = conn.recv(1024).decode('utf-8')
print (data)
if data and data.find(strHello) >= 0:   
    msg = clientHelloResp(n, e)
    conn.sendall(bytes(msg, 'utf-8'))
    data = conn.recv(1024).decode('utf-8')
    print (data)
    if data and data.find(strSessionKey) >= 0:
        # Add code to parse the received string and extract the symmetric key
        key=  int( data.split(" ")[-1] )
        SymmKey = RSAdecrypt(key, d, n)# Make appropriate function call to decrypt the symmetric key
        # The next line generates the round keys for simplified AES
        simplified_AES.keyExp(SymmKey)
        challenge = generateNonce()
        print("Nonce: " + str(challenge))
        msg = SessionKeyResp( RSAencrypt(challenge, d, n) )
        conn.sendall(bytes(msg,'utf-8'))
        data = conn.recv(1024).decode('utf-8')
        print (data)
        if data and data.find(strNonceResp) >= 0:
            # Add code to parse the received string and extract the nonce
            encryptedChallenge = data.split(" ")[-1]
            # The next line runs AES decryption to retrieve the key.
            decryptedChallenge = simplified_AES.decrypt(int(encryptedChallenge))
            msg = nonceVerification(challenge, decryptedChallenge)
            # Make function call to compare the nonce sent with that received       
            conn.sendall(bytes(msg,'utf-8'))
conn.close()
