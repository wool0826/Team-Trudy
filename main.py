# Dependency

# Install OpenCV
# python -m pip install opencv-python

# Install PyCrypto
# python -m pip install pycryptodome

# Install secretSharing
# python -m pip install secretsharing

# Install utilitybelt
# python -m pip install utilitybelt

## For Python 3.X User
## link: https://github.com/blockstack/secret-sharing
## Remove all files in C:\Program Files (x86)\Python37-32\Lib\site-packages\secretsharing
## Clone git and Copy ( __init.py__, polynomials.py, primes.py, sharing.py ) 
## to C:\Program Files (x86)\Python37-32\Lib\site-packages\secretsharing

import struct, hashlib, time, binascii, os, cv2
import numpy as np

from secretsharing import SecretSharer
from Crypto.Cipher import AES
from Crypto import Random

# Crypto Functions
def makeEncryptFile(in_fname):
    password = make_password()
    password = password.encode('utf-8')

    key = hashlib.sha256(password).digest()

    encrypt_file(key, in_fname, out_filename='output')

    #delete original file

    #decrypt
    recvFileName = 'rec_' + in_fname
    decrypt_file(key, in_filename='output', out_filename= recvFileName)

    return key
def decrypt_file(key, in_filename, out_filename, chunksize=24 * 1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
def encrypt_file(key, in_filename, out_filename=None, chunksize=65536):
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = Random.new().read( AES.block_size )
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    length = 16 - (len(chunk) % 16)
                    chunk += bytes([length]) * length

                outfile.write(encryptor.encrypt(chunk))
def make_password():
    timekey = int(time.time())
    return str(timekey)

# Key Sharing Functions
def makeKeyToAscii(key):
    return binascii.hexlify(bytearray(key)).decode('utf-8')
def makeKeyFromAscii(stringKey):
    return binascii.a2b_hex(stringKey)
def getSharingKey(key, n ,k):
    return SecretSharer.split_secret(key, k, n)
def recoverSharingKey(shares):
    return makeKeyFromAscii(SecretSharer.recover_secret(shares))

# Steganograpy Functions
def hideInformation(fname, shares):
    return 0

if __name__ == '__main__':  

    """FILE ENCRYPTION"""
    key = makeEncryptFile('secret.txt')
    
    """KEY SHARING"""
    tempkey = makeKeyToAscii(key)

    N = 3
    K = 2

    shares = getSharingKey(tempkey, N, K)
    recoverdKey = recoverSharingKey(shares[1:4])

    print("key: %s" % key)
    print(shares)    
    print("key: %s" % recoverdKey)

    """HIDING INFORMATION"""
    #hideInformation("sample.jpg", shares)



