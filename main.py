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

# in_fname  plainText에 해당하는 파일의 경로

# cipherText를 생성하는 함수이지만 테스트를 위해서 복호화까지 진행하는 코드를 적음.
def makeEncryptFile(in_fname):
    # 현재 시간을 이용하여 비밀번호 생성
    password = make_password()
    password = password.encode('utf-8')

    # SHA256을 이용해서 key값 생성
    key = hashlib.sha256(password).digest()

    # key를 이용한 AES256암호화를 수행해서 output 파일을 만듦.
    # 파일을 사실 만들 필요는 없음. 메모리에 올리기만 하면 될 것으로 판단됨.
    result = encrypt_file(key, in_fname, out_filename='output')

    # 지금은 테스트 중이니까 decrypt한 파일도 만들어서 확인
    recvFileName = 'rec_' + in_fname
    decrypt_file(key, in_filename='output', out_filename= recvFileName)

    # 반환값은 키값과 output 데이터
    return key, result


# key           복호화에 이용할 키
# in_filename   cipherText에 해당하는 파일의 경로
# out_filename  plainText에 해당하는 파일의 경로
# chunkSize     복호화할 때 필요한 chunk Size

# plainText를 생성하는 함수
def decrypt_file(key, in_filename, out_filename, chunksize=24 * 1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        # 이 부분은 잘 모르겠으나.. 처음에 이니셜벡터와 같이 cipherText 맨 앞에 추가된 값을 읽어들임.
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)

        # 복호화는 CBC모드.
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        # chunkSize를 기준으로 파일을 읽어들이고 복호화함.
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)

# key           암호화에 이용할 키
# in_filename   plainText에 해당하는 파일의 경로
# out_filename  cipherText에 해당하는 파일의 경로
# chunkSize     암호화할 때 필요한 chunk Size

# cipherText를 생성하는 함수
def encrypt_file(key, in_filename, out_filename=None, chunksize=65536):
    # result는 output파일에 대한 값을 메모리에 적재하기 위해 선언한 배열
    result = []

    if not out_filename:
        out_filename = in_filename + '.enc'

    # 암호화에 필요한 값들 초기화
    iv = Random.new().read( AES.block_size )
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    print('original iv: %s' % iv )
    print('original struct: %s\n' % struct.pack('<Q', filesize))

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            # 이 파트에서 write를 안 해도 되는데 일단 확인을 위해서 지우지 않았음.
            # 차후에 속도개선용으로 사용가능.

            outfile.write(struct.pack('<Q', filesize))
            result.append(struct.pack('<Q', filesize))

            outfile.write(iv)
            result.append(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    # 길이가 16bit가 아니면 padding
                    length = 16 - (len(chunk) % 16)
                    chunk += bytes([length]) * length

                result.append(encryptor.encrypt(chunk))
                outfile.write(encryptor.encrypt(chunk))
    return result

# 현재 시간에 따른 key seed를 정하는 함수
def make_password():
    timekey = int(time.time())
    return str(timekey)

# Key Sharing Functions

# byteArray형태인 key값을 string으로 바꿔주는 함수
def makeKeyToAscii(key):
    return binascii.hexlify(bytearray(key)).decode('utf-8')

# string형태인 key값을 byteArray형식으로 바꿔주는 함수
def makeKeyFromAscii(stringKey):
    return binascii.a2b_hex(stringKey)

# key값을 n of k 만큼의 sharingKey들로 만들어주는 함수
def getSharingKey(key, n ,k):
    return SecretSharer.split_secret(key, k, n)

# shares[] = sharingKey들의 배열
# shares[]들을 이용하여 key값을 복원하는 함수
def recoverSharingKey(shares):
    return makeKeyFromAscii(SecretSharer.recover_secret(shares))

# Steganograpy Functions

# bytesData 형태의 data를 img에 bit단위로 넣어주는 함수
def insertDataIntoImage(img, bytesData ,length, x, y, channel):
    mask = 0xFE
    curr_x = x
    curr_y = y
    pc = channel

    height, width ,c = img.shape

    count = 0
    for elements in bytesData:
        for value in elements:
            for i in range(0,8):
                index = 0 if (value & (1 << (7-i))) == 0 else 1

                img.itemset((curr_y,curr_x,pc), img.item(curr_y, curr_x, pc) & mask | index)

                pc += 1
                if pc >= c:
                    pc = 0
                    curr_x += 1
                    if curr_x >= width:
                        curr_x = 0
                        curr_y += 1
                        if curr_y >= height:
                            return 0,0,0 # error

                count += 1

    print('Insert Data Assertion %r' % (count == length))
                
    return curr_x, curr_y, pc

# x,y,channel 값을 기준으로 length 길이만큼의 data를 bytesData 형태의 값으로 반환하는 함수.
def getDataFromImage(img, length, x, y, channel):
    curr_x = x
    curr_y = y
    pc = channel

    retrieveData = 0
    data = []

    height, width ,c = img.shape

    count = 0
    for i in range(length):
        bit = img.item(curr_y, curr_x, pc) & 1

        pc += 1
        if pc >= c:
            pc = 0
            curr_x += 1
            if curr_x >= width:
                curr_x = 0
                curr_y += 1
                if curr_y >= height:
                    return 0,0,0 # error

        count += 1
        retrieveData = retrieveData << 1
        retrieveData += bit

        if count == 8:
            data.append(retrieveData)
            retrieveData = 0
            count = 0
                
    return bytes(data), curr_x, curr_y, pc     

# 각 데이터의 길이 값을 넣어주는 함수
# 각 길이는 2^31까지 가능 (32bit)
def insertLengthIntoImage(img, length, x, y, channel):
    index = 1 << 31
    mask = 0xFE
    curr_x = x
    curr_y = y
    pc = channel

    height, width ,c = img.shape

    ## first 32bit for outputlength
    for i in range(0,32):
        bit = 0 if (length & index) == 0 else 1
        img.itemset((curr_y, curr_x, pc), img.item(curr_y, curr_x, pc) & mask | bit)

        pc += 1
        if pc >= c:
            pc = 0
            curr_x += 1
            if curr_x >= width:
                curr_x = 0
                curr_y += 1
                if curr_y >= height:
                    return 0,0,0 # error

        index = index >> 1
    return curr_x, curr_y, pc

# 각 데이터의 길이 값을 받아오는 함수
def getLengthFromImage(img, x, y, channel):

    retrieveValue = 0
    height, width ,c = img.shape

    curr_x = x
    curr_y = y
    pc = channel

    for i in range(0,32):
        value = img.item(curr_y,curr_x,pc) & 1
    
        pc += 1
        if pc >= c:
            pc = 0
            curr_x += 1
            if curr_x >= width:
                curr_x = 0
                curr_y += 1
                if curr_y >= height:
                    return 0,0,0 # error
        
        retrieveValue = retrieveValue << 1
        retrieveValue += value

    return retrieveValue, curr_x, curr_y, pc

# 각 data의 bit수를 세주는 함수
def countBitLength(share, output):
    shareLength = 0    

    structSize = len(output[0]) * 8
    ivSize = len(output[1]) * 8
    dataSize = len(output[2]) * 8

    for value in share:
        shareLength += len(value) * 8

    return shareLength, structSize, ivSize, dataSize

# fname     스테가노그래피에 이용할 원본 이미지의 경로
# shares    여기서는 1개의 sharingKey만 쓰게 했으나 고치게 될 것으로 보임
# output    cipherText에 해당하는 값
def hideInformation(fname, shares, output):
    shareLength, structSize, ivSize, dataSize = countBitLength(shares[0], output)

    outputLength = structSize + ivSize + dataSize   

    print('original outputLength : %d' % outputLength)
    print('original shareLength : %d\n' % shareLength)
    
    img = cv2.imread(fname)

    x,y,c = insertLengthIntoImage(img, outputLength, 0,0,0)         # insert outputLength
    x,y,c = insertLengthIntoImage(img, shareLength, x,y,c)          # insert shareLength
    x,y,c = insertDataIntoImage(img, output, outputLength, x,y,c)   # write outputdata
    
    shareArr = []
    shareArr.append(shares[0].encode())
    x,y,c = insertDataIntoImage(img, shareArr, shareLength, x,y,c) # write keySharing Data

    print('')

    outputSize, x,y,c = getLengthFromImage(img, 0,0,0)
    shareSize, x,y,c = getLengthFromImage(img, x,y,c)

    print('retrieved outputLength : %d' % outputSize)
    print('retrieved shareLength : %d\n' % shareSize)

    structValue,x,y,c = getDataFromImage(img, structSize, x,y,c)
    ivValue,x,y,c = getDataFromImage(img, ivSize, x,y,c)

    print('retrieved ivValue : %s' % ivValue)
    print('retrieved StructValue : %s\n' % structValue)
    
    dataValue,x,y,c = getDataFromImage(img, dataSize, x,y,c)

    #print('retrieved Data : %s\n' % dataValue)

    return 0

if __name__ == '__main__':  

    """FILE ENCRYPTION"""
    """secret.txt를 암호화 key를 생성해서 암호화 한 뒤 key, output으로 반환"""
    key, output = makeEncryptFile('secret.txt')
    
    """KEY SHARING"""
    """그냥 key값은 keySharing Library에서 쓸 수 없으므로 string형식으로 바꿔준다"""
    tempkey = makeKeyToAscii(key)

    N = 3
    K = 2

    """바꾼 key값을 이용하여 N of K 의 keySharing을 수행한다."""
    shares = getSharingKey(tempkey, N, K)

    print('sharing key', end=' ')
    print(shares)

    """sharing 복호화? 의 경우에서 코드"""
    recoverdKey = recoverSharingKey(shares[1:4])
    print('original key : %s' % key)
    print("recovered key: %s\n" % recoverdKey)

    """HIDING INFORMATION"""
    hideInformation("sample.jpg", shares, output)

