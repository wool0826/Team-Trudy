# Dependency

# Install OpenCV
# python -m pip install opencv-python

# Install PyCrypto
# python -m pip install pycryptodome

# Install secretSharing
# python -m pip install secretsharing

# Install utilitybelt
# python -m pip install utilitybelt

# Install PyQt5
# python -m pip install PyQt5

## For Python 3.X User
## link: https://github.com/blockstack/secret-sharing
## Remove all files in C:\Program Files (x86)\Python37-32\Lib\site-packages\secretsharing
## Clone git and Copy ( __init.py__, polynomials.py, primes.py, sharing.py ) 
## to C:\Program Files (x86)\Python37-32\Lib\site-packages\secretsharing

import struct, hashlib, time, binascii, os, cv2, sys
import numpy as np

from secretsharing import SecretSharer
from Crypto.Cipher import AES
from Crypto import Random
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5 import uic
from PyQt5.QtCore import *

form_class = uic.loadUiType("Trudy 2019.ui")[0]



class MyWindow(QMainWindow, form_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.visible = True

        # 버튼 세팅
        self.edit_text_path.clicked.connect(self.edit_text_path_btn_clicked)
        self.edit_image_path.clicked.connect(self.edit_image_path_btn_clicked)
        self.crypto_button.clicked.connect(self.crypto_start)
        self.open_filefolder.clicked.connect(self.open_filefolder_btn_clicked)

        self.edit_folder_path.clicked.connect(self.edit_folder_path_btn_clicked)
        self.encrypto_button.clicked.connect(self.encrypto_start)

    def edit_text_path_btn_clicked(self):
        defaultPath = self.crypto_text_path.text()

        if(defaultPath is ''):
            fname = QFileDialog.getOpenFileName(self,"텍스트 파일을 선택해주세요." , filter =  "TextFile(*.txt)")
        else :
            fname = QFileDialog.getOpenFileName(self,"텍스트 파일을 선택해주세요.",defaultPath, "TextFile(*.txt)")

        if(fname[0] is not ''):
            self.crypto_text_path.setText(fname[0])

        try:
            if (fname[0] is ''):
                return
            file = open(fname[0])
            self.plaintext.setText(''.join(file.readlines()))
            self.statusbar.showMessage(" 텍스트 호출 완료.")
        except Exception:
            self.handle_error("텍스트 호출 과정에서 문제가 발생했습니다.")
            return


    def edit_image_path_btn_clicked(self):
        defaultPath = self.crypto_image_path.text()

        if (defaultPath is ''):
            fname = QFileDialog.getOpenFileName(self, "이미지를 선택해주세요." , filter =  "Images(*.png)")
        else:
            fname = QFileDialog.getOpenFileName(self, "이미지를 선택해주세요." , defaultPath, "Images(*.png)")


        try:
            if (fname[0] is ''):
                return


            width = 781
            height = 361

            self.image.clear()
            self.image = QLabel(self.image)
            self.image.setFixedSize(width, height)
            self.image.setAlignment(Qt.AlignCenter)

            pixmap = QPixmap(fname[0])
            pwidth = pixmap.width()
            pheight = pixmap.height()

            ratio = width / height
            pratio = pwidth / pheight

            if ratio < pratio:
                scaledPixmap = pixmap.scaled(width, width / pratio)
            else:
                scaledPixmap = pixmap.scaled(height*pratio, height)

            self.image.setPixmap(scaledPixmap)
            self.image.show()
            self.statusbar.showMessage(" 이미지 호출 완료.")
        except:
            self.handle_error('이미지를 불러올 수 없습니다.')
        if(fname[0] is not ''):
            self.crypto_image_path.setText(fname[0])


    # 폴더 패스 설정
    def edit_folder_path_btn_clicked(self):
        defaultPath = self.chiper_image_folder.text()

        if(defaultPath is ''):
            fname = QFileDialog.getExistingDirectory(self, "이미지 폴더를 선택해주세요." )
        else :
            fname = QFileDialog.getExistingDirectory(self, "이미지 폴더를 선택해주세요.", defaultPath)

        if(fname is not ''):
            self.chiper_image_folder.setText(fname)

        self.statusbar.showMessage(" 이미지 폴더 선택 완료.")

    def open_filefolder_btn_clicked(self):
        cwd = os.getcwd()
        os.startfile(cwd)

    def handle_error(self, error):
        QMessageBox.about(self, '치명적인 에러', error)


    def crypto_check(self):
        n = self.n.value()
        k = self.k.value()

        defaultFilePath = self.crypto_text_path.text()
        defaultImagePath = self.crypto_image_path.text()

        self.cypto_progressBar.setValue(10)

        msg = ''
        try:
            if n <= 0:
                msg = 'n은 0보다 큰 수여야 합니다.'
                raise Exception
            elif k <= 0:
                msg = 'k는 0보다 큰 수여야 합니다.'
                raise Exception
            elif n < k:
                msg = 'k는 n보다 클 수 없습니다.'
                raise Exception

            try:
                text = open(defaultFilePath)
                text.close()
            except FileNotFoundError:
                msg = 'Text 파일을 찾을 수 없습니다.'
                raise Exception

            if not defaultFilePath.endswith('.txt'):
                msg = ".txt 파일이 아닙니다."
                raise Exception

            try:
                text = open(defaultImagePath)
                text.close()
            except FileNotFoundError:
                msg = '이미지를 찾을 수 없습니다.'
                raise Exception

            if not defaultFilePath.endswith('.txt'):
                msg = ".png 파일이 아닙니다."
                raise Exception

        except Exception as error:
            self.handle_error(msg)
            return False, 0, 0, 0, 0

        self.cypto_progressBar.setValue(20)

        return True, n, k, defaultFilePath, defaultImagePath



    def crypto_start(self):

        self.cypto_progressBar.setValue(0)

        check, n, k, defaultFilePath, defaultImagePath = self.crypto_check()

        # 체크를 통과하지 못한경우 종료
        if not check:
            #여기 프로그래스 바 세팅
            self.statusbar.showMessage(" 설정 값 오류. ")
            self.cypto_progressBar.setValue(100)
            return

        try:
            self.cypto_progressBar.setValue(30)
            steganoGraphy(self, defaultFilePath, defaultImagePath, n, k)
            self.statusbar.showMessage(" 암호화 성공. ")
            self.cypto_progressBar.setValue(100)
        except Exception:
            self.handle_error("키쉐어링 암호화 과정에서 문제가 발생했습니다.")
            self.statusbar.showMessage(" 키쉐어링 암호화 과정에서 문제가 발생했습니다.")
            self.cypto_progressBar.setValue(100)
            return

    def encrypto_check(self):

        defaultFolderPath = self.chiper_image_folder.text()
        #에러 체크가 필요한 부분
        return True, defaultFolderPath


    def encrypto_start(self):

        self.encrypto_progress.setValue(0)


        check, folderpath = self.encrypto_check()

        self.encrypto_progress.setValue(20)

        # 체크를 통과하지 못한경우 종료
        if not check:
            #여기 프로그래스 바 세팅
            self.encrypto_progress.setValue(100)
            self.statusbar.showMessage(" 설정 값에 문제가 있습니다. ")
            return

        try:
            getInformation(self, folderpath)
        except Exception:
            self.handle_error("복호화 과정에서 문제가 발생했습니다.")
            self.statusbar.showMessage(" 복호화 과정에서 문제가 발생했습니다. ")
            self.encrypto_progress.setValue(100)
            return

        try:
            file = open("recovered_output0.txt")
            self.plain_text.setText(''.join(file.readlines()))
            self.statusbar.showMessage(" 복호화 성공. ")
            self.encrypto_progress.setValue(100)
        except Exception:
            self.handle_error("복호화 텍스트 호출 과정에서 문제가 발생했습니다.")
            self.statusbar.showMessage(" 복호화 텍스트 호출 과정에서 문제가 발생했습니다.")
            self.encrypto_progress.setValue(100)
            return


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

    # 반환값은 키값과 output 데이터
    return key, result


# key           복호화에 이용할 키
# in_filename   cipherText에 해당하는 파일의 경로
# out_filename  plainText에 해당하는 파일의 경로
# chunkSize     복호화할 때 필요한 chunk Size

# plainText를 생성하는 함수(내부에서만 작동가능하다..)
def decrypt_file(key, iv, in_filename, structLen, out_filename):
    # 복호화는 CBC모드.
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    result = decryptor.decrypt(in_filename)

    # 파일을 열어서 해독한 내용중 padding된 부분을 제외한 구조길이,structLen만큼만 slicing해서 넣어준다.
    with open(out_filename, 'wb') as outfile:
        outfile.write(result[:structLen])


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
    iv = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

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
                encryptedData = encryptor.encrypt(chunk)
                result.append(encryptedData)
                outfile.write(encryptedData)
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
def getSharingKey(key, n, k):
    return SecretSharer.split_secret(key, k, n)


# shares[] = sharingKey들의 배열
# shares[]들을 이용하여 key값을 복원하는 함수
def recoverSharingKey(shares):
    return makeKeyFromAscii(SecretSharer.recover_secret(shares))


# Steganograpy Functions

# bytesData 형태의 data를 img에 bit단위로 넣어주는 함수
def insertDataIntoImage(img, bytesData, length, x, y, channel):
    mask = 0xFE
    curr_x = x
    curr_y = y
    pc = channel

    height, width, c = img.shape

    count = 0
    for elements in bytesData:
        for value in elements:
            for i in range(0, 8):
                index = 0 if (value & (1 << (7 - i))) == 0 else 1

                img.itemset((curr_y, curr_x, pc), img.item(curr_y, curr_x, pc) & mask | index)

                pc += 1
                if pc >= c:
                    pc = 0
                    curr_x += 1
                    if curr_x >= width:
                        curr_x = 0
                        curr_y += 1
                        if curr_y >= height:
                            return 0, 0, 0  # error

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

    height, width, c = img.shape

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
                    return 0, 0, 0  # error

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

    height, width, c = img.shape

    ## first 32bit for outputlength
    for i in range(0, 32):
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
                    return 0, 0, 0  # error

        index = index >> 1
    return curr_x, curr_y, pc


# 각 데이터의 길이 값을 받아오는 함수
def getLengthFromImage(img, x, y, channel):
    retrieveValue = 0
    height, width, c = img.shape

    curr_x = x
    curr_y = y
    pc = channel

    for i in range(0, 32):
        value = img.item(curr_y, curr_x, pc) & 1

        pc += 1
        if pc >= c:
            pc = 0
            curr_x += 1
            if curr_x >= width:
                curr_x = 0
                curr_y += 1
                if curr_y >= height:
                    return 0, 0, 0  # error

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
def hideInformation(self, fname, shares, output, hmac, checksum):
    shareLength, structSize, ivSize, dataSize = countBitLength(shares[0], output)

    outputLength = structSize + ivSize + dataSize

    img = cv2.imread(fname, cv2.IMREAD_UNCHANGED)

    x, y, c = insertLengthIntoImage(img, outputLength, 0, 0, 0)  # insert outputLength 32bit

    self.cypto_progressBar.setValue(60)

    x, y, c = insertLengthIntoImage(img, shareLength, x, y, c)  # insert shareLength 32bit

    self.cypto_progressBar.setValue(70)

    px, py, pc = insertDataIntoImage(img, output, outputLength, x, y, c)  # write outputdata

    self.cypto_progressBar.setValue(80)

    for n, share in enumerate(shares):
        shareArr = []

        shareArr.append(share.encode())

        checkArr = []

        print(n, checksum[n])

        checkArr.append(checksum[n])

        hx, hy, hc = insertDataIntoImage(img, shareArr, shareLength, px, py, pc)  # write keySharing Data

        hx, hy, hc = insertDataIntoImage(img, hmac, 256, hx, hy, hc)

        insertDataIntoImage(img, checkArr, 256, hx, hy, hc)

        cv2.imwrite("./files/image" + str(n) + ".png", img)

    # MAC insert.

def findInformation(input_images):
    structSize = 64

    ivSize = 128

    shareList = []

    dataList = []

    structLenList = []

    ivValueList = []

    hmacList = []

    checkSumList = []

    for imagePath in input_images:
        img = cv2.imread(imagePath, cv2.IMREAD_UNCHANGED)

        outputSize, x, y, c = getLengthFromImage(img, 0, 0, 0)

        shareSize, x, y, c = getLengthFromImage(img, x, y, c)

        dataSize = outputSize - structSize - ivSize

        structValue, x, y, c = getDataFromImage(img, structSize, x, y, c)

        ivValue, x, y, c = getDataFromImage(img, ivSize, x, y, c)

        dataValue, x, y, c = getDataFromImage(img, dataSize, x, y, c)

        shareValue, x, y, c = getDataFromImage(img, shareSize, x, y, c)

        hmac, x, y, c = getDataFromImage(img, 256, x, y, c)

        checksum, x, y, c = getDataFromImage(img, 256, x, y, c)

        structLen = int.from_bytes(structValue, byteorder='little')

        dataList.append(dataValue)

        shareList.append(shareValue.decode("utf-8"))

        ivValueList.append(ivValue)

        hmacList.append(hmac)

        structLenList.append(structLen)

        checkSumList.append(checksum)

    # get MAC data

    return shareList, dataList, ivValueList, structLenList, hmacList, checkSumList


def steganoGraphy(self, input_file, input_image, n, k):
    key, output = makeEncryptFile(input_file)

    tempkey = makeKeyToAscii(key)

    shares = getSharingKey(tempkey, n, k)

    paddingShares = []

    checkSumShares = []

    for share in shares:

        if len(share[2:]) % 64 != 0:
            length = 64 - (len(share[2:]) % 64)

            share = share[0:2] + '0' * length + share[2:]

        paddingShares.append(share)

        inputData = share.encode() + output[2]

        checkSumShares.append(inputData)


    self.cypto_progressBar.setValue(40)

    if not os.path.exists("./files/"):
        os.mkdir("./files/")

    hmac = []

    key += output[2]

    hmac.append(hashlib.sha256(key).digest())  # length: 256

    checksum = []


    for element in checkSumShares:
        inputData = element + hmac[0]

        checksum.append(hashlib.sha256(inputData).digest())

    self.cypto_progressBar.setValue(50)

    hideInformation(self, input_image, paddingShares, output, hmac, checksum)

    self.cypto_progressBar.setValue(90)
    os.remove("output")


def getInformation(self, input_folder):

    images = []

    for files in os.listdir(input_folder):

        if files.endswith('.png'):
            images.append(os.path.join(input_folder, files))


    self.encrypto_progress.setValue(30)

    kkey, dataList, ivValueList, structLenList, hmacList, checksum = findInformation(images)

    self.encrypto_progress.setValue(40)
    removeList = []

    for n, elem in enumerate(checksum):

        temp = hashlib.sha256(kkey[n].encode() + dataList[n] + hmacList[n]).digest()

        # print(n, elem, temp)

        if elem == temp:

            print("%d CheckSum Assertion Success" % n)

        else:

            print("%d CheckSum Assertion Failed" % n)

            removeList.append(n)

    removeList.reverse()

    for i in removeList:
        del kkey[i]

        del dataList[i]

        del ivValueList[i]

        del structLenList[i]

        del hmacList[i]

        del checksum[i]

    recoverdKey = SecretSharer.recover_secret(kkey)

    self.encrypto_progress.setValue(50)

    if len(recoverdKey) % 64 != 0:
        length = 64 - (len(recoverdKey) % 64)

        recoverdKey = '0' * length + recoverdKey

    recoverdKey = makeKeyFromAscii(recoverdKey)

    self.encrypto_progress.setValue(60)

    for i in range(0, len(dataList)):

        recvFileName = 'recovered_output' + str(i) + '.txt'

        forHmacTest = recoverdKey + dataList[i]

        hashed = hashlib.sha256(forHmacTest).digest()

        if hmacList[i] == hashed:

            print("%d Assertion Success" % i)

        else:

            print("%d Assertion Failed" % i)

        self.encrypto_progress.setValue(80)

        decrypt_file(recoverdKey, ivValueList[i], dataList[i], structLenList[i], out_filename=recvFileName)

        self.encrypto_progress.setValue(90)

if __name__ == '__main__':
    # GUI 불러오기
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.show()
    myWindow.setFixedSize(800, 700)
    app.exec()