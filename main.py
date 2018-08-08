import codecs
from Crypto.Cipher import AES
from random import randint
from copy import copy

def hexTob64(s):
    return codecs.encode(codecs.decode(s, 'hex'), 'base64').decode()

def hamming(a, b):
    # bytearrays a, b
    # print(a, b)
    ans = 0
    for i in range(len(a)):
        xord = a[i]^b[i]
        for j in range(8):
            if xord & (1<<j):
                ans += 1
    return ans

# print(hamming("this is a test", "wokka wokka!!!"))

def readb64file(filename):
    with open(filename) as f:
        s = ''.join(f.read().split())
        return codecs.decode(bytes(s, 'ascii'), 'base64')

def readhexfile(filename):
    with open(filename) as f:
        s = ''.join(f.read().split())
        return codecs.decode(bytes(s, 'ascii'), 'hex')

def readhexlines(filename):
    lines = []
    with open(filename) as f:
        s = f.read().split()
        for line in s:
            lines.append(codecs.decode(bytes(line, 'ascii'), 'hex'))
    return lines


def read6():
    return readb64file("6.txt")

def findKeysize(s):
    ans = 0
    minedit = 10000
    for ks in range(2, 41):
        dist = 0
        for i in range(0, len(s)//ks - 1):
            dist += hamming(s[i*ks:(i+1)*ks], s[(i+1)*ks: (i+2)*ks]) / ks
        dist /= (len(s)//ks)
        # print(ks, dist)
        if dist < minedit:
            minedit = dist
            ans = ks
    return ans

# print(findKeysize(read6()))

freqs = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}

def scoreString(s):
    # s is bytearray
    s = bytes(s)
    ans = 0
    for i in s:
        c = chr(i).lower()
        if c in freqs:
            ans += freqs[c]
    return ans

def decodeSingleXOR(s):
    # s is byte array
    bestscore = 0
    ans = ""
    for n in range(256):
        xorS = bytearray()
        for i in range(len(s)):
            xorS.append(n)

        out = xor(s, xorS)
        score = scoreString(out)
        if score > bestscore:
            bestscore = score
            ans = out
    return (ans, bestscore)

# print(decodeSingleXOR(bytes("hello world", 'ascii')))

def decodeRepeatXOR(s, keysize):
    pos = [bytearray() for _ in range(keysize)]
    for i in range(len(s)):
        pos[i%keysize].append(s[i])
    # print(pos)
    dec = []
    for i in range(keysize):
        dec.append(decodeSingleXOR(pos[i])[0])
    ans = bytearray()
    for i in range(len(s)):
        # print(i%keysize, i//keysize)
        # print("'", dec[i%keysize][i//keysize], "'")
        # ans += bytearray(dec[i%keysize][i//keysize], 'ascii')
        ans.append(dec[i%keysize][i//keysize])
    return ans.decode('ascii')
# S1C6
# print(decodeRepeatXOR(read6(), findKeysize(read6())))

def decodeAESECB(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

# C7
# d7 = readb64file("7.txt")
# print(decodeAESECB(d7, "YELLOW SUBMARINE").decode('ascii'))

# def detectAES(lines):
#     maxrepeat = 0
#     for line in lines:
#         blocksize = 16
#         splitline = [line[i:i+blocksize] for i in range(0, len(line), blocksize)]
#         # print(line)
#         # print(splitline)
#         repeats = 0
#         for i in range(len(splitline)):
#             for j in range(i+1, len(splitline)):
#                 if splitline[i] == splitline[j]:
#                     # print(splitline[i], splitline[j])
#                     repeats += 1
#         if  repeats > maxrepeat:
#             maxrepeat = repeats
#             ans = splitline
#     return (maxrepeat, ans)

# C8
# d8 = readhexlines("8.txt")
# print(d8)
# for line in d8:
#     print(len(line))
# detected = detectAES(d8)
# print(detected)
# for line in detected[1]:
#     print(line)
# print()
# for line in sorted(detected[1]):
#     print(line)

def padblock(block, length):
    # block can be bytes or bytearray
    ans = bytearray(block)
    padLength = length - (len(block)%length)
    for i in range(padLength):
        ans.append(padLength)
    return bytes(ans)

# c9
# tests = bytes('YELLOW SUBMARINE', 'ascii')
# print(padblock(tests, 20))

def xor(a, b):
    # bytestrings a and b
    if len(a) != len(b):
        raise Exception('Bytestrings have different length')
    ans = bytearray()
    for i in range(len(a)):
        ans.append(a[i]^b[i])
    return ans

def decodeAESCBC(message, key):
    # split message into 16-byte blocks
    splitmsg = [message[i:i+16] for i in range(0, len(message), 16)]
    print(splitmsg)
    # decode messages
    splitdecoded = []
    for msg in splitmsg:
        splitdecoded.append(decodeAESECB(msg, key))
    # xor messages
    xorblocks = []
    iv = b'\x00'*16
    xorblocks.append(iv)
    for i in range(0, len(splitmsg)-1):
        xorblocks.append(splitmsg[i])

    decoded = []
    for i in range(len(splitdecoded)):
        decoded.append(xor(splitdecoded[i], xorblocks[i]))
    return b''.join(decoded).decode('ascii')


# C10
# d10 = readb64file('10.txt')
# print(decodeAESCBC(d10, "YELLOW SUBMARINE"))

def genkey(size):
    key = bytearray()
    for _ in range(size):
        key.append(randint(0, 255))
    return bytes(key)

# key = genkey(16)
# for i in key:
#     print(i)

def encodeAESECB(data, key):
    data, key = bytes(data), bytes(key)
    data = padblock(data, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def encodeAESCBC(data, key):
    data, key = bytes(data), bytes(key)
    data = padblock(data, 16)
    cipher = AES.new(key, AES.MODE_CBC, genkey(16))
    return cipher.encrypt(data)


def encryptAES(data):
    # encrypts under ECB half the time, CBC half the time
    key = genkey(16)
    padded = bytearray(data)
    # append to front
    numfront = randint(5, 10)
    for _ in range(numfront):
        padded.insert(0, randint(0, 255))
    numback = randint(5, 10)
    for _ in range(numback):
        padded.append(randint(0, 255))
    padded = padblock(padded, 16)
    # print(padded)
    ecb = randint(0, 1)
    if ecb:
        return ('ECB', encodeAESECB(padded, key))
    else:
        return ('CBC', encodeAESCBC(padded, key))




def detectECB(text):
    # requires repeated blocks in input
    blocksize = 16
    splitline = [text[i:i+blocksize] for i in range(0, len(text), blocksize)]

    repeats = 0
    for i in range(len(splitline)):
        for j in range(i+1, len(splitline)):
            if splitline[i] == splitline[j]:
                repeats += 1
    return bool(repeats)
    # return (repeats, splitline)


def detectAESMode(encrypted):
    if detectECB(encrypted)[0] >= 1:
        return 'ECB'
    else:
        return 'CBC'

# C11
# encrypted = encryptAES(bytes('0'*100, 'ascii'))
# print(encrypted)
# print(detectAESMode(encrypted[1]))

def AESprefix(prefix, data, key):
    prefix = bytearray(prefix)
    prefix.extend(data)
    return encodeAESECB(prefix, key)

def detectFnBlockSize(data, key):
    prevlength = 0
    for i in range(30):
        prefix = bytes('0'*i, 'ascii')
        encrypted = AESprefix(prefix, data, key)
        # print(len(encrypted))
        if i >= 1 and len(encrypted) > prevlength:
            return len(encrypted) - prevlength
        prevlength = len(encrypted)

def detectECBpadded(blockSize, data, key):
    prefix = bytes('0'*blockSize*2, 'ascii')
    encrypted = AESprefix(prefix, data, key)
    return detectECB(encrypted)

def decryptSecret(blocksize, data, key):
    secret = bytearray() # same as data! but we infer it
    # find length of secret
    prevlength = len(AESprefix(bytes(), data, key))
    for i in range(1, blocksize):
        prefix = bytes('0'*i, 'ascii')
        encrypted = AESprefix(prefix, data, key)
        if len(encrypted) > prevlength:
            secretlength = len(encrypted)-i-blocksize
            break
        prevlength = len(encrypted)
    # print(secretlength, len(data))
    # decrypt each individual character
    for i in range(secretlength):
        # generate prefix to isolate character i - prefix = blocksize-(i%blocksize)-1
        prefix = bytes('0'*(blocksize - (i%blocksize)-1), 'ascii')
        # print(prefix)
        encrypted = AESprefix(prefix, data, key)
        # isolate the specific block containing character i
        # print(blocksize*(i//blocksize), blocksize*(i//blocksize + 1))
        block = encrypted[blocksize*(i//blocksize): blocksize*(i//blocksize + 1)]
        reference = secret[-blocksize+1:]
        while (len(reference) < blocksize-1):
            reference.insert(0, ord('0'))
        reference.append(0)
        for j in range(256):
            reference[-1] = j
            # print('\t', reference)
            refblock = AESprefix(reference, data, key)[:blocksize]
            if (refblock == block):
                secret.append(j)
                # print('found')
                break
        # print(secret)
    return secret


# C13
# key = genkey(16)
# unknown = readb64file('12.txt')
# # print(unknown)
# blocksize = detectFnBlockSize(unknown, key)
# print(blocksize)
#
# isECB = detectECBpadded(blocksize, unknown, key)
# # print(isECB)
#
# secret = decryptSecret(blocksize, unknown, key)
# print(secret.decode('ascii'))




























