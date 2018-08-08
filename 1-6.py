import codecs
import base64
import binascii

def hexTob64(s):
    return codecs.encode(codecs.decode(s, 'hex'), 'base64').decode()

# S1C1
# print(hexTob64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
def hexToInt(s):
    if s.isalpha():
        return ord(s)-ord('a')+10
    else:
        return int(s)

def intToHex(num):
    if num <= 9:
        return str(num)
    else:
        return chr(num-10+ord('a'))

def xorHex(a, b):
    ans = ""
    for i in range(len(a)):
        ans += intToHex(hexToInt(a[i]) ^ hexToInt(b[i]))
    return ans

# S1C2
# print(xorHex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))

# def isValidASCII(b):
#     for i in b:
#         if i >= 128:
#             return False
#     return True
#
# freqs = {
#     'a': 0.0651738,
#     'b': 0.0124248,
#     'c': 0.0217339,
#     'd': 0.0349835,
#     'e': 0.1041442,
#     'f': 0.0197881,
#     'g': 0.0158610,
#     'h': 0.0492888,
#     'i': 0.0558094,
#     'j': 0.0009033,
#     'k': 0.0050529,
#     'l': 0.0331490,
#     'm': 0.0202124,
#     'n': 0.0564513,
#     'o': 0.0596302,
#     'p': 0.0137645,
#     'q': 0.0008606,
#     'r': 0.0497563,
#     's': 0.0515760,
#     't': 0.0729357,
#     'u': 0.0225134,
#     'v': 0.0082903,
#     'w': 0.0171272,
#     'x': 0.0013692,
#     'y': 0.0145984,
#     'z': 0.0007836,
#     ' ': 0.1918182
# }
#
# def scoreString(s):
#     ans = 0
#     for i in s:
#         c = i.lower()
#         if c in freqs:
#             ans += freqs[c]
#     return ans
#
# def decodeSingleXOR(s):
#     bestscore = 0
#     ans = ""
#     for n1 in range(16):
#         for n2 in range(16):
#             c = intToHex(n1)+intToHex(n2)
#
#             xorS = c*(len(s)//2)
#             out = xorHex(s, xorS)
#             bytes = codecs.decode(out, "hex")
#
#             if not isValidASCII(bytes):
#                 continue
#
#             ascii = bytes.decode("ascii")
#             score = scoreString(ascii)
#             if score > bestscore:
#                 bestscore = score
#                 ans = ascii
#     return (ans, bestscore)

# S1C3
# print(decodeSingleXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

# with open('4.txt') as f:
#     strings = f.read().split()

def findEncrypted(ss):
    bestscore = 0
    ans = ""
    for s in ss:
        out, score = decodeSingleXOR(s)
        # print(out)
        if score > bestscore:
            bestscore = score
            ans = out
    return ans

# S1C4
# print(findEncrypted(strings))

def repeatKey(key, length):
    ans = key * (length//len(key))
    ans += key[:length-len(ans)]
    return ans

def xor(a, b):
    # bytestrings a and b
    if len(a) != len(b):
        raise Exception('Bytestrings have different length')
    ans = bytearray()
    for i in range(len(a)):
        ans.append(a[i]^b[i])
    return ans


def encodeRepeat(s, key):
    xors = repeatKey(key, len(s))
    out = xor(bytes(s, 'ascii'), bytes(xors, 'ascii'))
    return out.hex()

# S1C5
# print(encodeRepeat("Burning 'em, if you ain't quick and nimble", "ICE"))
# print(encodeRepeat("I go crazy when I hear a cymbal", "ICE"))

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

def read6():
    with open("6.txt") as f:
        s = ''.join(f.read().split())
        return codecs.decode(bytes(s, 'ascii'), 'base64')

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

print(decodeRepeatXOR(read6(), findKeysize(read6())))