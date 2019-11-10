from Crypto.Cipher import AES
from Crypto import Random

credit_card_number = "4532294977918448"
print 'Number to encrypt = ' + credit_card_number

round_keys = []

def xor(a, b):
    a = '{:032b}'.format(int(a, 16))
    tmp = ''
    for i in range(len(a) - 5):
        tmp += str(int(a[i]) ^ int(b[i]))
    return tmp

def enc(card_number, rounds, produce_keys):

    encoded_number = '{0:054b}'.format(int(card_number))
    l = encoded_number[:27]
    r = encoded_number[27:]

    if produce_keys:
        for i in range(rounds):
            key = Random.new().read(16).encode('hex')
            round_keys.append(key)

    for i in range(rounds):        
        
        key = round_keys[i]
        obj = AES.new(key.decode('hex'))
        hex_r = '{:08x}'.format(int(r + '0'*5, 2))
        b = hex_r + '0'*23 + str(i+1)
        enc_res = obj.encrypt(b.decode('hex')).encode('hex')[:7] + '0'
        tmp = r
        r = xor(enc_res, l+'0'*5)
        l = tmp

    return (l , r)

def dec(cipher, rounds):

    encoded_number = '{0:054b}'.format(int(cipher))
    l = encoded_number[:27]
    r = encoded_number[27:]

    for i in range(rounds,0,-1):
        key = round_keys[i-1]
        obj = AES.new(key.decode('hex'))
        
        hex_l = '{:08x}'.format(int(l + '0'*5, 2))
        b = hex_l + '0'*23 + str(i)
        enc_res = obj.encrypt(b.decode('hex')).encode('hex')[:7] + '0'
        tmp = l
        l = xor(enc_res, r+'0'*5)
        r = tmp

    return (l , r)


l , r = enc(credit_card_number, 6, True)
final = l + r
final = int(final, 2)
while final > 9999999999999999:
    print 'Not valid encoded number = ' +  str(final)
    l , r = enc(final, 6, False)
    final = l + r
    final = int(final, 2)

print 'encoded number = ' + str(final)

print 'Decrypting ...'
print 'Cipher to decrypt = ' + str(final)
l , r = dec(final, 6)
final = l + r
final = int(final, 2)
while final > 9999999999999999:
    print 'Not valid encoded number = ' +  str(final)
    l , r = dec(final, 6)
    final = l + r
    final = int(final, 2)

print 'dec number = ' + str(final)
