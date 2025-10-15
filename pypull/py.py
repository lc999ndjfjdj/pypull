key=[1,1,0,0,1]
initstate=key
for k in range(31-len(initstate)):
    key.append(key[3+k]^key[k])
print(key)

def encrypt(plaintext, key_stream):
    groups = []
    while len(key_stream)//7 <= len(plaintext):#在明文过长的时候进行自增
        key_stream += key_stream
    #print(len(key_stream)),abc是31，abcabcabcabc是62
    for i in range(0, len(key_stream), 7):
        group = key_stream[i:i+7]
        num = 0
        for bit in group:
            num = (num << 1) | bit # 将每个位逻辑左移并异或
        groups.append(num)

    ciphertext = ""
    for i, char in enumerate(plaintext):
        key_num = groups[i]
        encrypted_char = chr(ord(char) ^ key_num)
        ciphertext += encrypted_char
    return ciphertext

plaintext1 = "abc"
ciphertext1 = encrypt(plaintext1, key)
print(f"明文 '{plaintext1}' 的密文：{ciphertext1}")

plaintext2 = "abcabcabcabc"
ciphertext2 = encrypt(plaintext2, key)
print(f"明文 '{plaintext2}' 的密文：{ciphertext2}")
