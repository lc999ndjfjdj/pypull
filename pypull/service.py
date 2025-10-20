import libnum
def create(plaintext,key):
    S = list(range(256))  # S 初始化为 256 长度的数组 [0, 1, 2, ..., 255]
    T = [0] * 256         # T 初始化为全零数组
    K = [ord(c) for c in key]  # 将 key 转为对应的 ASCII 码
    for i in range(256):
        T[i]=K[i%len(key)]
    j=0
    for i in range(256):
        j=(j+S[i]+T[i])%256
        S[i],S[j]=S[j],S[i]
    i=j=0
    cipher_hex = []
    for p_char in plaintext:  # 逐个处理明文字符
        p = ord(p_char)  # 明文字符转ASCII码
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256

        
        key_byte = S[t]  # 生成1字节密钥流
        cipher_byte = p ^ key_byte  # 明文与密钥流异或（核心加密步骤）
        cipher_hex.append(f"{cipher_byte:02x}")  # 密文字节转两位十六进制
    
    return cipher_hex
print(create('abab','cipherByRC4'))