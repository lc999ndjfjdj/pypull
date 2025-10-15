import numpy as np
from gmpy2 import invert,gcd,mpz
# 置换密码
class zhihuan:
    @staticmethod
    def encrypt(m, key):
        m_to_array = [x for x in m]  # 定义明文数组

        key = [int(x) for x in key]
        lie = len(key)  # 二维矩阵列数
        hang = (len(m) + lie - 1) // lie  # 矩阵行数,带余数除法计算

        # 二维矩阵初始化
        m_zhen = np.full((hang, lie),'',dtype='object')
        for x in range(len(m_to_array)):
            i = x // lie
            j = x % lie
            m_zhen[i][j] = m_to_array[x]

        c_to_array = []  # 密文数组
        key_map = {val: idx for idx, val in enumerate(key)}# 创建字典
        for k in range(1, lie + 1):
            # 找到当前k对应的列索引
            col = key_map.get(k,-1)
            # 读取该列的所有行
            for j in range(hang):
                if m_zhen[j][col] != '':  # 排除填充的0
                    c_to_array.append(m_zhen[j][col])    


        result = ''.join([str(x) for x in c_to_array])
        return result
    @staticmethod
    def decrypt(c, key):
        key = [int(x) for x in key]
        lie = len(key)  # 列数
        print(lie)
        hang = (len(c) + lie - 1) // lie  # 行数
        print(hang)
        m_zhen = np.full((hang, lie), '', dtype='object')

        # 每列实际长度（前 full_cols 列是 hang，其余是 hang-1）
        full_cols = len(c) % lie#满列
        print(full_cols)
        # 行数存储
        col_lens = [hang if i < full_cols else hang - 1 for i in range(lie)]
        print(col_lens)
        # 所有的多余项必然从最后一列开始增加
        #最后列的行数会比前面列多一（如果有多余项）
        key_map = {val: idx for idx, val in enumerate(key)}  # key值 -> 列索引

        # 逐列写入密文
        idx = 0
        for k in range(1, lie + 1):
            col = key_map[k]#获取下标
            for row in range(col_lens[col]):#行数获取，遍历添加到m_zhen
                m_zhen[row][col] = c[idx]
                idx += 1

        m_to_array = []
        for i in range(hang):
            for j in range(lie):
                if m_zhen[i][j] != '':
                    m_to_array.append(m_zhen[i][j])

        return ''.join(m_to_array)
# 代替密码
class daiti:
    encrypt_dict = {
        'a': 'j', 'b': 'p', 'c': 'v', 'd': 'e', 'e': 'y', 'f': 'w',
        'g': 'd', 'h': 'u', 'i': 'l', 'j': 't', 'k': 'h', 'l': 'a',
        'm': 'o', 'n': 'r', 'o': 'g', 'p': 's', 'q': 'z', 'r': 'm',
        's': 'i', 't': 'b', 'u': 'x', 'v': 'c', 'w': 'q', 'x': 'f',
        'y': 'n', 'z': 'k'
    }
    decrypt_dict = {
        'a': 'l', 'b': 't', 'c': 'v', 'd': 'g', 'e': 'd', 'f': 'x',
        'g': 'o', 'h': 'k', 'i': 's', 'j': 'a', 'k': 'z', 'l': 'i',
        'm': 'r', 'n': 'y', 'o': 'm', 'p': 'b', 'q': 'w', 'r': 'n',
        's': 'p', 't': 'j', 'u': 'h', 'v': 'c', 'w': 'f', 'x': 'u',
        'y': 'e', 'z': 'q'
    }
    def encrypt(m):
        c=''.join([daiti.encrypt_dict[x] for x in m])
        return c
    def decrypt(c):
        m=''.join([daiti.decrypt_dict[x] for x in c])
        return m
# 仿射密码
class fangshe:
    @staticmethod#静态方法，防止参数隐形偏移
    def encrypt(m, a, b):
        if gcd(mpz(a), mpz(26)) != 1:
            return 'a和26不互素'
        
        m_offsets = [ord(x) - ord('a') for x in m]  # 明文转0-25
        c_offsets = [(a * offset + b) % 26 for offset in m_offsets]
        return ''.join([chr(offset + ord('a')) for offset in c_offsets])
    @staticmethod
    def decrypt(c, a, b):
        if gcd(mpz(a), mpz(26)) != 1:
            return 'a和26不互素'
        
        c_offsets = [ord(y) - ord('a') for y in c]  # 密文转0-25
        m_offsets = [(invert(a, 26) * (offset - b)) % 26 for offset in c_offsets]
        return ''.join([chr(offset + ord('a')) for offset in m_offsets])
# 维吉尼亚密码
class weiji:
    # 26个英文字母
    alphabet = [chr(i) for i in range(ord('a'), ord('z') + 1)]
    # 字母字典
    dict_weiji = {val: idx for idx, val in enumerate(alphabet)}
    @staticmethod
    def encrypt(m, key):
        m_to_array = [x for x in m]
        c = ''
        for i in range(len(m_to_array)):
            # 获取明文字符的索引
            idx = weiji.dict_weiji.get(m_to_array[i])
            # 获取密钥字符的索引
            key_idx = weiji.dict_weiji.get(key[i % len(key)])
            # 加密
            c_idx = (idx + key_idx) % 26
            # 获取密文字符
            c+=weiji.alphabet[c_idx]
        return c
    @staticmethod
    def decrypt(c, key):
        c_to_array = [x for x in c]
        m = ''
        for i in range(len(c_to_array)):
            # 获取密文字符的索引
            idx = weiji.dict_weiji.get(c_to_array[i])
            # 获取密钥字符的索引
            key_idx = weiji.dict_weiji.get(key[i % len(key)])
            # 解密
            m_idx = (idx - key_idx + 26) % 26
            m+=weiji.alphabet[m_idx]
        return m
def inputMassage(object):
    print('Please select encrypt or decrypt')
    print('1. encrypt')
    print('2. decrypt')
    b=input()
    switch = {
        '1': object.encrypt,
        '2': object.decrypt
    }
    func = switch[b]
    text = input('please input text:')
    return func,text
def main():
    while True:
        print('Please select a Cyptography:')
        print('1. 置换密码')
        print('2. 代替密码')
        print('3. 仿射密码')
        print('4. 维吉尼亚密码')
        print('5. 退出')
        a=input()
        match a:
            case '1':
                func , text =inputMassage(zhihuan)#传入对象
                key = input('please input key:')
                print(func(text, key))
            case '2':
                func , text =inputMassage(daiti)
                print(func(text))
            case '3':
                func , text =inputMassage(fangshe)
                key_a = int(input('please input key_a:'))
                key_b = int(input('please input key_b:'))
                print(func(text, key_a, key_b))
            case '4':
                func , text =inputMassage(weiji)
                key = input('please input key:')
                print(func(text, key))
            case '5':
                return
if __name__ == '__main__':
    main()