import socket
from Crypto.Util.number import isPrime

HOST = '39.106.16.204'
PORT = 14536

def try_x(x):
    s = socket.create_connection((HOST, PORT))
    try:
        data = s.recv(1024)
        s.sendall(str(x).encode() + b'\n')
        data = s.recv(1024)
        if b'traceback' not in data.lower():  # 如果没有报错，说明通过
            return True
    except:
        pass
    finally:
        s.close()
    return False

# 测试多个 x，看哪些能成功返回
for x in range(1, 1000):
    if try_x(x):
        print(f"[+] x = {x} might be valid")
        # 可以继续尝试：y = x ^ p，检查是否符合 flag 格式
