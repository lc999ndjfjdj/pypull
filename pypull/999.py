from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from collections import defaultdict
gift = 64698960125130294692475067384121553664
key1_h = "74aeb356c6eb74f364cd316497c0f714"
cipher = b'6\xbf\x9b\xb1\x93\x14\x82\x9a\xa4\xc2\xaf\xd0L\xad\xbb5\x0e|>\x8c|\xf0^dl~X\xc7R\xcaZ\xab\x16\xbe r\xf6Pl\xe0\x93\xfc)\x0e\x93\x8e\xd3\xd6'
cipher_h = cipher.hex()
cipher = bytes.fromhex(cipher_h)


def s_t_n(value, hex_str=False):
    if hex_str:
        return [int(hex_str[i:i + 1], 16) for i in range(32)]
    bin_str = format(value, '0128b')
    return [int(bin_str[i * 4:(i + 1) * 4], 2) for i in range(32)]


gift_nn = s_t_n(gift)
key1_nn = s_t_n(0, key1_h)

p_c_s = []
for i in range(32):
    m = key1_nn[i]
    b = gift_nn[i]
    cands = [x for x in range(16) if (x & m) == b]
    p_c_s.append(cands)



p_b_y = defaultdict(list)
for i, y in enumerate(key1_nn):
    p_b_y[y].append(i)

y_c = {}
for y, poses in p_b_y.items():
    s = set(p_c_s[poses[0]])
    for i in poses[1:]:
        s &= set(p_c_s[i])
    y_c[y] = list(s)

used = set()
inv_map = {}
solutions = []
items = sorted(y_c.items(), key=lambda kv: len(kv[1]))


def get_flag(idx):
    if idx == len(items):
        key0_n = [inv_map[y] for y in key1_nn]
        key_h = "".join(f"{n:x}" for n in key0_n)
        aes0 = AES.new(bytes.fromhex(key_h), AES.MODE_CBC, bytes.fromhex(key1_h))
        aes1 = AES.new(bytes.fromhex(key1_h), AES.MODE_CBC, bytes.fromhex(key_h))
        try:
            pt = unpad(aes0.decrypt(aes1.encrypt(cipher)), 16)
            if pt.startswith(b"flag{"):
                print(pt.decode())
                solutions.append((key_h, pt.decode()))
                return True
        except:
            pass
        return False
    y, cands = items[idx]
    for x in cands:
        if x in used:
            continue
        inv_map[y] = x
        used.add(x)
        if get_flag(idx + 1):
            return True
        used.remove(x)
        del inv_map[y]
    return False


get_flag(0)
