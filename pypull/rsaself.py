import random
import gmpy2
import RSAwienerHacker
from Crypto.Util.number import *
import random
from functools import reduce
import math
import gmpy2 as gp
import libnum
from gmpy2 import invert
import binascii
from Crypto.Util.number import isPrime, sieve_base as primes
import rsa
from Crypto.Util.number import *
# getpq_1(n,e,d):已知n（非常大）,e,d求p,q（无法直接 从n分解）（返回p，q的值）
# dpdqm(p,q,c,dp,dq):m
# dpm(e,n,c,dp):m
# cen(c1,c2,e1,e2,n):m
# limit(e,n,c):e很小，m
# near_pq(e,n,c):公式(p+q)**2/4-n=(p-q)**2/4（p,q很相近时可以使用）
'''
低加密指数广播攻击(很多cn)
broadcast_attack(data):进行求明文
known_e(data,e):知道e(data=[(c1,n1),....]
unknown_e(data):不知道e，爆破e
'''
'''
低加密指数攻击
enc_e_is_small(e,n,c):e小,n大
enc_e_is_big(e,n,c):e大
'''
# 高位p求p:p_high():p
# 高位m求m:m_high():m
# m(p,q,e,c):m #包括e和phi不互素
# 都没有了看看https://blog.csdn.net/m0_57291352/article/details/120201628?spm=1001.2014.3001.5502
def gcd(a, b):
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a
def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)
def getpq_1(n,e,d):
    p = 1
    q = 1
    while p == 1 and q == 1:
        K = d*e - 1
        g = random.randint(0, n)
        while p == 1 and q == 1 and K %2 ==0:
            K //= 2
            x = pow(g, K, n)
            if x != 1 and gcd(x - 1, n)>1:
                p = gcd(x - 1, n)
                q = n//p
    return p, q
def getpq(n,e,d):
    p,q = getpq_1(n,e,d)
    print(hex(p))
    print(hex(q))
def dpdqm(p,q,c,dp,dq):
    I = gmpy2.invert(q, p)
    mp = pow(c, dp, p)
    mq = pow(c, dq, q)  # 求幂取模运算
    m = (((mp - mq) * I) % p) * q + mq  # 求明文公式
    print(print(hex(m)[2:]))  # 转为十六进制
    return m
def dpm(e,n,c,dp):
    for i in range(1, e):  # 在范围(1,e)之间进行遍历
        if (dp * e - 1) % i == 0:
            if n % (((dp * e - 1) // i) + 1) == 0:  # 存在p，使得n能被p整除
                p = ((dp * e - 1) // i) + 1
                q = n // (((dp * e - 1) // i) + 1)
                phi = (q - 1) * (p - 1)  # 欧拉定理
                d = gp.invert(e, phi)  # 求模逆
                m = pow(c, d, n)# 快速求幂取模运算
                print(print(hex(m)[2:]))
                return m
def cen(c1,c2,e1,e2,n):
    s = gmpy2.gcdext(e1, e2)
    m = pow(c1, s[1], n) * pow(c2, s[2], n) % n
    if (c1 == pow(m, e1, n)):
        print(bytes.fromhex(hex(m)[2:]))
    return m
def broadcast_attack(data):
    def extended_gcd(a,b):
        x,y = 0,1
        lastx,lasty = 1,0
        while b:
            a,(q,b) = b,divmod(a,b)
            x,lastx = lastx-q*x,x
            y,lasty = lasty-q*y,y
        return (lastx,lasty,a)
    def chinese_remaindor_theorem(items):
        N = 1
        for a,n in items:
            N *= n
        result = 0
        for a,n in items:
            m = N//n
            r,s,d = extended_gcd(n,m)
            if d != 1:
                N = N//n
                continue
            result += a*s*m
        return result%N ,N
    x,n = chinese_remaindor_theorem(data)
    return x
def known_e(data,e):
    m = gmpy2.iroot(gmpy2.mpz(broadcast_attack(data)), e)[0]
    print(long_to_bytes(m))
    return m
def unknown_e(data):
    print('修改关键词')
    for i in range(1, 100):
        e = i
        m = gmpy2.iroot(gmpy2.mpz(broadcast_attack(data)), e)[0]
        if b'flag{' in long_to_bytes(m):  # 修改关键词
            print('e=' + f'{i}')
            print(long_to_bytes(m))
def enc_e_is_small(e,n,c):
    i = 0
    while True:
        if gmpy2.iroot((c + i * n), e)[1] == True:
            m = gmpy2.iroot((c + i * n), e)[0]
            break
        print(i)
        i += 1
    print(binascii.unhexlify(hex(m)[2:]))
    return m
def fermat_attack(n):
    a = gmpy2.isqrt(n)
    b2 = a*a - n
    b = gmpy2.isqrt(n)
    count = 0
    while b*b != b2:
        a = a + 1
        b2 = a*a - n
        b = gmpy2.isqrt(b2)
        count += 1
    p = a+b
    q = a-b
    assert n == p * q
    return p, q
def near_pq(e,n,c):
    p, q = fermat_attack(n)
    phi = (p-1)*(q-1)
    d = invert(e, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
def enc_e_is_big(e,n,c):
    d = RSAwienerHacker.hack_RSA(e, n)
    if (d!=None):
        m = gmpy2.powmod(c, d, n)
        print(binascii.unhexlify(hex(m)[2:]))
    else:
        print("失败")
def limit(e,n,c):
    prd = 1
    for i in primes:
        prd *= i
    # p为(2^prd-1)和n的公约数
    p = gmpy2.gcd(gmpy2.powmod(2, prd, n) - 1, n)
    q = n // p
    d = gmpy2.invert(e, (p - 1) * (q - 1))  # 计算私钥d
    m = gmpy2.powmod(c, d, n)  # 解密
    flag = binascii.unhexlify(hex(m)[2:])
    print(flag)
def m(p,q,e,c):
    print('n=p**r∗q时，e和phi不互素问题，去看https://blog.csdn.net/m0_74345946/article/details/133936371?spm=1001.2101.3001.6650.3&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EYuanLiJiHua%7EPosition-3-133936371-blog-105303760.235%5Ev40%5Epc_relevant_3m_sort_dl_base4&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EYuanLiJiHua%7EPosition-3-133936371-blog-105303760.235%5Ev40%5Epc_relevant_3m_sort_dl_base4&utm_relevant_index=4')
    print('特殊的，e = 2**t且e比较小（e = 256),去看https://blog.csdn.net/m0_57291352/article/details/120201628?spm=1001.2014.3001.5502')
    print('没有提示：没有逆元，也不符合其他条件')
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e,phi)==1:
        d = gmpy2.invert(e, phi)
        m = pow(c, d, n)
        print(libnum.n2s(int(m)))
    elif gcd(e,phi)!=1 and gcd(e,(q-1))==1:
        d = inverse(e, q - 1)
        m = pow(c, d, q)
        print(long_to_bytes(int(m)))
    elif gcd(e, phi)!=1 and gcd(e, (p - 1)) == 1:
        d = inverse(e, p - 1)
        m = pow(c, d, p)
        print(long_to_bytes(int(m)))
    elif gcd(e, phi) != 1 and gcd(e, phi) == e and e< 100:
        print('1.复制代码，去sagemath一起跑，两个都试试')
        n = p * q
        phi = (p - 1) * (q - 1)
        _gcd = gmpy2.gcd(e, phi)
        d = gmpy2.invert(e // _gcd, phi)
        m_gcd = gmpy2.powmod(c, d, n)
        m = gmpy2.iroot(m_gcd, _gcd)
        flag = libnum.n2s(int(m[0]))
        print(flag)
        '''
        from Crypto.Util.number import *
        p = 
        q = 
        c = 
        e = 
        n = p*q

        P.<a>=PolynomialRing(Zmod(p),implementation='NTL')
        f=a^e-c
        mps=f.monic().roots()

        P.<a>=PolynomialRing(Zmod(q),implementation='NTL')
        g=a^e-c
        mqs=g.monic().roots()

        flag=[]
        for mpp in mps:
            x=mpp[0]
            for mqq in mqs:
                y=mqq[0]
                solution = CRT_list([int(x), int(y)], [p, q])
                flag.append(solution)
        print(m)'''
    elif gcd(e, phi) != 1 and gcd(e, phi)==e and gcd(e, (p - 1)) == e and gcd(e, (q - 1)) == e and gcd(e, phi) > 100:
        print('2.复制代码，直接跑，修改关键flag')
        '''
from Crypto.Util.number import *
import random
import math
from gmpy2 import *

def onemod(e, q):
    p = random.randint(1, q-1)
    while(powmod(p, (q-1)//e, q) == 1):  # (r,s)=1
        p = random.randint(1, q)
    return p


def AMM_rth(o, r, q):  # r|(q-1)
    """
    x^r % q = o
    :param o:
    :param r:
    :param q:
    :return:
    """
    assert((q-1) % r == 0)
    p = onemod(r, q)

    t = 0
    s = q-1
    while(s % r == 0):
        s = s//r
        t += 1
    k = 1
    while((s*k+1) % r != 0):
        k += 1
    alp = (s*k+1)//r

    a = powmod(p, r**(t-1)*s, q)
    b = powmod(o, r*a-1, q)
    c = powmod(p, s, q)
    h = 1

    for i in range(1, t-1):
        d = powmod(int(b), r**(t-1-i), q)
        if d == 1:
            j = 0
        else:
            j = (-int(math.log(d, a))) % r
        b = (b*(c**(r*j))) % q
        h = (h*c**j) % q
        c = (c*r) % q
    result = (powmod(o, alp, q)*h)
    return result


def ALL_Solution(m, q, rt, cq, e):
    mp = []
    for pr in rt:
        r = (pr*m) % q
        # assert(pow(r, e, q) == cq)
        mp.append(r)
    return mp


def ALL_ROOT2(r, q):  # use function set() and .add() ensure that the generated elements are not repeated
    li = set()
    while(len(li) < r):
        p = powmod(random.randint(1, q-1), (q-1)//r, q)
        li.add(p)
    return li


def attack(p, q, e, check=None):
    cp = c % p
    cq = c % q

    mp = AMM_rth(cp, e, p)
    mq = AMM_rth(cq, e, q)

    rt1 = ALL_ROOT2(e, p)
    rt2 = ALL_ROOT2(e, q)

    amp = ALL_Solution(mp, p, rt1, cp, e)
    amq = ALL_Solution(mq, q, rt2, cq, e)

    if check is not None:
        j = 1
        t1 = invert(q, p)
        t2 = invert(p, q)
        for mp1 in amp:
            for mq1 in amq:
                j += 1
                if j % 1000000 == 0:
                    print(j)
                ans = (mp1 * t1 * q + mq1 * t2 * p) % (p * q)
                if check(ans):
                    return ans
    return amp, amq

def calc(mp, mq, e, p, q):
    i = 1
    j = 1
    t1 = invert(q, p)
    t2 = invert(p, q)
    for mp1 in mp:
        for mq1 in mq:
            j += 1
            if j % 1000000 == 0:
                print(j)
            ans = (mp1*t1*q+mq1*t2*p) % (p*q)
            if check(ans):
                return
    return

def check(m):
    try:
        a = long_to_bytes(m)
        if b'NSSCTF' in a:
            print(a)
            return True
        else:
            return False
    except:
        return False

if __name__ == '__main__':
    e = 1009
    n = 38041020633815871156456469733983765765506895617311762629687651104582466286930269704125415948922860928755218376007606985275046819516740493733602776653724917044661666016759231716059415706703608364873041098478331738686843910748962386378250780017056206432910543374411668835255040201640020726710967482627384460424737495938659004753604600674521079949545966815918391090355556787926276553281009472950401599151788863393804355849499551329
    c = 2252456587771662978440183865248648532442503596913181525329434089345680311102588580009450289493044848004270703980243056178363045412903946651952904162045861994915982599488021388197891419171012611795147125799759947942753772847866647801312816514803861011346523945623870123406891646751226481676463538137263366023714001998348605629756519894600802504515051642140147685496526829541501501664072723281466792594858474882239889529245732945
    p = 5220649501756432310453173296020153841505609640978826669340282938895377093244978215488158231209243571089268416199675077647719021740691293187913372884975853901554910056350739745148711689601574920977808625399309470283   
    q = 7286645200183879820325990521698389973072307061827784645416472106180161656047009812712987400850001340478084529480635891468153462119149259083604029658605921695587836792877281924620444742434168448594010024363257554563
    cp = c % p
    cq = c % q

    mp = AMM_rth(cp, e, p)
    mq = AMM_rth(cq, e, q)

    rt1 = ALL_ROOT2(e, p)
    rt2 = ALL_ROOT2(e, q)

    amp = ALL_Solution(mp, p, rt1, cp, e)
    amq = ALL_Solution(mq, q, rt2, cq, e)

    calc(amp, amq, e, p, q)

                '''

    elif gcd(e, phi) != 1 and gcd(e, phi) == e and gcd(e, phi) > 100:
        print('3.复制代码去sage,注意修改关键词flag{}，以及AMM里p改成q试一下')
        '''
        # sagemath
        import random
        import math
        import time
        from Crypto.Util.number import bytes_to_long,long_to_bytes
        p = 0
        #设置模数
        def GF(a):
            global p
            p = a
        #乘法取模
        def g(a,b):
            global p
            return pow(a,b,p)


        def AMM(x,e,p):
            GF(p)
            y = random.randint(1, p-1)
            while g(y, (p-1)//e) == 1:
                y = random.randint(1, p-1)
                print(y)
            print("find")
            #p-1 = e^t*s
            t = 1
            s = 0
            while p % e == 0:
                t += 1
                print(t)
            s = p // (e**t)
            print('e =',e)
            print('p =',p)
            print('s =',s)
            print('t =',t)
            # s|ralpha-1
            k = 1    
            while((s * k + 1) % e != 0):
                k += 1
            alpha = (s * k + 1) // e
            #计算a = y^s b = x^s h =1
            #h为e次非剩余部分的积
            a = g(y, (e ** (t - 1) ) * s)
            b = g(x, e * alpha - 1)
            c = g(y, s)
            h = 1
            #
            for i in range(1, t-1):
                d = g(b,e**(t-1-i))
                if d == 1:
                    j = 0
                else:
                    j = -math.log(d,a)
                b = b * (g(g(c, e), j))
                h = h * g(c, j)
                c = g(c, e)
            #return (g(x, alpha * h)) % p
            root = (g(x, alpha * h)) % p
            roots = set()
            for i in range(e):
                mp2 = root * g(a,i) %p
                assert(g(mp2, e) == x)
                roots.add(mp2)
            return roots
        p=
        q=
        e=
        c = 
        n = p*q
        mps = AMM(c,e,p)
        for mpp in mps:
                solution = long_to_bytes(int(mpp))
                if b'moectf' in solution: # 修改关键词
                #solution = int(mpp)
                    print(solution)
                    '''
def p_high():
    print('复制')
"""     sage
(此处解法中p4为p去除0的剩余位)
p_high = 0xd1c520d9798f811e87f4ff406941958bab8fc24b19a32c3ad89b0b73258ed3541e9ca696fd98ce15255264c39ae8c6e8db5ee89993fa44459410d30a0a8af700ae3aee8a9a1d6094f8c757d3b79a8d1147e85be34fb260a970a52826c0a92b46cefb5dfaf2b5a31edf867f8d34d22229
n = 0x79e0bf9b916e59286163a1006f8cefd4c1b080387a6ddb98a3f3984569a4ebb48b22ac36dff7c98e4ebb90ffdd9c07f53a20946f57634fb01f4489fcfc8e402865e152820f3e2989d4f0b5ef1fb366f212e238881ea1da017f754d7840fc38236edba144674464b661d36cdaf52d1e5e7c3c21770c5461a7c1bc2db712a61d992ebc407738fc095cd8b6b64e7e532187b11bf78a8d3ddf52da6f6a67c7e88bef5563cac1e5ce115f3282d5ff9db02278859f63049d1b934d918f46353fea1651d96b2ddd874ec8f1e4b9d487d8849896d1c21fb64029f0d6f47e560555b009b96bfd558228929a6cdf3fb6d47a956829fb1e638fcc1bdfad4ec2c3590dea1ed3
c = 0x1b2b4f9afed5fb5f9876757e959c183c2381ca73514b1918d2f123e386bebe9832835350f17ac439ac570c9b2738f924ef49afea02922981fad702012d69ea3a3c7d1fc8efc80e541ca2622d7741090b9ccd590906ac273ffcc66a7b8c0d48b7d62d6cd6dd4cd75747c55aac28f8be3249eb255d8750482ebf492692121ab4b27b275a0f69b15baef20bf812f3cbf581786128b51694331be76f80d6fb1314d8b280eaa16c767821b9c2ba05dfde5451feef22ac3cb3dfbc88bc1501765506f0c05045184292a75c475486b680f726f44ef8ddfe3c48f75bb03c8d44198ac70e6b7c885f53000654db22c8cee8eb4f65eaeea2da13887aaf53d8c254d2945691
pbits = 1024 # p原本位数
kbits = pbits - p_high.nbits() # p丢失位数
p_high = p_high << kbits
PR.<x> = PolynomialRing(Zmod(n))
f = x + p_high
p0 = f.small_roots(X = 2 ^ kbits,beta = 0.4)[0]
print(p_high + p0) """
def m_high():
    """ print('复制')
    def phase2(high_m, n, c,e):
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    m = high_m + x
    M = m((m^e - c).small_roots()[0])
    print(hex(int(M))[2:])
 """





