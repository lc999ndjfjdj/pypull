import math


def Get_Mi(m_list, M):
    M_list = []
    for mi in m_list:
        M_list.append(M // mi)#(求M/mi)
    return M_list


def Get_resMi(M_list, m_list):#求ei(ei在模mi的情况下和M/mi互为乘法逆元)
    resM_list = []
    for i in range(len(M_list)):
        resM_list.append(extended_gcd(M_list[i], m_list[i])[0])
    return resM_list

def extended_gcd(a,b):
        x,y = 0,1
        lastx,lasty = 1,0
        while b:
            a,(q,b) = b,divmod(a,b)
            x,lastx = lastx-q*x,x
            y,lasty = lasty-q*y,y
        return (lastx,lasty,a)



def result(a_list, m_list):
    for i in range(len(m_list)):#判断模是否互素
        for j in range(i + 1, len(m_list)):
            if 1 != math.gcd(m_list[i], m_list[j]):
                print("模不互素")
                return
    m = 1
    for mi in m_list:#求M(list的m相乘)
        m *= mi
    Mi_list = Get_Mi(m_list, m)#M/mi
    Mi_inverse = Get_resMi(Mi_list, m_list)#ei
    x = 0
    for i in range(len(a_list)):
        x += Mi_list[i] * Mi_inverse[i] * a_list[i]
        x %= m#减少计算量
    return x

a_list = list(map(int, input().split(",")))
m_list = list(map(int, input().split(",")))
print(result(a_list, m_list))