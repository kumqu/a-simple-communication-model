import random

# 十进制转为十六进制
def decToHex(n):
    return hex(int(n, 10))[2:]


# 十六进制转为十进制
def hexToDec(n):
    return int(n, 16)


# 生成n位的随机数
def createRandomNum(n):
    return random.randint(10 ** (n - 1), 10 ** n - 1)


# 欧几里得算法求最大公约数
def gcd(x, y):
    while y:
        x, y = y, x % y
    return x


# 扩展欧几里得算法求乘法逆元(x*a + y*b = q)
def getInverse(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = getInverse(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q


# 平方求模
def getMod(a, e, m):
    result = 1
    while e != 0:
        if e & 1 == 1:
            result = result * a % m
        e >>= 1
        a = a * a % m
    return result


# 生成10000以内素数表(eratosthenes算法）
def primeFilter(n):
    return lambda x: x % n > 0


def createSmallPrimeNum():
    num = iter(range(3, 10000, 2))
    prime = [2]
    while True:
        try:
            n = next(num)
            prime.append(n)
            num = filter(primeFilter(n), num)
        except StopIteration:
            return prime


# 素数检测算法（Miller-Rabin算法）
def Miller_Rabin(n):
    if n < 3:
        return False

    k = 1
    m = 0
    while (n - 1) % (2 ** k) == 0:
        m = (int)((n - 1) / (2 ** k))
        if m % 2:
            break
        k += 1
    if m == 0:
        return False

    a = random.randint(2, n - 1)
    b = getMod(a, m, n)

    if b == 1:
        return True

    for i in range(0, k):
        if b == n - 1:
            return True
        else:
            b = b * b % n

    return False


# 生成大素数(x位）
def createLargePrimeNum(x):
    flag = False
    smallPrimeNum = createSmallPrimeNum()

    while (not flag):
        flag = True
        n = createRandomNum(x)
        if not n % 2: n += 1

        # 10000内素数检验
        for i in smallPrimeNum:
            if n % i == 0:
                flag = False
                break
        if not flag: continue

        # 10次Miller-Rabin素性检测
        for i in range(0, 20):
            if not Miller_Rabin(n):
                flag = False
                break
    return n


# 密钥生成
def createKey(x):
    p = createLargePrimeNum(x)
    q = createLargePrimeNum(x)
    n = p * q
    _n = (p - 1) * (q - 1)
    e = random.randint(2, _n - 1)

    while (gcd(e, _n) != 1):
        e = random.randint(2, _n - 1)

    d, tmp1, tmp2 = getInverse(e, _n)
    if d < 0:
        d += _n
    return e, n, d


# 加密函数
def encrypt(m, e, n):
    assert m < n, "m must be shorter than n"
    return getMod(m, e, n)


# 解密函数
def decrypt(c, d, n):
    return getMod(c, d, n)


# 64bit(16位）一组，进行RSA加密(p为16进制，e、n为10进制，输出c为10进制）
def rsa_encrypt(p, e, n):
    n_str = decToHex(str(n))
    c = ""
    while len(p) >= 16:
        tmp = decToHex(str(encrypt(hexToDec(p[0:16]), e, n)))
        if len(tmp) < len(n_str):
            tmp = (len(n_str) - len(tmp)) * '0' + tmp
        c += tmp
        p = p[16:]

    if len(p) != 0:
        tmp = decToHex(str(encrypt(hexToDec(p[0:16]), e, n)))
        if len(tmp) < len(n_str):
            tmp = (len(n_str) - len(tmp)) * '0' + tmp
        c += tmp

    return c


# 64bit(16位）一组，进行RSA解密(c为16进制，d、n为10进制, 输出m为16进制)
def rsa_decrypt(c, d, n):
    n_hex = decToHex(str(n))
    m = ""
    num = len(n_hex)
    while len(c) > 0:
        x = hexToDec(c[0: num])
        c = c[len(n_hex):]
        tmp = decrypt(x, d, n)
        if len(decToHex(str(tmp))) < 16 and len(c) > 0:
            m += (16-len(decToHex(str(tmp)))) * '0'
        m += decToHex(str(tmp))
    return m