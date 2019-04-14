import binascii

# 定义字长为32位
w = 32

# 初始化缓冲区寄存器(A、B、C、D、E)
H = ["01100111010001010010001100000001",
     "11101111110011011010101110001001",
     "10011000101110101101110011111110",
     "00010000001100100101010001110110",
     "11000011110100101110000111110000"]

# 初始化常数值K_i列表
K = ["01011010100000100111100110011001",
     "01101110110110011110101110100001",
     "10001111000110111011110011011100",
     "11001010011000101100000111010110"]


# 10进制转为16进制
def decToHex(n):
    return hex(int(n, 10))[2:]


# 16进制转为10进制
def hexToDec(n):
    return int(n, 16)


# 16进制转换为2进制
def hexToBin(hex):
    msg = ""
    for char in hex:
        temp = bin(int(char, 16))[2:]
        if len(temp) < 4:
            msg += '0' * (4-len(temp))
        msg += temp
    return msg


# 2进制转换为16进制
def binToHex(bin):
    msg = ""
    i = 0
    while(i < len(bin)):
        msg += hex(int(bin[i:i+4], 2))[2:]
        i += 4
    return msg


# x、y的逐位逻辑“与”
def logic_and(x, y):
    assert len(x) == len(y)
    z = ""
    for i in range(0, len(x)):
        if x[i] == "1" and y[i] == "1":
            z += "1"
        else:
            z += "0"
    return z


# x、y的逐位逻辑“或”
def logic_or(x, y):
    assert len(x) == len(y)
    z = ""
    for i in range(0, len(x)):
        if x[i] == "0" and y[i] == "0":
            z += "0"
        else:
            z += "1"
    return z


# x的逐位逻辑“非”
def logic_not(x):
    y = ""
    for i in range(0, len(x)):
        if x[i] == "1":
            y += "0"
        else:
            y += "1"
    return y


# x、y的逐位逻辑“异或”
def logic_xor(x, y):
    assert len(x) == len(y)
    z = ""
    for i in range(0, len(x)):
        if x[i] != y[i]:
            z += "1"
        else:
            z += "0"
    return z


# x循环左移n位
def ringShiftLeft(x, n):
    y = x[n:] + n * "0"
    z = (w-n) * "0" + x[0: -(w-n)]
    return logic_or(y, z)


# 求模运算(10进制输入，2进制输出）
def getMod(x):
    tmp = bin(x % 2**w)[2:]
    if len(tmp) < w:
        tmp = (w - len(tmp)) * "0" + tmp
    return tmp


# 定义基本逻辑函数f_t
def f_t(a, b, c, t):
    assert 0 <= t < 80
    if(0 <= t <= 19):
        return logic_or(logic_and(a, b),logic_and(logic_not(a), c))
    elif( 40 <= t <= 59):
        temp1 = logic_or(a, b)
        temp2 = logic_or(a, c)
        temp3 = logic_or(b, c)
        temp4 = logic_and(temp1, temp2)
        return logic_and(temp3, temp4)
    else:
        return logic_xor(logic_xor(a, b), c)


# 定义SHA-1的压缩函数（循环函数）
def sha1_compress(t, k, W, H_t):
    #计算寄存器A的值
    temp = int(H_t[4],2) + int(f_t(H_t[1], H_t[2], H_t[3], t),2) + \
           int(ringShiftLeft(H_t[0], 5),2) + int(W[t],2) + \
           int(k,2)
    temp = getMod(temp)

    #更新寄存器A,B,C,D,E的值(H_t)
    H_t[4] = H_t[3]
    H_t[3] = H_t[2]
    H_t[2] = ringShiftLeft(H_t[1], 30)
    H_t[1] = H_t[0]
    H_t[0] = temp

    return H_t


#sha-1算法的轮运算
def sha1_cycle(x):

    # 计算得到当前分组字W0到W79的列表
    W = []
    for t in range(0, 80):
        if t < 16:
            W.append(x[0:32])
            x = x[32:]
        else:
            temp1 = logic_xor(W[t-16], W[t-14])
            temp2 = logic_xor(W[t-8], W[t-3])
            W.append(ringShiftLeft(logic_xor(temp1, temp2), 1))

    # 计算寄存器（A,B,C,D,E)的值
    H_t = H[:]
    for t in range(0, 80):
        if t <= 19:
            H_t = sha1_compress(t, K[0], W, H_t)
        elif 20 <= t <= 39:
            H_t = sha1_compress(t, K[1], W, H_t)
        elif 40 <= t <= 59:
            H_t = sha1_compress(t, K[2], W, H_t)
        elif 60 <= t <= 79:
            H_t = sha1_compress(t, K[3], W, H_t)

    # 计算得到这一轮的散列结果,并存入缓存区寄存器 H（A，B，C，D，E）
    H[0] = getMod(int(H_t[0],2) + int(H[0], 2))
    H[1] = getMod(int(H_t[1], 2) + int(H[1], 2))
    H[2] = getMod(int(H_t[2], 2) + int(H[2], 2))
    H[3] = getMod(int(H_t[3], 2) + int(H[3], 2))
    H[4] = getMod(int(H_t[4], 2) + int(H[4], 2))


#sha-1算法(16进制输入)
def sha1(x):
    msg = hexToBin(x)

    # 处理后的消息存入列表中
    msg_list = []

    # 计算输入x的二进制长度n(n也为2进制）
    n = bin(len(msg))[2:]
    # print(len(msg))

    # 消息分割
    while len(msg) > 512:
        msg_list.append(msg[0: 512])
        msg = msg[512:]

    # 消息填充
    if len(msg) > 448:
        msg_list.append(msg + "1" + (511 - len(msg)) * "0")
        msg_list.append(448 * '0' + (64 - len(n)) * "0" + n)
    else:
        msg_list.append(msg + "1" + (447 - len(msg)) * "0" + (64 - len(n)) * "0" + n )

    # 开始迭代计算散列值
    for msg in msg_list:
        sha1_cycle(msg)

    # 从缓冲区H取出最终的散列值
    hash = ""
    for i in list(map(binToHex, H)):
        hash += i

    return hash


