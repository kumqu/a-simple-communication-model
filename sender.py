import socket, os, sys, binascii
import des, rsa, sha1


# 读取文件信息
def read_message(filename):
    msg = ""
    with open(filename) as f:
        try:
            for line in f.readlines():
                msg += line
        finally:
            f.close()
    return msg


# 写入文件信息
def write_message(filename, msg):
    try:
        f = open(filename, 'a')
        f.write(msg + '\n')
    finally:
        f.close()


# 消息发送端程序
def sender(msg):

    # 设置接收端端口
    address = ('127.0.0.1', 6666)

    # 建立发送端
    try:
        sender = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
        print('Sending terminal start!')
    except socket.error as error:
        print("Socket failed. Error code: " + str(error[0]) + ", Error message: " + msg[1])
        sys.exit()

    # 建立连接
    try:
        sender.connect(address)
        print("Connect with receiver successful!")
    except socket.error as error:
        print("Socket failed. Error code: " + str(error[0]) + ", Error message: " + msg[1])
        sys.exit()

    # 发送数据
    try:
        sender.sendall(msg)
    except socket.error:
        print('send failed!')
        sys.exit()

    # 接收反馈
    reply = sender.recv(4096)
    print(reply.decode())

    # 断开连接
    sender.close()


# 加密消息，并发送密文
def main():
    cipher_message = []

    # 读取消息，将ASCII码转化为16进制
    msg = read_message('./sender/messages.txt').encode()
    msg = binascii.hexlify(msg).decode('ascii')

    # des的ECB模式加密消息
    des_key = read_message('./sender/des_key.txt')
    des_cipher = des.ECB_encrypt(msg, des_key)
    cipher_message.append(des_cipher)

    # 生成rsa公钥、私钥，并写入文件
    rsa_e, rsa_n, rsa_d = rsa.createKey(15)
    if os.path.isfile('./receiver/rsa_d.txt'):
        os.remove('./receiver/rsa_d.txt')
    write_message('./receiver/rsa_d.txt', hex(rsa_d)[2:])
    if os.path.isfile('./receiver/rsa_e.txt'):
        os.remove('./receiver/rsa_e.txt')
    write_message('./receiver/rsa_e.txt', hex(rsa_e)[2:])
    if os.path.isfile('./receiver/rsa_n.txt'):
        os.remove('./receiver/rsa_n.txt')
    write_message('./receiver/rsa_n.txt', hex(rsa_n)[2:])

    # rsa加密对称密钥
    des_key_encrypted = rsa.rsa_encrypt(des_key, rsa_e, rsa_n)
    cipher_message.append(des_key_encrypted)

    # sha-1生成消息认证码
    sha1_hash = sha1.sha1(des_cipher)

    # rsa对消息认证码数字签名
    signed_hash = rsa.rsa_encrypt(sha1_hash, rsa_d, rsa_n)
    cipher_message.append(signed_hash)

    # 将消息密文，RSA加密的对称密钥，数字签名后的sha-1消息认证码发送给接收端程序
    sender(','.join(cipher_message).encode())
    print('\nSent messages:\n' + ','.join(cipher_message))


if __name__ == "__main__":
    main()