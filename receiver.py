import socket,sys, binascii
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


def receiver():
    # 设置接收端端口
    address = ('127.0.0.1', 6666)

    # 建立接收端
    try:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Receiving terminal start!")
    except socket.error as msg:
        print("Socket failed. Error code: " + str(msg[0]) + ", Error message: " + msg[1])
        sys.exit()

    # 绑定监听
    try:
        receiver.bind(address)
        print("Binding port succeed!")
    except socket.error as msg:
        print("Bind failed. Error code: " + str(msg[0]) + ", Error message: " + msg[1])
        sys.exit()

    # 设置连接数为 1
    receiver.listen(1)

    # 接收连接,读取数据
    while True:
        connect, address = receiver.accept()
        data = connect.recv(4096)
        print('\nReceived messages:\n' + data.decode())
        if not data:
            break
        connect.sendall(b'Receiver: messages have received!')
        return data.decode()

    # 断开连接
    connect.close()
    receiver.close()


# 接收密文，并解密消息
def main():
    # 获取消息
    cipher_message = receiver().split(',')
    des_cipher = cipher_message[0]
    des_key_encrypted = cipher_message[1]
    signed_hash = cipher_message[2]

    # 获取rsa公钥、私钥
    rsa_d = int(read_message('./receiver/rsa_d.txt'), 16)
    rsa_n = int(read_message('./receiver/rsa_n.txt'), 16)
    rsa_e = int(read_message('./receiver/rsa_e.txt'), 16)

    # 解密消息签名
    hash_decrypted = rsa.rsa_decrypt(signed_hash, rsa_e, rsa_n)

    # 验证消息签名
    if hash_decrypted == sha1.sha1(des_cipher):
        print('\n消息签名验证成功，加密数据完整！')
    else:
        print('\n消息签名验证失败，加密数据不完整！')

    # 解密对称密钥
    des_key = rsa.rsa_decrypt(des_key_encrypted, rsa_d, rsa_n)

    # 解密密文
    msg = des.ECB_decrypt(des_cipher, des_key)

    # 将16进制密文转化为ASCII码
    msg = binascii.unhexlify(msg).decode()
    print('\nDecrypted messages: \n' + msg)


if __name__ == "__main__":
    main()