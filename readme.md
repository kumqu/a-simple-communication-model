# 依赖：
  Python3.6
  pip install socket

# 用法：
  1. 先运行receiver.py程序。
  2. 再运行sender.py程序。
  3. 得到测试结果，并与sender目录下的message.txt内容进行比对，检验正确性。
  4. 修改sender目录下的messages.txt文件内容（ASCII码字符），可以多次测试得到相应的正确测试结果。

# 项目文件
  receiver.py 消息接收端程序
  sender.py   消息发送端程序
  des.py      实现的des算法
  rsa.py      实现的rsa算法
  sha1.py     实现的sha-1算法
    
  receiver/            接收端随机生成的RSA公钥和私钥文件（默认为25位16进制数），用于消息加密和数字签名
  sender/des_key.txt   对称加密密钥，用于加密明文文件
  sender/messages.txt  发送端发送的明文文件
  
# 实现原理
  1. 消息接收端和发送端建立连接，生成连接确认信息
  2. 接收端生成rsa公钥和私钥，将公钥发送给接收端(文件中读取）
  3. 发送端使用des的ECB模式加密消息(messages.txt),rsa公钥加密对称密钥（des_key),使用sha-1算法生成消息认证码，rsa私钥对消息认证码进行数字签名；
     将消息密文，RSA加密的对称密钥，数字签名后的sha-1消息认证码发送给接收端程序
  4. 接收端收到加密消息返回确认消息给发送端；接收端计算消息认证码确认消息的完整性；最后将对称密钥和密文进行解密，得到最终解密的明文信息
  
  
  
