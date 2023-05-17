# 简介

感谢[RELIC](https://github.com/relic-toolkit/relic)与[GmSSL](https://github.com/guanzhi/GmSSL)。

RELIC-SM9是一种支持SM9标识密码算法的高性能开源密码学库，其支持

- SM9数字签名算法，包括数字签名生成算法与数字签名验证算法
- SM9密钥交换协议
- SM9密钥封装机制，包括密钥封装算法与解封装算法
- SM9公钥加密算法，包括加密算法与解密算法



# 安装说明

## 环境

Linux

gcc



## 文件结构

主要文件如下

```tex
relic-SM9/
├── src/
│   ├── gmssl/
│   │   ├── sm3.c             //辅助函数 
│   │   ├── sm3_hmac.c        //辅助函数
│   │   └── sm3_kdf.c         //辅助函数
│   └── sm9.c                 //底层代码
├── test/
│   ├── debug.h               //性能测试代码
│   ├── test_sm9.c            //各项子功能测试与性能测试
│   ├── test_sm9_sign.c       //签名、验签算法示例
│   ├── test_sm9.kem.c  	  //封装、解封装算法示例
│   ├── test_sm9_encrypt.c    //加密、解密算法示例
│   ├── test_sm9_dh.c         //密钥交换示例
│   ├── test_sm9_server.c     //服务器端接口
│   ├── test_sm9_client.c     //客户端接口
│   ├── CMakeLists.txt        //配置文件
├── LICENSE                   //Apache-2.0
├── run.sh                    //下载后执行该文件
└── README-cn.md              //你在这里
```





## 下载与初次运行

```shell
git clone https://github.com/Madeep2000/relic_SM9.git
cd relic_SM9
./run.sh
```





# 使用示例

## 使用帮助

```shell
cd build/bin
./test_sm9_server -h
#./test_sm9_client -h
```

## 服务器端

密钥生成中心(key generation center, KGC)是负责选择系统参数、生成主密钥并产生用户私钥的可信机构，在此视作服务器的角色。

### 主密钥对生成

如果想生成一对签名主密钥，有：

```shell
#just an example
./test_sm9_server --setup --alg=sign --outfile=masterpub.bin --outkey=masterkey.bin -t
```

其中

- ```--setup```表明当前功能切换为：主密钥对的生成，
- ```--alg```表明生成的密钥类型，请填入"sign"或"enc"其中之一，
- ```--outfile```填输出的主公钥路径，输出二进制文件，对后缀名不敏感，
- ```--outkey```填输出的主私钥路径，输出二进制文件，对后缀名不敏感，
- 可选项``` -t ```表示以文本形式打印出主密钥对。



### 用户私钥生成

如果想生成用户签名私钥，有：

```shell
#just an example
./test_sm9_server --keygen --alg=sign --user-id=Alice --inkey=masterkey.bin --outkey=alicekey.abc -t
```

其中

- ```--keygen```表明当前功能切换为：用户密钥的生成，
- ```--alg```表明生成的密钥类型，请填入"sign"或"enc"其中之一，
- ```--user-id```填输入的用户标识值，请以文本形式输入，
- ```--inkey```填输入的主私钥路径，输入视作二进制文件，对后缀名不敏感，
- ```--outkey```填输出的用户私钥路径，输出二进制文件，对后缀名不敏感，
- 可选项``` -t ```表示以文本形式打印出用户私钥。



## 客户端

使用SM9标识密码算法进行数字签名与验签、密钥交换、密钥封装与解封装、公钥加密与解密等操作的用户在此视作客户端。

在使用``` ./test_sm9_client```之前请确保你已持有用户标识、用户私钥、主公钥，后两者生成自``` ./test_sm9_server```

如果想加密一份文件，有：

```shell
./test_sm9_client --enc --user-id=Bob --master-pub=masterpub.bin --infile=message.bin --outfile=cipher.bin -t
```

其中

- ```--enc```表明当前功能切换为：加密；其他功能详见使用帮助，
- ```--user-id```填输入的用户标识值，请以文本形式输入，
- ```--master-pub```填输入的主公钥路径，输入视作二进制文件，对后缀名不敏感，
- ```--infile```填欲加密的文件路径，输入视作二进制文件，对后缀名不敏感，
- ```--outfile```填输出的密文路径，输出二进制文件，对后缀名不敏感，
- 可选项``` -t ```表示以文本形式打印出明文和密文。

如果想解密一份文件，有：

```shell
./test_sm9_client --dec --user-id=Bob --user-key=userkey.bin --infile=cipher.bin --outfile=plaintext.bin -t
```

其中

- ```--dec```表明当前功能切换为：解密；其他功能详见使用帮助，
- ```--user-id```填输入的用户标识值，请以文本形式输入，
- ```--user-key```填输入的用户私钥路径，输入视作二进制文件，对后缀名不敏感，
- ```--infile```填欲解密的文件路径，输入视作二进制文件，对后缀名不敏感，
- ```--outfile```填输出的明文路径，输出二进制文件，对后缀名不敏感，
- 可选项``` -t ```表示以文本形式打印出密文和明文。



# 许可

Apache-2.0



# 联系信息

mdlw@m.scnu.edu.cn

