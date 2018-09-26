## 项目介绍
本项目为聚龙链（JulongChain）平台提供国密算法接口。

## 支持算法
- SM2(GM/T 0003-2012): 签名、验签、加密、解密。
- SM3(GM/T 0004-2012): 哈希。
- SM4(GM/T 0002-2012): ECB和CBC模式的加密、解密。

## 编译说明
1. 从GitLab下载项目源码，下载地址为http://gitlab.bcia.net.cn:6060/bcia/julongchain-csp-sdt.git；
2. 在Linux系统(推荐使用ubuntu16.04, 内核版本4.4.0, gcc版本为5.4.0),源码所在目录中执行如下命令：
   ```sh
   $ make
   ```