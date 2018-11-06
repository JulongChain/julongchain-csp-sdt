/**
 * Copyright SDT. All Rights Reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 /**
  * SM2.h
  * SM2算法接口定义
  *
  * @date 2018/10/18
  * @company SDT (兴唐通信科技有限公司)
  */

#ifndef _SM2__H_
#define _SM2_H_ 

// 一般操作数的长度(长字个数)
#define DIG_LEN 8

typedef unsigned int small;
typedef small *big;

// ECC数据结构体
typedef struct 
{
    small  x[DIG_LEN];
    small  y[DIG_LEN];
} affpoint;

typedef affpoint *epoint;

// 点结构体
typedef struct 
{
        small  x[DIG_LEN];
        small  y[DIG_LEN];
		small  z[DIG_LEN];
} projpoint;

typedef projpoint *point;

/***************************************************
* function			   : KDF
* description		   : KDF函数
* parameters:
	-- data[in]		   : 数据
	-- data_len[in]	   : 数据长度
	-- key_len[in]	   : 密钥长度
	-- key[out]		   : 密钥

* return 			   : 0--success;
						 非0--error code
***************************************************/
void KDF(unsigned char *data, unsigned int data_len, unsigned int key_len,unsigned char *key);

/***************************************************
* function          	: EccMakeKey
* description	        : ECC公/私钥生成接口函数
* parameters:
	-- sk[in]	        : 私钥
	-- sk_len[in]       : 私钥长度
	-- type[in]         : 曲线类型
    -- pk[out]			: 公钥
    -- pk_len[out]		: 公钥长度

* return 		        : 0--success;
			              非0--error code
***************************************************/
int EccMakeKey(unsigned char *sk, unsigned int sk_len, 
			   unsigned char *pk, unsigned int *pk_len, int type);

/***************************************************
* function          	: EccSign
* description	        : ECC签名生成接口函数
* parameters:
	-- hash[in]	        : 数据哈希值
	-- hash_len[in]     : 数据哈希值长度
    -- random[in]		: 随机数
    -- random_len[in]	: 随机数长度
    -- sk[in]	        : 私钥
	-- sk_len[in]       : 私钥长度
	-- sign[out]	    : 签名值
	-- sign_len[out]    : 签名值长度

* return 		        : 0--success;
			              非0--error code
***************************************************/
int EccSign(unsigned char *hash, unsigned int hash_len, 
			unsigned char *random, unsigned int random_len, 
			unsigned char *sk, unsigned int sk_len, 
			unsigned char *sign, unsigned int *sign_len);

/***************************************************
* function				: EccVerify
* description			: ECC签名验证接口函数
* parameters:
	-- hash[in] 		: 数据哈希值
	-- hash_len[in] 	: 数据哈希值长度
	-- pk[in]			: 公钥
	-- pk_len[in]		: 公钥长度
	-- sign[in]		    : 签名值
	-- sign_len[in]	    : 签名值长度

* return				: 0--success;
                         非0--error code
***************************************************/
int EccVerify(unsigned char *hash, unsigned int hash_len, 
			  unsigned char *pk, unsigned int pk_len, 
			  unsigned char *sign, unsigned int sign_len);

/***************************************************
* function				    : EccEncrypt
* description			    : ECC加密接口函数
* parameters:
	-- plain[in] 	        : 明文数据
	-- plain_len[in] 	    : 明文数据长度
	-- random[in]		    : 随机数
    -- random_len[in]	    : 随机数长度
	-- pk[in]			    : 公钥
	-- pk_len[in]		    : 公钥长度
	-- cipher[out]		    : 密文数据
	-- cipher_len[out]	    : 密文数据长度 (cipher_len = plain_len+96)

* return				: 0--success;
                         非0--error code
***************************************************/
int EccEncrypt(unsigned char *plain, unsigned int plain_len, 
			   unsigned char *random, unsigned int random_len, 
			   unsigned char *pk, unsigned int pk_len, 
			   unsigned char *cipher, unsigned int *cipher_len);

/***************************************************
* function				: sdt_ecc_decrypt
* description			: ECC解密接口函数
* parameters:
	-- cipher[in] 	    : 密文数据
	-- cipher_len[in] 	: 密文数据长度
	-- sk[in]			: 私钥
	-- sk_len[in]		: 私钥长度
	-- plain[out]		: 明文数据
	-- plain_len[out]	: 明文数据长度 (plain_len = cipher_len-96)

* return				: 0--success;
                         非0--error code
***************************************************/
int EccDecrypt(unsigned char *cipher, unsigned int cipher_len, 
			   unsigned char *sk, unsigned int sk_len, 
			   unsigned char *plain, unsigned int *plain_len);


#endif

