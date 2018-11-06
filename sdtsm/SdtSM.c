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
  * SdtSM.c
  * 国密算法接口实现
  *
  * @date 2018/10/18
  * @company SDT (兴唐通信科技有限公司)
  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#include "SdtSM.h"
#include "SM2.h"
#include "SM3.h"
#include "SM4.h"

#define SDT_MAX_RANDOM_LEN      1024
#define SDT_MAX_DERIVEKEY_LEN   1024
#define SDT_MAX_PACKAGE_LEN     2048

#define SDT_HASH_SECTION_LEN    512
#define SDT_ECC_SK_LEN          32
#define SDT_ECC_PK_LEN          64
#define SDT_ECC_SING_LEN        64
#define SDT_ECC_RANDOM_LEN      32
#define SDT_ECC_PADDING_LEN     96
#define SDT_HASH_LEN            32
#define SDT_MAX_KDFZ_LEN        384
#define SDT_SYMM_KEY_LEN        16
#define SDT_SYMM_IV_LEN         16
#define SDT_SYMM_BLOCK_LEN      16

#define SDT_MAX_INT             0xFFFFFFFF

#define URANDOM_FILE_NAME  "/dev/urandom"

/***************************************************
* function          	: init_random
* description	        : 设置随机数种子
* parameters            : 无
* return 		        : 0--success;
			              非0--error code
***************************************************/
void init_random()
{
	unsigned int ticks = 0;
	int fd = 0;
	struct timeval tv;
	gettimeofday (&tv, NULL);
	ticks = tv.tv_sec + tv.tv_usec;
	fd = open(URANDOM_FILE_NAME, O_RDONLY);
	if (fd > 0)
    {
		unsigned int r;
		int i;
		for(i = 0; i < 512; i++)
        {
			read (fd, &r, sizeof(r));
			ticks += r;
        }
		close(fd);
    }
  	srandom(ticks);
}

/***************************************************
* function          	: sdt_random_gen
* description	        : 生成随机数
* parameters:
    -- data_len[in]	    : 随机数长度(最大为1024)
	-- data[out]		: 随机数

* return 		        : 0--success;
			              非0--error code
***************************************************/
int sdt_random_gen(unsigned char *data, unsigned int data_len)
{
	unsigned int *plRand = NULL;
	unsigned int *pcRand = NULL;
	int randLongLen = 0;
	int randCharLen = 0;
	// 参数检查
	if(NULL == data || 0 == data_len || SDT_MAX_RANDOM_LEN < data_len)
	{
		return ERR_PARAM;
	}
	
	init_random();
		
	randLongLen = data_len/sizeof(int);
	randCharLen = data_len%sizeof(int);
	plRand = (unsigned int *)data;
	pcRand = (unsigned int *)data+randLongLen;
	while(randLongLen-- > 0)
	{	
		*plRand++ = random() & SDT_MAX_INT;
	}
	if(randCharLen)
	{
		int tmp = random() & SDT_MAX_INT;
		memcpy(pcRand, &tmp, randCharLen);
	}
	return ERR_OK;
}

/***************************************************
* function          	: sdt_ecc_makekey
* description	        : 生成SM2公钥
* parameters:
	-- sk[in]	        : 私钥
	-- sk_len[in]       : 私钥长度
    -- pk[out]			: 公钥
    -- pk_len[out]		: 公钥长度

* return 		        : 0--success;
			              非0--error code
***************************************************/
int sdt_ecc_makekey(unsigned char *sk, unsigned int sk_len, 
                              unsigned char *pk, unsigned int *pk_len)
{
	// 参数检查
	if(NULL == sk || SDT_ECC_SK_LEN != sk_len \
		|| NULL == pk || SDT_ECC_PK_LEN > *pk_len)
	{
		return ERR_PARAM;
	}
	// 生成公钥
	int ret = EccMakeKey(sk, SDT_ECC_SK_LEN, pk, pk_len, 0);
	if(ret != 0)
	{
		return ERR_ECC_MAKEKEY;
	}
	return ERR_OK;
}

/***************************************************
* function          	: sdt_ecc_sign
* description	        : ECC签名
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
int sdt_ecc_sign(unsigned char *hash, unsigned int hash_len, 
				 unsigned char *random, unsigned int random_len,
                 unsigned char *sk, unsigned int sk_len, 
                 unsigned char *sign, unsigned int *sign_len)
{
	// 参数检查
	if(NULL == hash || SDT_HASH_LEN != hash_len \
		|| NULL == random || SDT_ECC_RANDOM_LEN != random_len \
		|| NULL == sk || SDT_ECC_SK_LEN != sk_len \
		|| NULL == sign)
	{
		return ERR_PARAM;
	}
	int ret = 1;
    // 签名
	ret = EccSign(hash, hash_len, random, random_len, sk, sk_len, sign, sign_len);
	if(ret != 0)
	{
		return ERR_ECC_SIGN;
	}
	return ERR_OK;
}

/***************************************************
* function				: sdt_ecc_verify
* description			: ECC验签
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
int sdt_ecc_verify(unsigned char *hash, unsigned int hash_len, 
			 unsigned char *pk, unsigned int pk_len, 
			 unsigned char *sign, unsigned int sign_len)
{
	// 参数检查
	if(NULL == hash || SDT_HASH_LEN != hash_len \
		|| NULL == pk || SDT_ECC_PK_LEN != pk_len \
		|| NULL == sign || SDT_ECC_SING_LEN != sign_len)
	{
		return ERR_PARAM;
	}
	int ret = 1;
	// 验签
	ret = EccVerify(hash, hash_len, pk, pk_len, sign, sign_len);
	if(ret != 0)
	{
		return ERR_ECC_VERIFY;
	}
	return ERR_OK;
}

/***************************************************
* function				    : sdt_ecc_encrypt
* description			    : ECC加密
* parameters:
	-- plain_data[in] 	    : 明文数据
	-- plain_data_len[in] 	: 明文数据长度
	-- random[in]		    : 随机数
    -- random_len[in]	    : 随机数长度
	-- pk[in]			    : 公钥
	-- pk_len[in]		    : 公钥长度
	-- cipher_data[out]		: 密文数据
	-- cipher_data_len[out]	: 密文数据长度

* return				: 0--success;
                         非0--error code
***************************************************/
int sdt_ecc_encrypt(unsigned char *plain_data, unsigned int plain_data_len,
					unsigned char *random, unsigned int random_len, 
					unsigned char *pk, unsigned int pk_len,
					unsigned char *cipher_data, unsigned int *cipher_data_len)
{
	// 参数检查
	if(NULL == plain_data || 0 == plain_data_len \
		|| SDT_MAX_PACKAGE_LEN < plain_data_len \
		|| NULL == random || SDT_ECC_RANDOM_LEN != random_len \
		|| NULL == pk || SDT_ECC_PK_LEN != pk_len \
		|| NULL == cipher_data || (plain_data_len+SDT_ECC_PADDING_LEN) > *cipher_data_len)
	{
		return ERR_PARAM;
	}
	int ret = 1;
	// ECC加密
	ret = EccEncrypt(plain_data, plain_data_len, random, random_len, pk, pk_len, cipher_data, cipher_data_len);
	if(ret != 0)
	{
		return ERR_ECC_ENC;	
	}
	return ERR_OK;	
}

/***************************************************
* function				: sdt_ecc_decrypt
* description			: ECC解密
* parameters:
	-- cipher_data[in] 	    : 密文数据
	-- cipher_data_len[in] 	: 密文数据长度
	-- sk[in]			    : 私钥
	-- sk_len[in]		    : 私钥长度
	-- plain_data[out]		: 明文数据
	-- plain_data_len[out]	: 明文数据长度

* return				: 0--success;
                         非0--error code
***************************************************/
int sdt_ecc_decrypt(unsigned char *cipher_data, unsigned int cipher_data_len, 
					unsigned char *sk, unsigned int sk_len, 
					unsigned char *plain_data, unsigned int *plain_data_len)
{
	// 参数检查
	if(NULL == cipher_data || 0 == cipher_data_len \
		|| SDT_MAX_PACKAGE_LEN < cipher_data_len \
		|| NULL == sk || SDT_ECC_SK_LEN != sk_len \
		|| NULL == plain_data || (cipher_data_len-SDT_ECC_PADDING_LEN) > *plain_data_len)
	{
		return ERR_PARAM;
	}
	int ret = 1;
	// ECC解密
	ret = EccDecrypt(cipher_data, cipher_data_len, sk, sk_len, plain_data, plain_data_len);
	if(ret != 0)
	{
		return ERR_ECC_DEC;	
	}
	return ERR_OK;	
}

/***************************************************
* function			   : sdt_kdf
* description		   : KDF
* parameters:
	-- data[in]		   : 数据
	-- data_len[in]	   : 数据长度(最大为384)
	-- key[out]		   : 密钥
	-- key_len[in]	   : 密钥长度

* return 			   : 0--success;
						 非0--error code
***************************************************/
int sdt_kdf(unsigned char *data, unsigned int data_len, 
			unsigned int key_len, unsigned char *key)
{
	// 参数检查
	if(NULL == data || SDT_MAX_KDFZ_LEN < data_len \
		|| 0 == data_len || NULL == key \
		|| 0 == key_len || SDT_MAX_DERIVEKEY_LEN < key_len)
	{
		return ERR_PARAM;
	}
	// KDF
	KDF(data, data_len, key_len, key);
	return ERR_OK;	
}

/***************************************************
* function 			    : sdt_hash
* description			: SM3哈希
* parameters:
	-- data[in]		    : 数据
	-- data_len[in]     : 数据长度
	-- hash[out]	    : 哈希值
	-- hash_len[out]    : 哈希值长度

* return				: 0--success;
***************************************************/
int sdt_hash(unsigned char *data, unsigned int data_len,
				unsigned char *hash, unsigned int *hash_len)
{
    // 参数检查
	if(NULL == data || 0 == data_len \
		|| NULL == hash || SDT_HASH_LEN > *hash_len)
	{
		return ERR_PARAM;
	}
	SM3_state state;
	memset(&state, 0, sizeof(SM3_state));
	// 哈希Init
	SM3_Init(&state);
	int leftLen = data_len;
	while(leftLen > 0)
	{
		int len = leftLen;
		if(len > SDT_HASH_SECTION_LEN)
		{
			len = SDT_HASH_SECTION_LEN;
		}
		// 哈希Update
		SM3_Update(&state, data+(data_len-leftLen), len);
		leftLen = leftLen-len;
	}
	// 哈希Final
	SM3_Final(hash, SDT_HASH_LEN, &state, data_len);
	*hash_len = SDT_HASH_LEN;
	return ERR_OK;	
}

/***************************************************
* function					 : sdt_symm_ecb_enc
* description				 : ECB模式对称加密
* parameters:
	-- key[in]				 : 密钥
	-- key_len[in]			 : 密钥长度
	-- plain_data[in]		 : 明文数据
	-- data_len[in]          : 数据长度
	-- cipher_data[out] 	 : 密文数据

* return			   : 0--success;
						非0--error code
***************************************************/
int sdt_symm_ecb_enc(unsigned char *key,  unsigned int key_len,
						unsigned char *plain_data, unsigned int data_len,
						unsigned char *cipher_data)
{
    // 参数检查
	if (NULL == key || SDT_SYMM_KEY_LEN != key_len \
		|| NULL == plain_data || 0 == data_len \
		|| SDT_MAX_PACKAGE_LEN < data_len \
		|| 0 != data_len%SDT_SYMM_BLOCK_LEN || NULL == cipher_data)
	{
		return ERR_PARAM;
	}
	// ECB加密
	SM4_EncECB(key, plain_data, cipher_data, data_len);
	return ERR_OK;
}

/***************************************************
* function					 : sdt_symm_ecb_dec
* description				 : ECB模式对称解密
* parameters:
	-- key[in]				 : 密钥
	-- key_len[in]			 : 密钥长度
	-- cipher_data[in]		 : 密文数据
	-- data_len[in]          : 数据长度
	-- plain_data[out] 	     : 明文数据

* return			   : 0--success;
						非0--error code
***************************************************/
int sdt_symm_ecb_dec(unsigned char *key,  unsigned int key_len,
						unsigned char *cipher_data, unsigned int data_len,
						unsigned char *plain_data)
{
    // 参数检查
	if (NULL == key || SDT_SYMM_KEY_LEN != key_len \
		|| NULL == cipher_data || 0 == data_len \
		|| SDT_MAX_PACKAGE_LEN < data_len \
		|| 0 != data_len%SDT_SYMM_BLOCK_LEN || NULL == plain_data)
	{
		return ERR_PARAM;
	}
	// ECB解密
	SM4_DecECB(key, cipher_data, plain_data, data_len);
	return ERR_OK;
}

/***************************************************
* function			         : sdt_symm_cbc_enc
* description		         : CBC模式对称加密
* parameters:
	-- key[in]		         : 密钥
	-- key_len[in]		     : 密钥长度
	-- iv[in]	             : IV
	-- iv_len[in]	         : IV长度
	-- plain_data[in]        : 明文数据
	-- data_len[in]          : 数据长度
	-- cipher_data[out]      : 密文数据

* return 			   : 0--success;
						 非0--error code
 ***************************************************/
int sdt_symm_cbc_enc(unsigned char *key,  unsigned int key_len,
				unsigned char *iv, unsigned int iv_len,
				unsigned char *plain_data, unsigned int data_len,
				unsigned char *cipher_data)
{
    // 参数检查
	if (NULL == key || SDT_SYMM_KEY_LEN != key_len \
		|| NULL == iv || SDT_SYMM_IV_LEN != iv_len \
		|| NULL == plain_data || 0 == data_len \
		|| SDT_MAX_PACKAGE_LEN < data_len \
		|| 0 != data_len%SDT_SYMM_BLOCK_LEN || NULL == cipher_data)
	{
		return ERR_PARAM;
	}
	// CBC加密
	SM4_EncCBC(key, iv, plain_data, cipher_data, data_len);
	return ERR_OK;
}

/***************************************************
* function			         : sdt_symm_cbc_dec
* description		         : CBC模式对称解密
* parameters:
	-- key[in]		         : 密钥
	-- key_len[in]		     : 密钥长度
	-- iv[in]	             : IV
	-- iv_len[in]	         : IV长度
	-- cipher_data[in]       : 密文数据
	-- data_len[in]          : 数据长度
	-- plain_data[out]       : 明文数据

* return 			   : 0--success;
						 非0--error code
 ***************************************************/
int sdt_symm_cbc_dec(unsigned char *key,  unsigned int key_len,
					unsigned char *iv, unsigned int iv_len,
					unsigned char *cipher_data, unsigned int data_len,
					unsigned char *plain_data)
{
    // 参数检查
	if (NULL == key || SDT_SYMM_KEY_LEN != key_len \
		|| NULL == iv || SDT_SYMM_IV_LEN != iv_len \
		|| NULL == cipher_data || 0 == data_len \
		|| SDT_MAX_PACKAGE_LEN < data_len \
		|| 0 != data_len%SDT_SYMM_BLOCK_LEN || NULL == plain_data)
	{
		return ERR_PARAM;
	}
	// CBC解密
	SM4_DecCBC(key, iv, cipher_data, plain_data, data_len);
	return ERR_OK;
}
