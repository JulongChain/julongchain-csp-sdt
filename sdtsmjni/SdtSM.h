/******************************************************
file_name		 :  SdtSM.h												
auther			 ：
description      :  sm算法调用接口库头文件
others			 ：  none
modification：
				  2018-04-27	created this file
						
******************************************************/
#ifndef __SDTSM_H_
#define __SDTSM_H_

#define ERR_OK          0x0000
#define ERR_BASE        0x1000

#define ERR_PARAM           (ERR_BASE+0x0001)
#define ERR_ECC_MAKEKEY     (ERR_BASE+0x0002)
#define ERR_ECC_SIGN        (ERR_BASE+0x0003)
#define ERR_ECC_VERIFY      (ERR_BASE+0x0004)
#define ERR_ECC_ENC         (ERR_BASE+0x0005)
#define ERR_ECC_DEC         (ERR_BASE+0x0006)
#define ERR_SYMM_ECB_ENC    (ERR_BASE+0x0007)
#define ERR_SYMM_ECB_DEC    (ERR_BASE+0x0008)
#define ERR_SYMM_CBC_ENC    (ERR_BASE+0x0009)
#define ERR_SYMM_CBC_DEC    (ERR_BASE+0x000A)


#ifdef __cplusplus
extern "C" {
#endif


/***************************************************
* function          	: sdt_random_gen
* description	        : 生成随机数
* parameters:
	-- data[out]		: 随机数
	-- data_len[in]	    : 随机数长度(最大为1024)
	
* return 		        : 0--success; 
			              非0--error code					
***************************************************/
int sdt_random_gen(unsigned char *data, unsigned int data_len);


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
int sdt_ecc_makekey(unsigned char *sk, unsigned int sk_len, \
                              unsigned char *pk, unsigned int *pk_len);


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
int sdt_ecc_sign(unsigned char *hash, unsigned int hash_len, \
					unsigned char *random, unsigned int random_len, \
                    unsigned char *sk, unsigned int sk_len, \
                    unsigned char *sign, unsigned int *sign_len);


/***************************************************
* function				: sdt_ecc_verify
* description			: ECC验签
* parameters:
	-- hash[in] 		: 数据哈希值
	-- hash_len[in] 	: 数据哈希值长度
	-- sk[in]			: 私钥
	-- sk_len[in]		: 私钥长度
	-- sign[in]		    : 签名值
	-- sign_len[in]	    : 签名值长度					
						
* return				: 0--success; 
                         非0--error code					
***************************************************/
int sdt_ecc_verify(unsigned char *hash, unsigned int hash_len, \
					   unsigned char *pk, unsigned int pk_len, \
					   unsigned char *sign, unsigned int sign_len);

/***************************************************
* function				    : sdt_ecc_encrypt
* description			    : ECC加密
* parameters:
	-- plain_data[in] 	    : 数据明文
	-- plain_data_len[in] 	: 数据明文长度
	-- random[in]		    : 随机数
    -- random_len[in]	    : 随机数长度
	-- pk[in]			    : 公钥
	-- pk_len[in]		    : 公钥长度
	-- cipher_data[out]		: 数据密文
	-- cipher_data_len[out]	: 数据密文长度					
						
* return				: 0--success; 
                         非0--error code					
***************************************************/
int sdt_ecc_encrypt(unsigned char *plain_data, unsigned int plain_data_len, \
				unsigned char *random, unsigned int random_len, \
				unsigned char *pk, unsigned int pk_len, \
				unsigned char *cipher_data, unsigned int *cipher_data_len);

/***************************************************
* function				: sdt_ecc_decrypt
* description			: ECC解密
* parameters:
	-- cipher_data[in] 	    : 数据密文
	-- cipher_data_len[in] 	: 数据密文长度
	-- sk[in]			    : 公钥
	-- sk_len[in]		    : 公钥长度
	-- plain_data[out]		: 数据明文
	-- plain_data_len[out]	: 数据明文长度					
						
* return				: 0--success; 
                         非0--error code						
***************************************************/
int sdt_ecc_decrypt(unsigned char *cipher_data, unsigned int cipher_data_len, \
				unsigned char *sk, unsigned int sk_len, \
				unsigned char *plain_data, unsigned int *plain_data_len);


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
int sdt_kdf(unsigned char *data, unsigned int data_len, \
				unsigned int key_len, unsigned char *key);


/***************************************************
* function 			    : sdt_hash
* description			: 计算Hash
* parameters:
	-- data[in]		    : 数据									
	-- data_len[in]     : 数据长度											
	-- hash[out]	    : 哈希值
	-- hash_len[out]    : 哈希值长度						
																		
* return				: 0--success; 
***************************************************/
int sdt_hash(unsigned char *data, unsigned int data_len, \
				unsigned char *hash, unsigned int *hash_len);

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
int sdt_symm_ecb_enc(unsigned char *key,  unsigned int key_len, \
						unsigned char *plain_data, unsigned int data_len, \
						unsigned char *cipher_data);

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
int sdt_symm_ecb_dec(unsigned char *key,  unsigned int key_len, \
						unsigned char *cipher_data, unsigned int data_len, \
						unsigned char *plain_data);


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
int sdt_symm_cbc_enc(unsigned char *key,  unsigned int key_len, \
                     unsigned char *iv, unsigned int iv_len, \
                     unsigned char *plain_data, unsigned int data_len, \
                     unsigned char *cipher_data);


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
int sdt_symm_cbc_dec(unsigned char *key,  unsigned int key_len, \
                     unsigned char *iv, unsigned int iv_len, \
                     unsigned char *cipher_data, unsigned int data_len, \
                     unsigned char *plain_data);


#ifdef __cplusplus
  }
#endif

#endif

