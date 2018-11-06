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
  * SM4.h
  * SM4算法接口定义
  *
  * @date 2018/10/18
  * @company SDT (兴唐通信科技有限公司)
  */

#ifndef _SM4_H_H_
#define _SM4_H_H_


#ifdef __cplusplus
extern "C" {
#endif

/***************************************************
* function			    : SM4_EncECB
* description		    : SM4 ECB模式加密
* parameters:
	-- key[in]		    : 密钥
	-- plain_text[in]   : 明文数据
	-- cipher_text[out] : 密文数据
	-- len[in]          : 数据长度

* return 			    : void
***************************************************/
void SM4_EncECB(unsigned char *key, unsigned char *plain_text, unsigned char *cipher_text, int len);

/***************************************************
* function			    : SM4_DecECB
* description		    : SM4 ECB模式解密
* parameters:
	-- key[in]		    : 密钥
	-- cipher_text[in]  : 密文数据
	-- plain_text[out]  : 明文数据
	-- len[in]          : 数据长度

* return 			    : void
***************************************************/
void SM4_DecECB(unsigned char *key,  unsigned char *cipher_text, unsigned char *plain_text, int len);

/***************************************************
* function			    : SM4_EncCBC
* description		    : SM4 CBC模式加密
* parameters:
	-- key[in]		    : 密钥
	-- iv[in]		    : IV
	-- plain_text[in]   : 明文数据
	-- cipher_text[out] : 密文数据
	-- len[in]          : 数据长度

* return 			    : void
***************************************************/
void SM4_EncCBC(unsigned char *key, unsigned char *iv, unsigned char *plain_text, unsigned char *cipher_text, int len);

/***************************************************
* function			    : SM4_DecCBC
* description		    : SM4 CBC模式解密
* parameters:
	-- key[in]		    : 密钥
	-- iv[in]		    : IV
	-- cipher_text[in]  : 密文数据
	-- plain_text[out]  : 明文数据
	-- len[in]          : 数据长度

* return 			    : void
***************************************************/
void SM4_DecCBC(unsigned char *key, unsigned char *iv, unsigned char *cipher_text, unsigned char *plain_text, int len);

#ifdef __cplusplus
}
#endif

#endif