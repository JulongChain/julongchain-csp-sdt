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
  * SM3.h
  * SM3算法接口定义
  *
  * @date 2018/10/18
  * @company SDT (兴唐通信科技有限公司)
  */

#ifndef _SM3_H_H_
#define _SM3_H_H_

typedef unsigned char U8;
typedef unsigned int  U32;

typedef struct
{
	U32 IV[8];
	U8  m[64];
	U32 len;
} SM3_state;

#ifdef __cpluscplus
extern "C" {
#endif

/***************************************************
* function			   : SM3_Init
* description		   : 哈希初始化
* parameters:
	-- ctx[out]		   : 哈希上下文

* return 			   : void
***************************************************/
void SM3_Init(SM3_state *ctx);

/***************************************************
* function			   : SM3_Update
* description		   : 哈希更新
* parameters:
	-- ctx[in]		   : 哈希上下文
	-- data[in]	       : 数据长度
	-- data_len[in]    : 数据长度(字节数)

* return 			   : 0--success;
						 非0--error code
***************************************************/
int SM3_Update(SM3_state *ctx, const U8 *data, U32 data_len);

/***************************************************
* function			   : SM3_Final
* description		   : 哈希结束
* parameters:
	-- hash[out]	   : 哈希值
	-- hash_len[in]	   : 哈希值长度
	-- ctx[in]	       : 哈希上下文
	-- data_len[in]	   : 数据总长度

* return 			   : 0--success;
						 非0--error code
***************************************************/
int SM3_Final(U8 *hash, U32 hash_len, SM3_state *ctx, U32 data_len);

/***************************************************
* function			   : SM3_Hash
* description		   : 哈希函数
* parameters:
	-- msg[in]		   : 数据
	-- msg_len[in]	   : 数据长度
	-- hash[out]	   : 哈希值
	-- hash_len[in]    : 哈希值长度

* return 			   : 0--success;
						 非0--error code
***************************************************/
int SM3_Hash(U8 *msg, U32 msg_len, U8 *hash, U32 hash_len);

/***************************************************
* function			   : SM3_HASH
* description		   : 哈希函数
* parameters:
	-- msg[in]		   : 数据
	-- msg_len[in]	   : 数据长度
	-- all_len[in]	   : 数据总长度
	-- hash[out]	   : 哈希值
    -- hash_len[in]    : 哈希值长度
    -- flag[in]        : 标识

* return 			   : 0--success;
						 非0--error code
***************************************************/
int SM3_HASH(U8 *msg, U32 msg_len, U32 all_len,
				U8 *hash, U32 hash_len, U32 flag);


#ifdef __cpluscplus
}
#endif

#endif

