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
  * SM2.c
  * SM2算法接口实现
  *
  * @date 2018/10/18
  * @company SDT (兴唐通信科技有限公司)
  */
#include "SM2.h"
#include "SM3.h"

// 以下是椭圆曲线的参数(little endian)，用外部变量存储

// GF(p)
#define M 256

// p = 2^256-2^224-2^96+2^64-1
const small P[DIG_LEN] = 
		{0xFFFFFFFF,0xFFFFFFFF,0x00000000,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE};
// a = -3
const small A[DIG_LEN] = 
		{0xFFFFFFFC,0xFFFFFFFF,0x00000000,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE};
// b
const small B[DIG_LEN] = 
		{0x4D940E93,0xDDBCBD41,0x15AB8F92,0xF39789F5,0xCF6509A7,0x4D5A9E4B,0x9D9F5E34,0x28E9FA9E};
// y^2 = x^3 +ax + b
const small N[DIG_LEN] = 
		{0x39D54123,0x53BBF409,0x21C6052B,0x7203DF6B,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE};
// G
const affpoint G = 
		{{0x334C74C7,0x715A4589,0xF2660BE1,0x8FE30BBF,0x6A39C994,0x5F990446,0x1F198119,0x32C4AE2C},
{0x2139F0A0,0x02DF32E5,0xC62A4740,0xD0A9877C,0x6B692153,0x59BDCEE3,0xF4F6779C,0xBC3736A2}};

#define LOHALF(x) ((small)((x) & 0xffff))
#define HIHALF(x) ((small)((x) >> 16 & 0xffff))
#define TOHIGH(x) ((small)((x) << 16))


int compare(big a, big b)
{
   int i;
   for(i=DIG_LEN-1; i>=0; i--)
   {
	  if(a[i] > b[i])
		  return 1;
	  else if(a[i] < b[i])
		  return 0;
   }
   return 1;
}

void add(big w, big u, big v)
{
	int i, flag;
	small sum, carry, borrow;

	carry = 0;
	for(i=0; i<DIG_LEN; i++)
	{											
		sum = u[i] + v[i] + carry;
		if(sum < u[i])
		{
			carry = 1;
		}
		else if(sum > u[i])
		{
			carry = 0;
		}
		w[i] = sum;						
	}

	flag = 0;
	i = DIG_LEN;		
	while(i--)
	{											
		if(w[i] > P[i])
		{
			flag = 1; 
			break;
		}
		else if(w[i] < P[i])
		{
			flag = -1; 
			break;
		}
	}

	if (carry==1 || flag>=0)
	{
		borrow = 0;
		for(i=0; i<DIG_LEN; i++)
		{											
			sum = w[i] - P[i] - borrow;	
			if(w[i] < P[i])
			{
				borrow = 1;	
			}
			else if(w[i] > P[i])
			{
				borrow = 0;	
			}
			w[i] = sum;						
		}
	}
}

void sub(big w, big u, big v)
{
	int i;
	small sum, carry, borrow;

	borrow = 0;
	for(i=0; i<DIG_LEN; i++)
	{											
		sum = u[i] - v[i] - borrow;	
		if(u[i] < v[i])
		{
			borrow = 1;
		}
		else if(u[i] > v[i])
		{
			borrow = 0;
		}
		w[i] = sum;						
	}

	if(borrow)
	{
		carry = 0;
		for(i=0; i<DIG_LEN; i++)
		{											
			sum = w[i] + P[i] + carry;	
			if(sum < w[i])
			{
				carry = 1;
			}
			else if(sum > w[i])
			{
				carry = 0;	
			}
			w[i] = sum;						
		}										
	}
}

void mod(big u, big v)
{	
	small w[DIG_LEN],carry, borrow, sum;
	int i, flag;

	carry = 0;
	u[0] = v[0] + v[8]; 
	if(u[0] <v [0])
	{
		carry++;
	}
	u[0] += v[9]; 
	if(u[0] < v[9])
	{
		carry++;
	}

    u[0] += v[10]; 
	if(u[0] < v[10])
	{
		carry++;
	}
	u[0] += v[11]; 
	if(u[0] < v[11])
	{
		carry++;
	}
	u[0] += v[12]; 
	if(u[0] < v[12])
	{
		carry++;
	}
	u[0] += v[13]; 
	if(u[0] < v[13])
	{
		carry++;
	}
	u[0] += v[13]; 
	if(u[0] < v[13])
	{
		carry++;
	}
	u[0] += v[14]; 
	if(u[0] < v[14])
	{
		carry++;
	}
	u[0] += v[14]; 
	if(u[0] < v[14])
	{
		carry++;
	}
	u[0] += v[15]; 
	if(u[0] < v[15])
	{
		carry++;
	}
	u[0] += v[15]; 
	if(u[0] < v[15])
	{
		carry++;
	}

	u[1] = v[1] + carry;
	carry = 0; 
	if(u[1] < v[1])
	{
		carry++;
	}
	u[1] += v[9]; 
	if(u[1] < v[9])
	{
		carry++;
	}
	u[1] += v[10]; 
	if(u[1] < v[10])
	{
		carry++;
	}

	u[1] += v[11]; 
	if(u[1] < v[11])
	{
		carry++;
	}
	u[1] += v[12]; 
	if(u[1] < v[12])
	{
		carry++;
	}
	u[1] += v[13]; 
	if(u[1] < v[13])
	{
		carry++;
	}
	u[1] += v[14]; 
	if(u[1] < v[14])
	{
		carry++;
	}
	u[1] += v[14]; 
	if(u[1] < v[14])
	{
		carry++;
	}
	u[1] += v[15]; 
	if(u[1] < v[15])
	{
		carry++;
	}
	u[1] += v[15]; 
	if(u[1] < v[15])
	{
		carry++;
	}
	u[2] = v[2] + carry;
	carry = 0;
	if(u[2] < v[2])
	{
		carry++;
	}
	w[3] = v[3] + carry;
	carry = 0; 
	if(w[3] < v[3])
	{
		carry++;
	}
	w[3] += v[8]; 
	if(w[3] < v[8])
	{
		carry++;
	}
	w[3] += v[11]; 
	if(w[3] < v[11])
	{
		carry++;
	}
	w[3] += v[12]; 
	if(w[3] < v[12])
	{
		carry++;
	}
	w[3] += v[13]; 
	if(w[3] < v[13])
	{
		carry++;
	}
	w[3] += v[13]; 
	if(w[3] < v[13])
	{
		carry++;
	}
	w[3] += v[14]; 
	if(w[3] < v[14])
	{
		carry++;
	}
	w[3] += v[15]; 
	if(w[3] < v[15])
	{
		carry++;
	}

	w[4] = v[4] + carry;
	carry = 0; 
	if(w[4] < v[4])
	{
		carry++;
	}
	w[4] += v[9]; 
	if(w[4] < v[9])
	{
		carry++;
	}
	w[4] += v[12]; 
	if(w[4] < v[12])
	{
		carry++;
	}
	w[4] += v[13]; 
	if(w[4] < v[13])
	{
		carry++;
	}
	w[4] += v[14]; 
	if(w[4] < v[14])
	{
		carry++;
	}
	w[4] += v[14]; 
	if(w[4] < v[14])
	{
		carry++;
	}
	w[4] += v[15]; 
	if(w[4] < v[15])
	{
		carry++;
	}

	w[5] = v[5] + carry;
	carry = 0; 
	if(w[5] < v[5])
	{
		carry++;
	}
	w[5] += v[10]; 
	if(w[5] < v[10])
	{
		carry++;
	}
	w[5] += v[13]; 
	if(w[5] < v[13])
	{
		carry++;
	}
	w[5] += v[14]; 
	if(w[5] < v[14])
	{
		carry++;
	}
	w[5] += v[15]; 
	if(w[5] < v[15])
	{
		carry++;
	}
	w[5] += v[15]; 
	if(w[5] < v[15])
	{
		carry++;
	}

	w[6] = v[6] + carry;
	carry = 0; 
	if(w[6] < v[6])
	{
		carry++;
	}
	w[6] += v[11]; 
	if(w[6] < v[11])
	{
		carry++;
	} 
	w[6] += v[14]; 
	if(w[6] < v[14])
	{
		carry++;
	}
	w[6] += v[15]; 
	if(w[6] < v[15])
	{
		carry++;
	}
	w[7] = v[7] + carry;
	carry = 0; 
	if(w[7] < v[7])
	{
		carry++;
	}
	w[7] += v[8]; 
	if(w[7] < v[8])
	{
		carry++;
	}
	w[7] += v[9]; 
	if(w[7] < v[9])
	{
		carry++;
	}
	w[7] += v[10]; 
	if(w[7] < v[10])
	{
		carry++;
	}
	w[7] += v[11]; 
	if(w[7] < v[11])
	{
		carry++;
	}
	w[7] += v[12]; 
	if(w[7] < v[12])
	{
		carry++;
	}
	w[7] += v[12]; 
	if(w[7] < v[12])
	{
		carry++;
	}
	w[7] += v[13]; 
	if(w[7] < v[13])
	{
		carry++;
	}
	w[7] += v[13]; 
	if(w[7] < v[13])
	{
		carry++;
	}
	w[7] += v[14]; 
	if(w[7] < v[14])
	{
		carry++;
	}
	w[7] += v[14]; 
	if(w[7] < v[14])
	{
		carry++;
	}
	w[7] += v[15]; 
	if(w[7] < v[15])
	{
		carry++;
	}
	w[7] += v[15]; 
	if(w[7] < v[15])
	{
		carry++;
	}
	w[7] += v[15]; 
	if(w[7] < v[15])
	{
		carry++;
	}	
	borrow=0;
	if(u[2] < v[8])
	{
		borrow++;
	}
	u[2] -= v[8];
	
	if(u[2] < v[9])
	{
		borrow++;
	}
	u[2] -= v[9];
	
	if(u[2] < v[13])
	{
		borrow++;
	}
	u[2] -= v[13];
	
	if(u[2] < v[14])
	{
		borrow++;
	}
    u[2] -= v[14];
	
	u[3] =w[3]-borrow;
	if(w[3] < borrow)
	{
		borrow=1;
	}
	else
	{
		borrow=0;
	}
	
	u[4]=w[4]-borrow;
	if(w[4] < borrow)
	{
		borrow=1;
	}
	else
	{
		borrow=0;
	}
	
	u[5]=w[5]-borrow;
	if(w[5] < borrow)
	{
		borrow=1;
	}
	else
	{
		borrow=0;
	}
	
	u[6]=w[6]-borrow;
	if(w[6] < borrow)
	{
		borrow=1;
	}
	else
	{
		borrow=0;
	}
	
	u[7]=w[7]-borrow;
	if(w[7] < borrow)
	{
		borrow=1;
	}
	else
	{
		borrow=0;
	}

	if(carry >= borrow)
	{
		carry -= borrow;
		while(carry != 0)
		{
			borrow = 0;
			for(i=0; i<DIG_LEN; i++)
			{											
				sum = u[i] - P[i] - borrow;	
				if(u[i] < P[i])
				{
					borrow = 1;	
				}
				else if(u[i] > P[i])
				{
					borrow = 0;	
				}
				u[i] = sum;						
			}
			carry = carry - borrow;
		}

		flag = 0;
		i = DIG_LEN;		
		while(i--)
		{											
			if(u[i] > P[i])
			{
				flag = 1; 
				break;
			}
			else if(u[i] < P[i])
			{
				flag = -1; 
				break;
			}
		}

		if(flag<0)
		{
			return;
		}
		else
		{
			borrow = 0;
			for(i=0; i<DIG_LEN; i++)
			{											
				sum = u[i] - P[i] - borrow;	
				if(u[i] < P[i])
				{
					borrow = 1;	
				}
				else if(u[i] > P[i])
				{
					borrow = 0;	
				}
				u[i] = sum;						
			}
		}
	}
	else
	{
		borrow -= carry;
		while(borrow)
		{
			carry = 0;
			for(i=0; i<DIG_LEN; i++)
			{											
				sum = u[i] + P[i] + carry;	
				if(sum < u[i])
				{
					carry = 1;
				}
				else if(sum > u[i])
				{
					carry = 0;	
				}
				u[i] = sum;						
			}
			borrow = borrow - carry;
		}
	}
}

void mul(big w, big u, big v)
{
	small clone[2*DIG_LEN];
	small r0=0, r1=0, r2=0;
	small x0, x1, y0, y1;
	small s1, s2, s3, s4;

#define mul_and_add(r2, r1, r0, x, y)			\
do{												\
	x0 = LOHALF(x); x1 = HIHALF(x);				\
	y0 = LOHALF(y); y1 = HIHALF(y);				\
	s1 = x0*y0+LOHALF(r0);						\
	s2 = x0*y1+HIHALF(r0);						\
	s3 = x1*y0+LOHALF(s2)+HIHALF(s1);			\
	s4 = x1*y1+HIHALF(s2)+HIHALF(s3);			\
	r0 = TOHIGH(s3)|LOHALF(s1);					\
	r1 += s4;									\
	r2 += (r1 < s4);						                                                                                                                                                                                                                                                                                                                                                                                                                                                	\
}while (0)

	mul_and_add(r2, r1, r0, u[0], v[0]);
	clone[0] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;
	
	mul_and_add(r2, r1, r0, u[1], v[0]); 
	mul_and_add(r2, r1, r0, u[0], v[1]);
	clone[1] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[2], v[0]); 
	mul_and_add(r2, r1, r0, u[1], v[1]);
	mul_and_add(r2, r1, r0, u[0], v[2]);
	clone[2] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[3], v[0]); 
	mul_and_add(r2, r1, r0, u[2], v[1]);
	mul_and_add(r2, r1, r0, u[1], v[2]); 
	mul_and_add(r2, r1, r0, u[0], v[3]);
	clone[3] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[4], v[0]);
	mul_and_add(r2, r1, r0, u[3], v[1]); 
	mul_and_add(r2, r1, r0, u[2], v[2]);
	mul_and_add(r2, r1, r0, u[1], v[3]); 
	mul_and_add(r2, r1, r0, u[0], v[4]);
	clone[4] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[5], v[0]);
	mul_and_add(r2, r1, r0, u[4], v[1]);
	mul_and_add(r2, r1, r0, u[3], v[2]); 
	mul_and_add(r2, r1, r0, u[2], v[3]);
	mul_and_add(r2, r1, r0, u[1], v[4]); 
	mul_and_add(r2, r1, r0, u[0], v[5]);
	clone[5] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[6], v[0]);
	mul_and_add(r2, r1, r0, u[5], v[1]);
	mul_and_add(r2, r1, r0, u[4], v[2]);
	mul_and_add(r2, r1, r0, u[3], v[3]); 
	mul_and_add(r2, r1, r0, u[2], v[4]);
	mul_and_add(r2, r1, r0, u[1], v[5]); 
	mul_and_add(r2, r1, r0, u[0], v[6]);
	clone[6] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[0]);
	mul_and_add(r2, r1, r0, u[6], v[1]);
	mul_and_add(r2, r1, r0, u[5], v[2]);
	mul_and_add(r2, r1, r0, u[4], v[3]);
	mul_and_add(r2, r1, r0, u[3], v[4]); 
	mul_and_add(r2, r1, r0, u[2], v[5]);
	mul_and_add(r2, r1, r0, u[1], v[6]);
	mul_and_add(r2, r1, r0, u[0], v[7]);
	clone[7] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[1]);
	mul_and_add(r2, r1, r0, u[6], v[2]);
	mul_and_add(r2, r1, r0, u[5], v[3]);
	mul_and_add(r2, r1, r0, u[4], v[4]);
	mul_and_add(r2, r1, r0, u[3], v[5]);
	mul_and_add(r2, r1, r0, u[2], v[6]);
	mul_and_add(r2, r1, r0, u[1], v[7]);
	clone[8] = r0; 
	r0 = r1; 
	r1 = r2;
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[2]);
	mul_and_add(r2, r1, r0, u[6], v[3]);
	mul_and_add(r2, r1, r0, u[5], v[4]);
	mul_and_add(r2, r1, r0, u[4], v[5]);
	mul_and_add(r2, r1, r0, u[3], v[6]);
	mul_and_add(r2, r1, r0, u[2], v[7]);
	clone[9] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[3]);
	mul_and_add(r2, r1, r0, u[6], v[4]);
	mul_and_add(r2, r1, r0, u[5], v[5]);
	mul_and_add(r2, r1, r0, u[4], v[6]);
	mul_and_add(r2, r1, r0, u[3], v[7]);
	clone[10] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[4]);
	mul_and_add(r2, r1, r0, u[6], v[5]);
	mul_and_add(r2, r1, r0, u[5], v[6]);
	mul_and_add(r2, r1, r0, u[4], v[7]);
	clone[11] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[5]);
	mul_and_add(r2, r1, r0, u[6], v[6]);
	mul_and_add(r2, r1, r0, u[5], v[7]);
	clone[12] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[6]);
	mul_and_add(r2, r1, r0, u[6], v[7]);
	clone[13] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, u[7], v[7]);
	clone[14] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	clone[15] = r0;

#undef mul_and_add

	mod(w, clone);
}

void squ(big x, big y)
{
	small clone[2*DIG_LEN];
	small r0=0, r1=0, r2=0;
	small x0, x1, y0, y1;
	small s1, s2, s3, s4;

#define mul_and_add(r2, r1, r0, x, y)			\
do{												\
	x0 = LOHALF(x); x1 = HIHALF(x);				\
	y0 = LOHALF(y); y1 = HIHALF(y);				\
	s1 = x0*y0+LOHALF(r0);						\
	s2 = x0*y1+HIHALF(r0);						\
	s3 = x1*y0+LOHALF(s2)+HIHALF(s1);			\
	s4 = x1*y1+HIHALF(s2)+HIHALF(s3);			\
	r0 = TOHIGH(s3)|LOHALF(s1);					\
	r1 += s4;									\
	r2 += (r1 < s4);							\
}while (0)

#define mul_and_doubleadd(r2, r1, r0, x, y)		\
do{												\
	x0 = LOHALF(x); x1 = HIHALF(x);				\
	y0 = LOHALF(y); y1 = HIHALF(y);				\
	s1 = x0*y0;	s2 = x1*y0;						\
	s3 = x0*y1+HIHALF(s1)+LOHALF(s2);			\
	s4 = x1*y1+HIHALF(s3)+HIHALF(s2);			\
	s3 = TOHIGH(s3)|LOHALF(s1);					\
	r2 += (s4>>31);								\
	s4 = (s4<<1) | (s3>>31);					\
	s3 <<= 1;									\
	r0 += s3;									\
	r1 += (s4 + (r0<s3));						\
	r2 += ((r1<s4)||((r1==s4)&&(r0<s3)));		\
}while (0)

	mul_and_add(r2, r1, r0, y[0], y[0]);
	clone[0] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;
	
	mul_and_doubleadd(r2, r1, r0, y[0], y[1]); 
	clone[1] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[0], y[2]);
	mul_and_add(r2, r1, r0, y[1], y[1]);
	clone[2] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[0], y[3]);
	mul_and_doubleadd(r2, r1, r0, y[1], y[2]);
	clone[3] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[0], y[4]);
	mul_and_doubleadd(r2, r1, r0, y[1], y[3]);
	mul_and_add(r2, r1, r0, y[2], y[2]);
	clone[4] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[0], y[5]);
	mul_and_doubleadd(r2, r1, r0, y[1], y[4]);
	mul_and_doubleadd(r2, r1, r0, y[2], y[3]);
	clone[5] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[0], y[6]);
	mul_and_doubleadd(r2, r1, r0, y[1], y[5]);
	mul_and_doubleadd(r2, r1, r0, y[2], y[4]);
	mul_and_add(r2, r1, r0, y[3], y[3]);
	clone[6] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[0], y[7]);
	mul_and_doubleadd(r2, r1, r0, y[1], y[6]);
	mul_and_doubleadd(r2, r1, r0, y[2], y[5]);
	mul_and_doubleadd(r2, r1, r0, y[3], y[4]);
	clone[7] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[1], y[7]);
	mul_and_doubleadd(r2, r1, r0, y[2], y[6]);
	mul_and_doubleadd(r2, r1, r0, y[3], y[5]);
	mul_and_add(r2, r1, r0, y[4], y[4]);
	clone[8] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[2], y[7]);
	mul_and_doubleadd(r2, r1, r0, y[3], y[6]);
	mul_and_doubleadd(r2, r1, r0, y[4], y[5]);
	clone[9] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[3], y[7]);
	mul_and_doubleadd(r2, r1, r0, y[4], y[6]);
	mul_and_add(r2, r1, r0, y[5], y[5]);
	clone[10] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[4], y[7]);
	mul_and_doubleadd(r2, r1, r0, y[5], y[6]);
	clone[11] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[5], y[7]);
	mul_and_add(r2, r1, r0, y[6], y[6]);
	clone[12] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_doubleadd(r2, r1, r0, y[6], y[7]);
	clone[13] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	mul_and_add(r2, r1, r0, y[7], y[7]);
	clone[14] = r0; 
	r0 = r1; 
	r1 = r2; 
	r2 = 0;

	clone[15] = r0;
	
#undef mul_and_add
#undef mul_and_doubleadd

	mod(x, clone);
}

void inv(big x, big y)
{
	small u[DIG_LEN], v[DIG_LEN], a[DIG_LEN]={1}, c[DIG_LEN]={0};
	small sum, carry;
	int i, flagu, flag;

	for(i=0; i<DIG_LEN; i++)
	{
		u[i] = y[i];
		v[i] = P[i];
	}
									
	for(flagu=1,i=0; i<DIG_LEN; i++)
	{
		if (u[i] != 0) 
		{
			flagu = 0; 
			break;
		}
	}

	while(!flagu)
	{
		while(u[0] % 2 == 0)
		{
			for(i=0; i<DIG_LEN-1; i++)
			{
				u[i] = (u[i] >> 1) | (u[i+1] << 31);
			}
			u[DIG_LEN-1] = u[DIG_LEN-1] >> 1;

			if(a[0] % 2 == 0)
			{
				for(i=0; i<DIG_LEN-1; i++)
				{
					a[i] = (a[i] >> 1)|(a[i+1] << 31);
				}
				a[DIG_LEN-1] = a[DIG_LEN-1] >> 1;
			}
			else
			{
				carry = 0;
				for(i=0; i<DIG_LEN; i++)
				{											
					sum = a[i] + P[i] + carry;	
					if(sum < a[i])
					{
						carry = 1;
					}
					else if(sum > a[i])
					{
						carry = 0;
					}
					a[i] = sum;						
				}
				for(i=0; i<DIG_LEN-1; i++)
				{
					a[i] = (a[i] >> 1) | (a[i+1] << 31);
				}
				a[DIG_LEN-1] = (a[DIG_LEN-1] >> 1) | (carry << 31);
			}
		}

		while(v[0] % 2 == 0)
		{
			for(i=0; i<DIG_LEN-1; i++)
			{
				v[i] = (v[i] >> 1) | (v[i+1] << 31);
			}
			v[DIG_LEN-1] = v[DIG_LEN-1] >> 1;

			if(c[0] % 2 == 0)
			{
				for(i=0; i<DIG_LEN-1; i++)
				{
					c[i] = (c[i] >> 1) | (c[i+1] << 31);
				}
				c[DIG_LEN-1] = c[DIG_LEN-1] >> 1;
			}
			else
			{
				carry = 0;
				for(i=0; i<DIG_LEN; i++)
				{											
					sum = c[i] + P[i] + carry;	
					if(sum < c[i])
					{
						carry = 1;
					}
					else if(sum > c[i])
					{
						carry = 0;	
					}
					c[i] = sum;						
				}
				for(i=0; i<DIG_LEN-1; i++)
				{
					c[i] = (c[i] >> 1) | (c[i+1] << 31);
				}
				c[DIG_LEN-1] = (c[DIG_LEN-1] >> 1) | (carry << 31);
			}
		}
		
		flag = 0;
		i = DIG_LEN;																
		while(i--)
		{											
			if(u[i] > v[i])
			{
				flag = 1; 
				break;
			}					
			else if(u[i] < v[i])
			{
				flag = -1; 
				break;
			}					
		}

		if(flag >= 0)
		{
			sub(u, u, v); 
			sub(a, a, c);
		}
		else
		{
			sub(v, v, u); 
			sub(c, c, a);
		}
									
		for(flagu=1,i=0; i<DIG_LEN; i++)
		{
			if(u[i] != 0)
			{
				flagu = 0; 
				break;
			}
		}
	}

	for(i=0; i<DIG_LEN; i++)
	{
		x[i] = c[i];
	}
}


void modorder(big r, big x)
{
	small order[DIG_LEN+1] =
	{0x39D54123,0x53BBF409,0x21C6052B,0x7203DF6B,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE,0};
	small mu[DIG_LEN+1] = 
	{0xF15149A0,0x12AC6361,0xFA323C01,0x8DFC2096,0x1,0x1,0x1,0x1,0x1};

	small r0, r1, r2;
	small x0, x1, y0, y1;
	small s1, s2, s3, s4;
	small *q1, q2[DIG_LEN+1], clone[DIG_LEN+2];
	small borrow, sum;
	int i, k, flag;

#define mul_and_add(r2, r1, r0, x, y)			\
do{												\
	x0 = LOHALF(x); x1 = HIHALF(x);				\
	y0 = LOHALF(y); y1 = HIHALF(y);				\
	s1 = x0*y0+LOHALF(r0);						\
	s2 = x0*y1+HIHALF(r0);						\
	s3 = x1*y0+LOHALF(s2)+HIHALF(s1);			\
	s4 = x1*y1+HIHALF(s2)+HIHALF(s3);			\
	r0 = TOHIGH(s3)|LOHALF(s1);					\
	r1 += s4;									\
	r2 += (r1 < s4);							\
}while (0)

	r0 = 0;
	r1 = 0;
	r2 = 0;
	for(k=0; k<=DIG_LEN; k++)
	{	
		for(i=k; i<=DIG_LEN;i++)
		{
			if(mu[i] != 0)
			{
				mul_and_add(r2, r1, r0, mu[i], x[2*DIG_LEN-1+k-i]);
			}
		}
		clone[k] = r0; 
		r0 = r1; 
		r1 = r2; 
		r2 = 0;
	}
	clone[DIG_LEN+1] = r0;
	q1 = clone + 1;

	r0 = 0;
	r1 = 0;
	r2 = 0;
	for(k=0; k<DIG_LEN+1; k++)
	{
		for(i=0; i<=k; i++)
		{
			mul_and_add(r2, r1, r0, q1[i], order[k-i]);
		}
		q2[k] = r0; 
		r0 = r1; 
		r1 = r2; 
		r2 = 0;
	}

	borrow = 0;
	for(i=0; i<DIG_LEN+1; i++)
	{											
		sum = x[i] - q2[i] - borrow;	
		if(x[i] < q2[i])
		{
			borrow = 1;	
		}
		else if(x[i] > q2[i])
		{
			borrow = 0;	
		}
		q1[i] = sum;						
	}

	flag = 0;
	i = DIG_LEN + 1;																
	while(i--)
	{											
		if(q1[i] > order[i])
		{
			flag = 1; 
			break;
		}					
		else if(q1[i] < order[i])
		{
			flag = -1; 
			break;
		}					
	}
	while(flag>=0)
	{
		borrow = 0;
		for(i=0; i<DIG_LEN+1; i++)
		{											
			sum = q1[i] - order[i] - borrow;	
			if(q1[i] < order[i])
			{
				borrow = 1;
			}
			else if(q1[i] > order[i])
			{
				borrow = 0;	
			}
			q1[i] = sum;						
		}

		flag = 0;
		i = DIG_LEN + 1;																
		while(i--)
		{											
			if(q1[i] > order[i])
			{
				flag = 1; 
				break;
			}					
			else if(q1[i] < order[i])
			{
				flag = -1; 
				break;
			}					
		}
	}
	for(i=0; i<DIG_LEN; i++)
	{
		r[i] = q1[i];
	}

#undef mul_and_add	
}

void modadd(big w, big u, big v, big p)
{
	int i, flag;
	small sum, borrow, carry;

	carry = 0;
	for(i=0; i<DIG_LEN; i++)
	{											
		sum = u[i] + v[i] + carry;	
		if(sum < u[i])
		{
			carry = 1;
		}
		else if(sum > u[i])
		{
			carry = 0;
		}
		w[i] = sum;						
	}

	if(carry)
	{
		borrow = 0;
		for(i=0; i<DIG_LEN; i++)
		{											
			sum = w[i] - p[i] - borrow;	
			if(w[i] < p[i])
			{
				borrow = 1;
			}
			else if(w[i] > p[i])
			{
				borrow = 0;	
			}
			w[i] = sum;						
		}
		return;
	}
	
	flag = 0;
	i = DIG_LEN;																
	while(i--)
	{											
		if(w[i] > p[i])
		{
			flag = 1; 
			break;
		}					
		else if(w[i] < p[i])
		{
			flag = -1; 
			break;
		}					
	}
	
	if(flag < 0)
	{
		return;
	}
	else
	{
		borrow = 0;
		for(i=0; i<DIG_LEN; i++)
		{											
			sum = w[i] - p[i] - borrow;	
			if(w[i] < p[i])
			{
				borrow = 1;	
			}
			else if(w[i] > p[i])
			{
				borrow = 0;	
			}
			w[i] = sum;						
		}
	}
}

void modsub(big w, big u, big v, big p)
{
	int i;
	small sum, borrow, carry;

	borrow = 0;
	for(i=0; i<DIG_LEN; i++)
	{											
		sum = u[i] - v[i] - borrow;	
		if(u[i] < v[i])
		{
			borrow = 1;
		}
		else if(u[i] > v[i])
		{
			borrow = 0;
		}
		w[i] = sum;						
	}

	if(borrow)
	{
		carry = 0;
		for(i=0; i<DIG_LEN; i++)
		{											
			sum = w[i] + p[i] + carry;	
			if(sum < p[i])
			{
				carry = 1;
			}
			else if(sum > p[i])
			{
				carry = 0;
			}
			w[i] = sum;						
		}
	}
}

void modinv(big x, big y, big p)
{
	small u[DIG_LEN], v[DIG_LEN], a[DIG_LEN]={1}, c[DIG_LEN]={0};
	small sum, carry;
	int i, flagu, flag;

	for(i=0; i<DIG_LEN; i++)
	{
		u[i] = y[i];
		v[i] = p[i];
	}
									
	for(flagu=1,i=0; i<DIG_LEN; i++)
	{
		if(u[i] != 0)
		{
			flagu = 0; 
			break;
		}
	}

	while(!flagu)
	{
		while(u[0] % 2 == 0)
		{
			for(i=0; i<DIG_LEN-1; i++)
			{
				u[i] = (u[i] >> 1) | (u[i+1] << 31);
			}
			u[DIG_LEN-1] = u[DIG_LEN-1] >> 1;

			if(a[0] % 2 == 0)
			{
				for(i=0; i<DIG_LEN-1; i++)
				{
					a[i] = (a[i] >> 1) | (a[i+1] << 31);
				}
				a[DIG_LEN-1] = a[DIG_LEN-1] >> 1;
			}
			else
			{
				carry = 0;
				for(i=0; i<DIG_LEN; i++)
				{											
					sum = a[i] + p[i] + carry;	
					if(sum < a[i])
					{
						carry = 1;
					}
					else if(sum > a[i])
					{
						carry = 0;
					}
					a[i] = sum;						
				}
				for(i=0; i<DIG_LEN-1; i++)
				{
					a[i] = (a[i] >> 1) | (a[i+1] << 31);
				}
				a[DIG_LEN-1] = (a[DIG_LEN-1] >> 1) | (carry << 31);
			}
		}
		while(v[0] % 2 == 0)
		{
			for(i=0; i<DIG_LEN-1; i++)
			{
				v[i] = (v[i] >> 1) | (v[i+1] << 31);
			}
			v[DIG_LEN-1] = v[DIG_LEN-1] >> 1;

			if(c[0] % 2 == 0)
			{
				for(i=0; i<DIG_LEN-1; i++)
				{
					c[i] = (c[i] >> 1) | (c[i+1] << 31);
				}
				c[DIG_LEN-1] = c[DIG_LEN-1] >> 1;
			}
			else
			{
				carry = 0;
				for(i=0; i<DIG_LEN; i++)
				{											
					sum = c[i] + p[i] + carry;	
					if(sum < c[i])
					{
						carry = 1;
					}
					else if(sum > c[i])
					{
						carry = 0;	
					}
					c[i] = sum;						
				}
				for(i=0; i<DIG_LEN-1; i++)
				{
					c[i] = (c[i] >> 1) | (c[i+1] << 31);
				}
				c[DIG_LEN-1] = (c[DIG_LEN-1] >> 1) | (carry << 31);
			}
		}
		
		flag = 0;
		i = DIG_LEN;																
		while(i--)
		{											
			if(u[i] > v[i])
			{
				flag = 1; 
				break;
			}					
			else if(u[i] < v[i])
			{
				flag = -1; 
				break;
			}					
		}

		if(flag >= 0)
		{
			modsub(u, u, v, p); 
			modsub(a, a, c, p);
		}
		else
		{
			modsub(v, v, u, p); 
			modsub(c, c, a, p);
		}
								
		for(flagu=1,i=0; i<DIG_LEN; i++)
		{
			if (u[i] != 0) 
			{
				flagu = 0; 
				break;
			}
		}
	}

	for(i=0; i<DIG_LEN; i++)
	{
		x[i] = c[i];
	}
}

void mulmodorder(big w, big u, big v)
{
	small r0=0, r1=0, r2=0;
	small x0, x1, y0, y1;
	small s1, s2, s3, s4;
	small clone[2*DIG_LEN];
	int i, j, k;

#define mul_and_add(r2, r1, r0, x, y)			\
do{												\
	x0 = LOHALF(x); x1 = HIHALF(x);				\
	y0 = LOHALF(y); y1 = HIHALF(y);				\
	s1 = x0*y0+LOHALF(r0);						\
	s2 = x0*y1+HIHALF(r0);						\
	s3 = x1*y0+LOHALF(s2)+HIHALF(s1);			\
	s4 = x1*y1+HIHALF(s2)+HIHALF(s3);			\
	r0 = TOHIGH(s3)|LOHALF(s1);					\
	r1 += s4;									\
	r2 += (r1 < s4);							\
}while (0)

	for (k=0; k<=2*(DIG_LEN-1); k++)
	{
		i = (k-(DIG_LEN-1) <= 0) ? 0: (k-(DIG_LEN-1));
		j = (k <= DIG_LEN-1) ? k : (DIG_LEN-1);
		while (i <= j)
		{
			mul_and_add(r2, r1, r0, u[i], v[k-i]);
			i++;
		}
		clone[k] = r0; 
		r0 = r1; 
		r1 = r2; 
		r2 = 0;
	}
	clone[2*DIG_LEN-1] = r0;	
	modorder(w, clone);

#undef mul_and_add
}


void projpointdouble(point p, point q);
void projpointadd(point r, point p, point q);
void mixpointadd(point r, point p, epoint q);

void pointadd(epoint r, epoint p, epoint q)
{
	int i, flag;
	small t1[DIG_LEN], t2[DIG_LEN], lambda[DIG_LEN];
	
	for(flag=1,i=0; i<DIG_LEN; i++)
	{
		if ((p->x[i] != 0) || (p->y[i] != 0)) 
		{
			flag = 0; 
			break;
		}
	}
	if(flag)
	{
		for(i=0; i<DIG_LEN; i++)
		{
			r->x[i] = q->x[i];
			r->y[i] = q->y[i];
		}
		return;
	}

	for(flag=1,i=0; i<DIG_LEN; i++)
	{
		if((q->x[i] != 0) || (q->y[i] != 0))
		{
			flag = 0; 
			break;
		}
	}
	if(flag)
	{
		for(i=0; i<DIG_LEN; i++)
		{
			r->x[i] = p->x[i];
			r->y[i] = p->y[i];
		}
		return;
	}
	
	for(flag=1,i=0; i<DIG_LEN; i++)
	{
		if(p->x[i] != q->x[i])
		{
			flag = 0; 
			break;
		}
	}
	if(flag)
	{	
		for(flag=1,i=0; i<DIG_LEN; i++)
		{
			if(p->y[i] != q->y[i])
			{
				flag = 0; 
				break;
			}
		}
		if(!flag)
		{
			for(i=0; i<DIG_LEN; i++)
			{
				r->x[i] = 0; 
				r->y[i] = 0;
			}
			return;
		}

		for(flag=1,i=0; i<DIG_LEN; i++)
		{
			if(p->y[i] != 0)
			{
				flag = 0; 
				break;
			}
		}
		if(flag)
		{
			for(i=0; i<DIG_LEN; i++)
			{
				r->x[i] = 0; 
				r->y[i] = 0;
			}
			return;
		}

		squ(t1, q->x); 
		add(t2, t1, t1); 
		add(t1, t1, t2); 
		add(t1, t1,(small *)A);
		add(t2, q->y, q->y); 
		inv(t2, t2); 
		mul(lambda, t1, t2);
	}
	else
	{
		sub(t1, p->x, q->x); 
		inv(t1, t1);
		sub(t2, p->y, q->y); 
		mul(lambda, t1, t2);
	}
	squ(t1, lambda); 
	sub(t1, t1, p->x); 
	sub(t1, t1, q->x);
	sub(t2, q->x, t1); 
	mul(t2, t2, lambda); 
	sub(t2, t2, q->y);

	for(i=0; i<DIG_LEN; i++)
	{
		r->x[i] = t1[i];
		r->y[i] = t2[i];
	}
}

void pointmul(epoint p, epoint q, big n)
{
	int naf[M + 1]={0};
	int lnaf, flag, i, j, l;
	int flag1, flag2;
	small carry, k[DIG_LEN];
	projpoint pre[8], temp;
	projpoint clone={{1},{1},{0}};

	for (flag1=1,i=0; i<DIG_LEN; i++)
	{
		if (n[i] != 0) 
		{
			flag1 = 0; 
			break;
		}
	}
	for (flag2=1,i=0; i<DIG_LEN; i++)
	{
		if ((q->x[i] != 0) || (q->y[i] != 0)) 
		{
			flag2 = 0; 
			break;
		}
	}
	if (flag1 || flag2)
	{
		for (i=0; i<DIG_LEN; i++)
		{
			p->x[i] = 0;
			p->y[i] = 0;
		}
		return;
	}

	for (i=0; i<DIG_LEN; i++) 
	{
		k[i] = n[i];
	}
	i = 0; 
	while (! flag1)
	{	
		if (k[0] % 2 == 0)
		{
			naf[i++] = 0; 

			for (j=0; j<DIG_LEN-1; j++)
			{
				k[j] = (k[j] >> 1) | (k[j+1] << 31);
			}
			k[DIG_LEN-1] = k[DIG_LEN-1] >> 1;
		}
		else
		{
			flag = k[0] & 0x1f;

			for (j=0; j<DIG_LEN-1; j++)
			{
				k[j] = (k[j] >> 5) | (k[j+1] << 27);
			}
			k[DIG_LEN-1] = k[DIG_LEN-1] >> 5;

			for (flag1=1,j=0; j<DIG_LEN; j++)
			{
				if (k[j] !=0 ) 
				{
					flag1 = 0; 
					break;
				}
			}

			if (flag < 16)
			{
				naf[i++] = flag; 					
				if (! flag1)
				{
					naf[i++] = 0; 
					naf[i++] = 0; 
					naf[i++] = 0; 
					naf[i++] = 0; 
				}
			}
			else 
			{
				naf[i++] = flag - 32;

				carry = 1; 
				j = 0;
				while (carry)
				{
					k[j]++;
					if (k[j] == 0) 
					{
						carry=1;
					}
					else 
					{
						carry = 0;
					}
					j++;
				}
				flag1 = 0;
				naf[i++] = 0; 
				naf[i++] = 0; 
				naf[i++] = 0; 
				naf[i++] = 0; 
			}
		}
	}
	lnaf = i;
	while (1)
	{
		if (naf[lnaf-1] == 0) 
		{
			lnaf--;
		}
		else 
		{
			break;
		}
	}

	for (i=0; i<DIG_LEN; i++)
	{
		pre[0].x[i] = q->x[i]; 
		pre[0].y[i] = q->y[i]; 
		pre[0].z[i]=0;
	}
	pre[0].z[0] = 1;

	projpointdouble(&temp, &pre[0]);
	for (i=0; i<7; i++)
	{
		projpointadd(&pre[i+1], &pre[i], &temp);
	}

	for (j=lnaf-1; j>=0; j--)
	{
		projpointdouble(&clone, &clone);
		if (naf[j] != 0)
		{
			if (naf[j] > 0)
			{
				i = (naf[j]-1)/2;
				projpointadd(&clone, &clone, &pre[i]);
			}
			if (naf[j] < 0)
			{
				i = (-naf[j]-1)/2;

				sub(temp.y, (small *)P, pre[i].y);
				for (l=0; l<DIG_LEN; l++)
				{
					temp.x[l] = pre[i].x[l]; 
					temp.z[l] = pre[i].z[l];
				}

				projpointadd(&clone, &clone, &temp);
			}
		}
	}

	for (flag=1,i=0; i<DIG_LEN; i++)
	{
		if (clone.z[i] !=0 ) 
		{
			flag = 0; 
			break;
		}
	}
	if (flag)
	{  
		for (i=0; i<DIG_LEN; i++)
		{
			p->x[i] = 0; 
			p->y[i] = 0;
		}
		return;
	}
	else
	{
		squ(p->x, clone.z);
		mul(p->x, p->x, clone.z);
		inv(p->x, p->x);
		mul(p->y, clone.y, p->x);
		mul(p->x, clone.z, p->x);
		mul(p->x, clone.x, p->x);
	}
}

void projpointdouble(point p, point q)
{
	small t1[DIG_LEN], t2[DIG_LEN], t3[DIG_LEN], t4[DIG_LEN], t5[DIG_LEN];
	int i, flag1, flag2;

	for (i=0; i<DIG_LEN; i++)
	{
		t1[i] = q->x[i];
		t2[i] = q->y[i];
		t3[i] = q->z[i];
	}

	for (flag1=1,i=0; i<DIG_LEN; i++)
	{
		if (t2[i] != 0) 
		{
			flag1 = 0; 
			break;
		}
	}
	for (flag2=1,i=0; i<DIG_LEN; i++)
	{
		if (t3[i] != 0) 
		{
			flag2 = 0; 
			break;
		}
	}

	if (flag1 || flag2)
	{
		for (i=1; i<DIG_LEN; i++)
		{
			p->x[i] = 0; 
			p->y[i] = 0; 
			p->z[i]=0;
		}
		p->x[0] = 1; 
		p->y[0] = 1; 
		p->z[0] = 0;
		return;
	}

	squ(t4, t3); 
	sub(t5, t1, t4); 
	add(t4, t1, t4);
	mul(t5, t4, t5); 
	add(t4, t5, t5); 
	add(t4, t4, t5);
	mul(t3, t2, t3); 
	add(t3, t3, t3); 

	for (i=0; i<DIG_LEN; i++)
	{
		p->z[i] = t3[i];
	}

	squ(t2, t2); 
	mul(t5, t1, t2); 
	add(t5, t5, t5);
	add(t5, t5, t5);
	squ(t1, t4); 
	add(t3, t5, t5); 
	sub(t1, t1, t3);
	squ(t2, t2); 
	add(t2, t2, t2); 
	add(t2, t2, t2); 
	add(t2, t2, t2);
	sub(t5, t5, t1); 
	mul(t5, t4, t5); 
	sub(t2, t5, t2);

	for (i=0; i<DIG_LEN; i++)
	{
		p->x[i] = t1[i];
		p->y[i] = t2[i];
	}
}

void mixpointadd(point r, point p, epoint q)
{
	small t1[DIG_LEN], t2[DIG_LEN], t3[DIG_LEN], t4[DIG_LEN];
	small t5[DIG_LEN], t6[DIG_LEN];
	small sum, carry;
	int i, flag1, flag2;
	
	for (i=0; i<DIG_LEN; i++)
	{
		t1[i] = p->x[i]; 
		t2[i] = p->y[i]; 
		t3[i] = p->z[i];
		t4[i] = q->x[i]; 
		t5[i] = q->y[i];
	}
	
	for (flag1=1,i=0; i<DIG_LEN; i++)
	{
		if (t3[i] != 0) 
		{
			flag1 = 0; 
			break;
		}
	}
	if (flag1)
	{
		for (i=0; i<DIG_LEN; i++)
		{
			r->x[i] = q->x[i]; 
			r->y[i] = q->y[i]; 
			r->z[i] = 0;
		}
		r->z[0] = 1;

		return;
	}

	for (flag2=1,i=0; i<DIG_LEN; i++)
	{
		if ((t4[i] != 0) || (t5[i] != 0)) 
		{
			flag2 = 0; 
			break;
		}
	}

	if (flag2)
	{
		for (i=0; i<DIG_LEN; i++)
		{
			r->x[i] = p->x[i]; 
			r->y[i] = p->y[i]; 
			r->z[i] = p->z[i];
		}

		return;
	}

	squ(t6, t3); 
	mul(t4, t4, t6);
	mul(t6, t3, t6); 
	mul(t5, t5, t6);
	sub(t4, t1, t4);
	sub(t5, t2, t5);
	
	for (flag1=1,i=0; i<DIG_LEN; i++)
	{
		if (t4[i] != 0) 
		{
			flag1 = 0; 
			break;
		}
	}
	for (flag2=1,i=0; i<DIG_LEN; i++)
	{
		if (t5[i] != 0) 
		{
			flag2 = 0; 
			break;
		}
	}
	if (flag1)
	{
		if (flag2) 
		{
			projpointdouble(r, p); 
			return;
		}
		else
		{
			for (i=1; i<DIG_LEN; i++)
			{
				r->x[i] = 0; 
				r->y[i] = 0; 
				r->z[i] = 0;
			}
			r->x[0] = 1; 
			r->y[0] = 1; 
			r->z[0] = 0;
			return;
		}
	}

	add(t1, t1, t1); 
	sub(t1, t1, t4);
	add(t2, t2, t2); 
	sub(t2, t2, t5);
	mul(t3, t3, t4);
	
	for (i=0; i<DIG_LEN; i++)
	{
		r->z[i] = t3[i];
	}

	squ(t6, t4); 
	mul(t4, t4, t6); 
	mul(t6, t1, t6);
	squ(t1, t5); 
	sub(t1, t1, t6); 

	for (i=0; i<DIG_LEN; i++)
	{
		r->x[i] = t1[i];
	}

	add(t1, t1, t1); 
	sub(t6, t6, t1);
	mul(t5, t5, t6); 
	mul(t4, t2, t4); 
	sub(t2, t5, t4);

	if (t2[0] % 2 == 0) 
	{
		for (i=0; i<DIG_LEN-1; i++)
		{
			r->y[i] = (t2[i] >> 1) | (t2[i+1] << 31);
		}
		r->y[DIG_LEN-1] = t2[DIG_LEN-1] >> 1;

	}
	else
	{
		carry = 0;
		for (i=0; i<DIG_LEN; i++)		
		{											
			sum = t2[i] + P[i] + carry;	
			if (sum < t2[i])
			{
				carry = 1;
			}
			else if (sum > t2[i])
			{
				carry = 0;	
			}
			t2[i] = sum;						
		}
		for (i=0; i<DIG_LEN-1; i++)
		{
			r->y[i] = (t2[i] >> 1) | (t2[i+1] << 31);
		}
		r->y[DIG_LEN-1] = (t2[DIG_LEN-1] >> 1) | (carry << 31);
	}
}

void projpointadd(point r, point p, point q)
{
	small t1[DIG_LEN], t2[DIG_LEN], t3[DIG_LEN], t4[DIG_LEN];
	small t5[DIG_LEN], t6[DIG_LEN], t7[DIG_LEN];
	small sum, carry;
	int i, flag1, flag2;
	
	for (i=0; i<DIG_LEN; i++)
	{
		t1[i] = p->x[i]; 
		t2[i] = p->y[i]; 
		t3[i] = p->z[i];
		t4[i] = q->x[i]; 
		t5[i] = q->y[i]; 
		t6[i] = q->z[i];
	}
	
	for (flag1=1,i=0; i<DIG_LEN; i++)
	{
		if (t3[i] != 0) 
		{
			flag1 = 0; 
			break;
		}
	}
	if (flag1)
	{
		for (i=0; i<DIG_LEN; i++)
		{
			r->x[i] = q->x[i]; 
			r->y[i] = q->y[i]; 
			r->z[i] = q->z[i];
		}
		return;
	}

	for (flag2=1,i=0; i<DIG_LEN; i++)
	{
		if (t6[i] != 0) 
		{
			flag2 = 0; 
			break;
		}
	}
	if (flag2)
	{
		for (i=0; i<DIG_LEN; i++)
		{
			r->x[i] = p->x[i]; 
			r->y[i] = p->y[i];
			r->z[i] = p->z[i];
		}
		return;
	}

	squ(t7, t6); 
	mul(t1, t1, t7);
	mul(t7, t6, t7); 
	mul(t2, t2, t7);

	squ(t7, t3); 
	mul(t4, t4, t7);
	mul(t7, t3, t7); 
	mul(t5, t5, t7);
	sub(t4, t1, t4);
	sub(t5, t2, t5);
	
	for (flag1=1,i=0; i<DIG_LEN; i++)
	{
		if (t4[i] != 0) 
		{
			flag1 = 0; 
			break;
		}
	}
	for (flag2=1,i=0; i<DIG_LEN; i++)
	{
		if (t5[i] != 0) 
		{
			flag2 = 0; 
			break;
		}
	}

	if (flag1)
	{
		if (flag2) 
		{
			projpointdouble(r, p); 
			return;
		}
		else
		{
			for (i=1; i<DIG_LEN; i++)
			{
				r->x[i] = 0; 
				r->y[i] = 0; 
				r->z[i]=0;
			}
			r->x[0] = 1; 
			r->y[0] = 1; 
			r->z[0] = 0;

			return;
		}
	}

	add(t1, t1, t1); 
	sub(t1, t1, t4);
	add(t2, t2, t2); 
	sub(t2, t2, t5);
	mul(t3, t3, t6);
	mul(t3, t3, t4); 

	for (i=0; i<DIG_LEN; i++)
	{
		r->z[i] = t3[i];
	}

	squ(t7, t4); 
	mul(t4, t4, t7); 
	mul(t7, t1, t7);
	squ(t1, t5); 
	sub(t1, t1, t7);
	
	for (i=0; i<DIG_LEN; i++)
	{
		r->x[i] = t1[i];
	}

	add(t1, t1, t1); 
	sub(t7, t7, t1);
	mul(t5, t5, t7); 
	mul(t4, t2, t4); 
	sub(t2, t5, t4);

	if (t2[0] % 2 == 0) 
	{
		for (i=0; i<DIG_LEN-1; i++)
		{
			r->y[i] = (t2[i] >> 1) | (t2[i+1] << 31);
		}
		r->y[DIG_LEN-1] = t2[DIG_LEN-1] >> 1;

	}
	else
	{
		carry = 0;
		for (i=0; i<DIG_LEN; i++)		
		{											
			sum = t2[i] + P[i] + carry;	
			if (sum < t2[i])
			{
				carry = 1;
			}
			else if (sum > t2[i])
			{
				carry = 0;
			}
			t2[i] = sum;						
		}
		for (i=0; i<DIG_LEN-1; i++)
		{
			r->y[i] = (t2[i] >> 1) | (t2[i+1] << 31);
		}
		r->y[DIG_LEN-1] = (t2[DIG_LEN-1] >> 1) | (carry << 31);
	}
}

void basepointmul(epoint p, big n)
{
	static affpoint pre1[16] = 
	{
		{{0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}, {0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}},
		{{0x334c74c7,0x715a4589,0xf2660be1,0x8fe30bbf,0x6a39c994,0x5f990446,0x1f198119,0x32c4ae2c}, {0x2139f0a0,0x02df32e5,0xc62a4740,0xd0a9877c,0x6b692153,0x59bdcee3,0xf4f6779c,0xbc3736a2}},
		{{0xb5824517,0xe18bd546,0x91caa486,0x673891d7,0xdf9f9a14,0xba220b99,0x55c1da54,0x95afbd11}, {0x334acdcb,0x8e4450eb,0x8a53f20d,0xc3c7d189,0x4053017c,0x2eee750f,0x517388c2,0xe8a6d82c}},
		{{0xb99fba55,0xf81c8da9,0x49feef6e,0x137f6c61,0x94da9ad4,0xcb129aa4,0x7d123db6,0x82a0f540}, {0x72c4dbc9,0xfdeca007,0x0cf58373,0xa961b58f,0xe973f9c3,0xecacab94,0x6a22ca3f,0xf12fa469}},
		{{0xd13a42ed,0xeae3d9a9,0x484e1b38,0x2b2308f6,0x88c21f3a,0x3db7b248,0x74d55da9,0xb692e5b5}, {0xe295e5ab,0xd186469d,0x73438e6d,0xdb61ac17,0x544926f9,0x5a924f85,0x0f3fb613,0xa175051b}},
		{{0x62c8d58b,0xa72d084f,0xeaf48fd7,0xe3d6467d,0x128a56a7,0x8fe75e5a,0xff2b68bd,0xc0023fe7}, {0x316815f9,0x64f67782,0x19a69cd2,0xb52b6d9b,0x89cbbade,0x5d1ed6fa,0xe7f4ccdb,0x796c910e}},
		{{0xc5f13015,0x1b2150c1,0x5d952c9b,0xdaaba91b,0x3f546142,0x0e8cc24c,0x3705f260,0x75a34b24}, {0x1cef1339,0x77d19542,0x0c3a0623,0x636644aa,0x6eeb2444,0x4683df17,0x3535e74d,0x642ce3bd}},
		{{0x6e7ecc08,0x4a59ac2c,0x4f191d63,0xaf2b7116,0xb284554f,0x3622a87f,0x441e9cd0,0xd9eb397b}, {0x93b6a54d,0xa66b8a48,0x0b4a663a,0x26fb89a4,0xeedfc9f4,0xafa87501,0x66f98108,0xf3f000bc}},
		{{0xe031d616,0xad8bc68c,0xe4003187,0x16888d8e,0x3bb8b600,0x44c0757f,0xf0164245,0x793fae7a}, {0x973f333b,0x210cd042,0x2dbd25f9,0x08666ff5,0xf5f7ad5d,0x65c5b129,0x19b3219a,0xe03d7a8d}},
		{{0xe0e00392,0xd68bfbac,0xd3445dc7,0x261014f7,0x14a071ee,0xd9f46b27,0x0810b682,0x1b200af3}, {0x2ae69bcd,0x0d91d8b1,0xbf8cd981,0x74a08f17,0xf0d2b82d,0xd822913c,0xb05bfad2,0x248b7af0}},
		{{0x9e62f2e2,0xba119a04,0x4df05ae5,0xf278e8a3,0x4eb5d180,0xd269f356,0x4f957cb1,0x8e74ad0f}, {0xbd76e2dd,0x112ff4da,0x630fdb7f,0x91373f20,0x4992904c,0xf43eab47,0xaf3b6db4,0x55a5ccc7}},
		{{0xbdd23de9,0x5ad104a8,0xeb71c2c1,0xf5a9e515,0xba95c174,0x390542a0,0x426491bf,0x4c55fb20}, {0xef626289,0x91525735,0x88f09635,0xd2ed977f,0x7a8a8521,0xfd48731b,0xb8fdebea,0x08f89a03}},
		{{0x35eb8e2e,0x7e8e61ea,0xb98a762c,0x1bb2700d,0x7738c17c,0xd81ea23b,0x6dba26a3,0xf9def2a4}, {0xd05e329f,0x183a7912,0x96ccde0e,0x34664a08,0x614283bb,0x56c22652,0xd5ff0513,0x91692899}},
		{{0xf3bdbe19,0x449d48d8,0xcc8510cb,0xab95de03,0x3f8bfb25,0xaef15946,0xdae3ca8b,0xda72c379}, {0xe82cc3ea,0xcba9315c,0x38a58020,0x4e524bac,0x538e348c,0x36ba2752,0x75ed450f,0xb170d0da}},
		{{0x2b4f8da6,0x947af0f5,0x17827976,0x7eda17d9,0x705853a0,0x5ba79a0c,0x3fb2ddc7,0xa5d9873b}, {0xa5fd9ce9,0xc2a48162,0x26f25f02,0x80ee8ae5,0x633be6a9,0xf60c8ef6,0x29a84a35,0xe2e23f02}},
		{{0x86bb6afb,0xbc4945bd,0xeba46fee,0x237eb711,0x7b86eb33,0x7c1db58b,0x273b3ac7,0xd94eb728}, {0x9568d0a4,0xbe1717e5,0x45f70212,0x4a6067cc,0xafc2fb17,0x19b32eb5,0xc3ac9d3c,0xbe3c1e7a}},
	};
	
	static affpoint pre2[16] = 
	{
		{{0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}, {0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000}},
		{{0xae53c1e9,0x68a88405,0xfd558656,0x51e46707,0x86896c10,0x71e834cf,0xe10d581f,0x3d251b54}, {0xeeb19032,0x1884d5b0,0x53e526fe,0xeeaf7298,0x1a8d8c11,0x5931f683,0xfb98b4d8,0x87891d33}},
		{{0xcac14893,0x9047673f,0xbfb58659,0xf5df5d83,0x1642e71a,0x0a6230c8,0x00777791,0xef14b338}, {0xa3386fca,0xcf1e99af,0x91313d53,0x7ace9377,0x6dcd01bb,0x36fe159b,0x2e2b960a,0xc9bc50d0}},
		{{0xe12e162d,0x716e5a7e,0x62dd5a00,0xbbf9bb2c,0x4144dd05,0xca235ccb,0x8f70520e,0xbcb7de0f}, {0x947cb8eb,0x981e8964,0xa04de08d,0x53c7102e,0xafc6a10d,0xe9076332,0x6b58c35d,0x93d90f77}},
		{{0x678337ee,0x834dbff6,0xfef0785a,0xc607e811,0xe30a298b,0xaaefc62b,0x326afad3,0xeb5ca335}, {0x84af54a8,0x9774fe13,0x785388b4,0xca4b6ef5,0x66f6c642,0x1346c82d,0xaa2d53ce,0xedcc0c2a}},
		{{0x64b9e6f4,0xb896b3f7,0x736fb3d0,0x47e4018c,0x07413920,0xfc2fc867,0x8e1aeae7,0x1a852642}, {0x50e2ae60,0x13868026,0x995384d0,0x7474dedc,0xdd43b011,0x2c4cc396,0x141de1b0,0x63b0e9c7}},
		{{0x69d17771,0xeb5fb3b3,0x933ed257,0x1fe07b18,0xe3673912,0xdfc4c81c,0x6a91a647,0x913614c6}, {0xc0ba877f,0x18aee853,0xeceff091,0x03109c2d,0x7e4ee08c,0x8532307e,0x6e6ce0bb,0xcef0791a}},
		{{0x057a4a0f,0xf0e9f5d8,0x9f125aa9,0xbbf7f8b4,0x283187c2,0x51e8fdd6,0x59d36298,0xe0997d47}, {0x6f4221c3,0x67ec3c5c,0xc860722f,0x3ea275db,0x3859f5e2,0x152d01e2,0x12680f44,0xfb574043}},
		{{0x49be2a1f,0x21ac3df8,0xc51d112f,0x11006e9f,0x4775c857,0x9151aa58,0xba04a8d9,0x5159d218}, {0x25fd1866,0x98b7d1a9,0xfc2ad9d8,0x8f4753ca,0x569c05a9,0x8eb91ec1,0x27e13f11,0x4abbd1ae}},
		{{0xb2c11f4c,0x616f6644,0x0e540758,0x251cd714,0x10f02017,0xf927a401,0xc1c941b6,0x92ff3cc3}, {0x13f565fe,0x32499062,0xeb9dbd4e,0x4633e3dd,0xc402e6c2,0xea9a9d1e,0xb14bb7cf,0xdc84ce34}},
		{{0x436ff69a,0xa93e23e5,0x9b63efce,0x52dcb0a7,0x9e90cb41,0x34f6538a,0x00234bc0,0x9cac08f2}, {0x5174a02d,0x6661825b,0xe036be57,0x07d4d06d,0x0ae6bd27,0x589d7461,0x7fc91a93,0xa296f557}},
		{{0xd29721d0,0x10acefa9,0xb5bcd340,0x8b0f6b8b,0x3d86785c,0x921d318c,0xc16aa378,0xd6916f3b}, {0x7ad84a0e,0x2a0d646a,0x2fe7e97a,0x7b93256c,0x26479e41,0x5765e276,0x2daaced3,0xae9da227}},
		{{0xf7f34ac5,0x56fdc215,0xda3877d3,0xebcb4ff2,0xaba6b832,0x1eb96792,0xa24741aa,0x807ce6be}, {0x9c721fb4,0xff1c1010,0x796353a7,0xd187d4bc,0x9af2d303,0x7639ae74,0xd56c9286,0xaff6d783}},
		{{0x6290dd01,0x6002d51b,0x99a836a5,0xcba3ab00,0xe00d2528,0x71776611,0x87fce119,0xfaf2cb8c}, {0xdf6882ae,0xd445228b,0x7cbce919,0xcbbfade1,0xa2eb2453,0x837b6335,0x8597f6b6,0x11ad7c4b}},
		{{0x8cf2e399,0x48de8f36,0x30a74277,0x7ae3d256,0xc505323f,0xdef1a9a6,0x4b8d9672,0xe55f203b}, {0x9a1e6e97,0xc58d8f0d,0xb2737a76,0xe160e6d4,0xd47cbdd8,0xd60bd087,0x4d5fef53,0x687d4136}},
		{{0x056bbf9b,0x83f21bbe,0x0b4ba5ab,0x4c2a9d12,0x45b64e4f,0xff383d18,0x06dd7867,0x8f13cc8d}, {0x424f0995,0xf3a292d8,0xe7cbe44b,0xfd2546ea,0x6c1e75a3,0x67d14dee,0xc93fb5a8,0x53b49e6c}},
	};
	
	unsigned int k[M];
	int i, j, flag;
	unsigned int u1, u2;
	projpoint q = {{1}, {1}, {0}};
	
	for(i=0; i<DIG_LEN; i++)
	{
		for(j=0; j<32; j++)
		{
			k[32*i+j] = (n[i] >> j) & 0x1;
		}
	}
	for(i=31; i>=0; i--)
	{
		projpointdouble(&q, &q);
		u1 = k[i]^(k[64+i]<<1)^(k[128+i]<<2)^(k[192+i]<<3);
		if(u1 != 0) mixpointadd(&q, &q, &pre1[u1]);
		u2 = k[32+i]^(k[96+i]<<1)^(k[160+i]<<2)^(k[224+i]<<3);
		if(u2 != 0) mixpointadd(&q, &q, &pre2[u2]);
	}
	
	for(flag=1,i=0; i<DIG_LEN; i++)
	{
		if(q.z[i] != 0)
		{
		    flag = 0;
		    break;
		}
	}
	if(flag)
	{
		for(i=0; i<DIG_LEN; i++)
		{
			p->x[i] = 0; p->y[i] = 0;
		}
		return;
	}
	else
	{
		squ(p->x, q.z);
		mul(p->x, p->x, q.z);
		inv(p->x, p->x);
		mul(p->y, q.y, p->x);
		mul(p->x, q.z, p->x);
		mul(p->x, q.x, p->x);
	}
}

/***************************************************
* function			   : pointVerify
* description		   : 验证点是否在曲线上，不包含无穷远点
* parameters:
	-- q[in]		   : 点

* return 			   : 0--success;
						 非0--error code
***************************************************/
int pointVerify(epoint q)
{
	int i;
	small g[DIG_LEN], h[DIG_LEN],l[DIG_LEN], m;
    
	squ(g, q->x); 
	add(g, g, (small*)A); 
	mul(g, g, q->x); 
	add(g, g, (small*)B);
	// g = x^3 + Ax +B;
    squ(h, q->y); 
	for(i=0; i<DIG_LEN; i++)
	{
        l[i] = g[i]-h[i];
	}
    m = 0;
    for (i=0; i<DIG_LEN; i++) 
	{
		m |= l[i];
	}
	// Q点不在曲线上
	if (m != 0) 
	{
		return(-1);
	}
    return(0);
}

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
void KDF(unsigned char *data, unsigned int data_len, unsigned int key_len,unsigned char *key)
{
	unsigned int multiple = 0;
	unsigned int remainder = 0;
	unsigned int ct = 0x1;
	unsigned int i;
	unsigned char temp[388];	
	multiple = key_len/32;
	remainder = key_len%32;
    for(i=0; i<data_len; i++)
		temp[i] = data[i];
	for(i=0; i<multiple; i++)
	{
		*(temp+data_len) = (unsigned char)(ct>>24);
		*(temp+data_len+1) = (unsigned char)(ct>>16);
		*(temp+data_len+2) = (unsigned char)(ct>>8);
		*(temp+data_len+3) = (unsigned char)(ct);
		SM3_HASH(temp, data_len+4, data_len+4, key+32*i, 32, 0);
		ct++;
	}
	if(remainder != 0)
	{
		*(temp+data_len) = (unsigned char)(ct>>24);
		*(temp+data_len+1) = (unsigned char)(ct>>16);
		*(temp+data_len+2) = (unsigned char)(ct>>8);
		*(temp+data_len+3) = (unsigned char)(ct);
		SM3_HASH(temp, data_len+4, data_len+4, key+32*multiple, remainder, 0);
	}

}
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
			   unsigned char *pk, unsigned int *pk_len, int type)
{
	int i, j;
	unsigned int prikey[DIG_LEN]={0};
	unsigned int x;
	affpoint pubkey;

	if (sk_len != 4*DIG_LEN) 
	{
		return(-1);
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		prikey[DIG_LEN-1-i] = (((unsigned int)(sk[j]) << 24) | ((unsigned int)(sk[j+1]) << 16)
					| ((unsigned int)(sk[j+2]) << 8) | ((unsigned int)(sk[j+3])));
	}
	
	basepointmul(&pubkey, prikey);

	x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= (pubkey.x[i] | pubkey.y[i]);
	}
	if (x == 0) 
	{
		return(-1); 
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		pk[j] = (unsigned char)((pubkey.x[DIG_LEN-1-i] >> 24) & 0xff);
		pk[j+1] = (unsigned char)((pubkey.x[DIG_LEN-1-i] >> 16) & 0xff);
		pk[j+2] = (unsigned char)((pubkey.x[DIG_LEN-1-i] >> 8) & 0xff);
		pk[j+3] = (unsigned char)((pubkey.x[DIG_LEN-1-i]) & 0xff);

		pk[j+4*DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN-1-i] >> 24) & 0xff);
		pk[j+1+4*DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN-1-i] >> 16) & 0xff);
		pk[j+2+4*DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN-1-i] >> 8) & 0xff);
		pk[j+3+4*DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN-1-i]) & 0xff);
	}

	*pk_len = 8*DIG_LEN;

	return(0);
}

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
			unsigned char *sign, unsigned int *sign_len)
{
	int i, j;
	unsigned int prikey[DIG_LEN] = {0};
	unsigned int rand[DIG_LEN] = {0};
	unsigned int e[DIG_LEN] = {0};
	unsigned int r[DIG_LEN] = {0};
	unsigned int s[DIG_LEN] = {0};
	unsigned int y[DIG_LEN] = {0};
	unsigned int h[DIG_LEN] = {0};
	unsigned int l[DIG_LEN] = {0};
	unsigned int m[DIG_LEN] = {0x1};
	unsigned int z[DIG_LEN] = {0x1};
	affpoint kg;
	unsigned int x;

	if (hash_len != 4*DIG_LEN)
	{
		return(-1);
	}
	if (random_len != 4*DIG_LEN)
	{
		return(-1);
	}
	if (sk_len != 4*DIG_LEN)
	{
		return(-1);
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		prikey[DIG_LEN-1-i] = (((unsigned int)(sk[j]) << 24) | ((unsigned int)(sk[j+1]) << 16)
					| ((unsigned int)(sk[j+2]) << 8) | ((unsigned int)(sk[j+3])));
	}
    x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= prikey[i];
	}
	if (x == 0) 
	{
		return(-1);
	}
	x = compare(prikey,(small*)N);
	if(x == 1)
	{
		return(-1);
    }
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		rand[DIG_LEN-1-i] = (((unsigned int)(random[j]) << 24) | ((unsigned int)(random[j+1]) << 16)
					| ((unsigned int)(random[j+2]) << 8) | ((unsigned int)(random[j+3])));
	}
    x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= rand[i];
	}
	if (x == 0) 
	{
		return(-1);
	}
	x = compare(rand,(small*)N);
	if(x == 1)
	{
		return(-1);
    }
	
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		e[DIG_LEN-1-i] = (((unsigned int)(hash[j]) << 24) | ((unsigned int)(hash[j+1]) << 16)
					| ((unsigned int)(hash[j+2]) << 8) | ((unsigned int)(hash[j+3])));
	}
    
	basepointmul(&kg, rand);

	for (i=0; i<DIG_LEN; i++) 
	{
		r[i] = kg.x[i]; 
	}
    modadd(r, e, r, (small*)N);

	x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= r[i];
	}
	if (x == 0) 
	{
		return(-1);
	}
    modadd(z, r, rand, (small*)N);
    x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= z[i];
	}
	if (x == 0) 
	{
		return(-1);
	}

    modadd(y, m, prikey, (small*)N);
	modinv(h, y, (small*)N);
	mulmodorder(y, r, prikey);
	modsub(l, rand, y, (small*)N);
	mulmodorder(s, h, l);

	x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= s[i];
	}
	if (x == 0) 
	{
		return(-1);
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		sign[j] = (unsigned char)((r[DIG_LEN-1-i] >> 24) & 0xff);
		sign[j+1] = (unsigned char)((r[DIG_LEN-1-i] >> 16) & 0xff);
		sign[j+2] = (unsigned char)((r[DIG_LEN-1-i] >> 8)&0xff);
		sign[j+3] = (unsigned char)((r[DIG_LEN-1-i]) & 0xff);

		sign[j+4*DIG_LEN] = (unsigned char)((s[DIG_LEN-1-i] >> 24) & 0xff);
		sign[j+1+4*DIG_LEN] = (unsigned char)((s[DIG_LEN-1-i] >> 16) & 0xff);
		sign[j+2+4*DIG_LEN] = (unsigned char)((s[DIG_LEN-1-i] >> 8) & 0xff);
		sign[j+3+4*DIG_LEN] = (unsigned char)((s[DIG_LEN-1-i]) & 0xff);
	}

	*sign_len = 8 * DIG_LEN;

	return(0);
}

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
			  unsigned char *sign, unsigned int sign_len)
{
	int i, j;
	unsigned int t[DIG_LEN] = {0};
	unsigned int r[DIG_LEN] = {0};
	unsigned int s[DIG_LEN] = {0};
	unsigned int e[DIG_LEN] = {0};
	unsigned int R[DIG_LEN] = {0};
	affpoint p1, p2, p3;
	unsigned int x;

	if (hash_len != 4*DIG_LEN) 
	{
		return(-1);
	}
	if (pk_len != 8*DIG_LEN) 
	{
		return(-1);
	}
	if (sign_len != 8*DIG_LEN) 
	{
		return(-1);
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		p1.x[DIG_LEN-1-i] = (((unsigned int)(pk[j]) << 24) | ((unsigned int)(pk[j+1]) << 16)
					| ((unsigned int)(pk[j+2])<<8) | ((unsigned int)(pk[j+3])));
		p1.y[DIG_LEN-1-i] = (((unsigned int)(pk[j+4*DIG_LEN]) << 24) | ((unsigned int)(pk[j+1+4*DIG_LEN]) << 16)
					| ((unsigned int)(pk[j+2+4*DIG_LEN]) << 8) | ((unsigned int)(pk[j+3+4*DIG_LEN])));
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		r[DIG_LEN-1-i] = (((unsigned int)(sign[j]) << 24) | ((unsigned int)(sign[j+1]) << 16)
					| ((unsigned int)(sign[j+2]) << 8) | ((unsigned int)(sign[j+3])));
		s[DIG_LEN-1-i] = (((unsigned int)(sign[j+4*DIG_LEN]) << 24)|((unsigned int)(sign[j+1+4*DIG_LEN]) << 16)
					| ((unsigned int)(sign[j+2+4*DIG_LEN]) << 8)|((unsigned int)(sign[j+3+4*DIG_LEN])));
	}

	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		e[DIG_LEN-1-i] = (((unsigned int)(hash[j]) << 24)|((unsigned int)(hash[j+1]) << 16)
					| ((unsigned int)(hash[j+2]) << 8) | ((unsigned int)(hash[j+3])));
	}

	x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= r[i];
	}
	if (x == 0) 
	{
		return(-1);
	}
    x = compare(r, (small*)N);
	if(x == 1)
	{
		return(-1);
	}

	x = 0; 
	for (i=0; i<DIG_LEN; i++)
	{
		x |= s[i];
	}
	if (x == 0) 
	{
		return(-1);
	}
	x = compare(s, (small*)N);
	if(x == 1)
	{
		return(-1);
	}
    
	modadd(t, r, s, (small*)N);

    x = 0; 
	for (i=0; i<DIG_LEN; i++)
	{
		x |= t[i];
	}
	if (x == 0) 
	{
		return(-1);
	}

    basepointmul(&p2, s);
    pointmul(&p3, &p1, t);
    pointadd(&p1, &p2, &p3);

    modadd(R, p1. x, e, (small*)N);

    x = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		x |= (R[i] ^ r[i]);
	}
	if (x != 0) 
	{
		return(-1);
	}

	return(0);
}

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
				unsigned char *cipher, unsigned int *cipher_len)
{
	int i, j, multiple, remainder;
	unsigned int y, rand[DIG_LEN] = {0};
	affpoint p;
	unsigned char x[8*DIG_LEN], t[96];
			  
	if (random_len != 4*DIG_LEN)
	{
		return(-1);
	}
			  
	if (pk_len != 8*DIG_LEN) 
	{
		return(-1);
	}
			  
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		rand[DIG_LEN-1-i] = (((unsigned int)(random[j]) << 24) | ((unsigned int)(random[j+1]) << 16)
								  | ((unsigned int)(random[j+2]) << 8) | ((unsigned int)(random[j+3])));
	}
	y = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		y |= rand[i];
	}
	if (y == 0) 
	{
		return(-1);
	}
	y=compare(rand,(small*)N);
	if(y==1)
	{
		return(-1);
	}
	basepointmul(&p, rand);
			  
	y = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		y |= (p.x[i] | p.y[i]);
	}
	if (y == 0) 
	{
		return(-1);
	}
			  
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		cipher[j] = (unsigned char)((p.x[DIG_LEN-1-i] >> 24) & 0xff);
		cipher[j+1] = (unsigned char)((p.x[DIG_LEN-1-i] >> 16) & 0xff);
		cipher[j+2] = (unsigned char)((p.x[DIG_LEN-1-i] >> 8) & 0xff);
		cipher[j+3] = (unsigned char)((p.x[DIG_LEN-1-i]) & 0xff);
			  
		cipher[j+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 24) & 0xff);
		cipher[j+1+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 16) & 0xff);
		cipher[j+2+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 8) & 0xff);
		cipher[j+3+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i]) & 0xff);
	}
			  
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		p.x[DIG_LEN-1-i] = (((unsigned int)(pk[j]) << 24) | ((unsigned int)(pk[j+1]) << 16)
								  | ((unsigned int)(pk[j+2]) << 8) | ((unsigned int)(pk[j+3])));
		p.y[DIG_LEN-1-i] = (((unsigned int)(pk[j+4*DIG_LEN]) << 24) | ((unsigned int)(pk[j+1+4*DIG_LEN]) << 16)
								  | ((unsigned int)(pk[j+2+4*DIG_LEN]) << 8) | ((unsigned int)(pk[j+3+4*DIG_LEN])));
	}
	pointmul(&p, &p, rand);
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		x[j] = (unsigned char)((p.x[DIG_LEN-1-i] >> 24) & 0xff);
		x[j+1] = (unsigned char)((p.x[DIG_LEN-1-i] >> 16) & 0xff);
		x[j+2] = (unsigned char)((p.x[DIG_LEN-1-i] >> 8) & 0xff);
		x[j+3] = (unsigned char)((p.x[DIG_LEN-1-i]) & 0xff);
			  
		x[j+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 24) & 0xff);
		x[j+1+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 16) & 0xff);
		x[j+2+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 8) & 0xff);
		x[j+3+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i]) & 0xff);
	}
				  
	// 加密
	KDF(x, pk_len, plain_len,cipher+8*DIG_LEN);
				  
	y = 0; 
	for (i=0; i<(int)plain_len; i++) 
	{
		y |= cipher[8*DIG_LEN+i];
	}
	if (y == 0) 
	{
		return(-1);
	}
	for (i=0; i<(int)plain_len; i++)
	{   
		cipher[8*DIG_LEN+i] ^= plain[i];
	}
	if(plain_len < 33)
	{
		for(i=0; i<32; i++)
			t[i] = x[i];
		for(i=0; i<(int)plain_len; i++)
			t[32+i] = plain[i];
		for(i=32+plain_len; i<(int)(pk_len+plain_len); i++)
			t[i] = x[i-plain_len];
		SM3_HASH(t, pk_len+plain_len, pk_len+plain_len,cipher+pk_len+plain_len, 32, 0);
	}
	else
	{
		for(i=0; i<32; i++)
			t[i] = x[i];
		for(i=0; i<32; i++)
			t[32+i] = plain[i];
		SM3_HASH(t, 64, 64+plain_len, cipher+8*DIG_LEN+plain_len, 32, 1);
		multiple = (plain_len-32)/64;
		remainder = (plain_len-32)%64;
		if(multiple != 0)
			SM3_HASH(plain+32, 64*multiple, 64+plain_len, cipher+8*DIG_LEN+plain_len, 32, 2);
		for(i=0; i<remainder; i++)
			t[i] = plain[32+64*multiple+i];
		for(i=remainder; i<32+remainder; i++)
			t[i] = x[i+32-remainder];
		SM3_HASH(t, 32+remainder, pk_len+plain_len, cipher+pk_len+plain_len, 32, 3);
	}
	cipher_len[0] = 8*DIG_LEN+plain_len+32;
				  
	return(0);
}
			  
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
			unsigned char *plain, unsigned int *plain_len)
{
	int i, j,multiple,remainder;
	unsigned int prikey[DIG_LEN] = {0};
	affpoint p;
	unsigned char y, u[32];
	unsigned char x[8*DIG_LEN], t[96];

    // 判断密文是否有效，无效则返回错误
	if((int)cipher_len < 8*DIG_LEN+32)
	{
		return(-1);
	}
	// 判断私钥是否有效，无效则返回错误
	if(sk_len != 4*DIG_LEN)
	{
		return(-1);
	}
			  
	for(i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		p.x[DIG_LEN-1-i] = (((unsigned int)(cipher[j]) << 24) | ((unsigned int)(cipher[j+1]) << 16)
						| ((unsigned int)(cipher[j+2]) << 8) | ((unsigned int)(cipher[j+3])));
		p.y[DIG_LEN-1-i] = (((unsigned int)(cipher[j+4*DIG_LEN]) << 24) | ((unsigned int)(cipher[j+1+4*DIG_LEN]) << 16)
						| ((unsigned int)(cipher[j+2+4*DIG_LEN]) << 8) | ((unsigned int)(cipher[j+3+4*DIG_LEN])));
	}
    // 判断C1是否是曲线上的点，不是则返回错误
	if(pointVerify(&p) == -1)
		return (-1);
			  
	for(i=0,j=0; i<DIG_LEN; i++,j+=4)
		prikey[DIG_LEN-1-i] = (((unsigned int)(sk[j]) << 24) | ((unsigned int)(sk[j+1]) << 16)
						| ((unsigned int)(sk[j+2]) << 8) | ((unsigned int)(sk[j+3])));
				  
	y = 0; 
	for(i=0; i<DIG_LEN; i++)
	{
		y |= prikey[i];
	}
	if(y == 0)
	{
		return(-1);
	}
	y = compare(prikey,(small*)N);
	if(y == 1)
	{
		return(-1);
	}
	pointmul(&p, &p, prikey);
				  
	y = 0; 
	for (i=0; i<DIG_LEN; i++) 
	{
		y |= (p.x[i] | p.y[i]);
	}
	if (y == 0) 
	{
		return(-1);
	}
			  
	for (i=0,j=0; i<DIG_LEN; i++,j+=4)
	{
		x[j] = (unsigned char)((p.x[DIG_LEN-1-i] >> 24) & 0xff);
		x[j+1] = (unsigned char)((p.x[DIG_LEN-1-i] >> 16) & 0xff);
		x[j+2] = (unsigned char)((p.x[DIG_LEN-1-i] >> 8) & 0xff);
		x[j+3] = (unsigned char)((p.x[DIG_LEN-1-i]) & 0xff);
			  
		x[j+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 24) & 0xff);
		x[j+1+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 16) & 0xff);
		x[j+2+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i] >> 8) & 0xff);
		x[j+3+4*DIG_LEN] = (unsigned char)((p.y[DIG_LEN-1-i]) & 0xff);
	}
			  
	// 解密
	KDF(x, 64, cipher_len-96, plain);
				  
	y = 0; 
	for (i=0; i<(int)cipher_len-96; i++) 
	{
		y |= plain[i];
	}
	if (y == 0) 
	{
		return(-1);
	}
	for (i=0; i<(int)cipher_len-96; i++)
	{
		plain[i] ^= cipher[64+i];
	}
	plain_len[0] = cipher_len-96;
			  
	if((int)(*plain_len) < 33)
	{
		for(i=0; i<32; i++)
			t[i] = x[i];
		for(i=0; i<(int)(*plain_len); i++)
			t[32+i] = plain[i];
		for(i = 32+(*plain_len); i<(int)(64+(*plain_len)); i++)
			t[i] = x[i-(*plain_len)];
		SM3_HASH(t, 64+(*plain_len), 64+(*plain_len), u, 32, 0);
	}
	else
	{
		for(i=0; i<32; i++)
			t[i] = x[i];
		for(i=0; i<32; i++)
			t[32+i] = plain[i];
		SM3_HASH(t, 64, 64+(*plain_len), u, 32, 1);
		multiple = ((*plain_len)-32)/64;
		remainder = ((*plain_len)-32)%64;
		if(multiple != 0)
			SM3_HASH(plain+32, 64*multiple, 64+(*plain_len),u, 32, 2);
		for(i=0; i<remainder; i++)
			t[i] = plain[32+64*multiple+i];
		for(i = remainder; i<32+remainder; i++)
			t[i] = x[i+32-remainder];
		SM3_HASH(t, 32+remainder, 64+(*plain_len), u, 32, 3);
	}
			  
	for(i=0; i<32; i++)
	{
		if(u[i] != *(cipher+cipher_len-32+i))
			return (-1);
	}	  
	return(0);
}
