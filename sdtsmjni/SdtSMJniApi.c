#include <memory.h>
#include "org_bcia_javachain_csp_gm_sdt_jni_SMJniApi.h"
#include "SdtSM.h"

#define MAX_OUT_LEN				4096
#define MAX_BUFFER_LEN          4096
#define DEFAULT_BUFFER_LEN      256

#define SUCCESS           0
#define JNIERR_BASE       1100
#define JNIERR_PARAM      (JNIERR_BASE+1)
#define JNIERR_MEMORY     (JNIERR_BASE+2)


int uint2uchar(unsigned int res, unsigned char* tag)
{
	tag[0] = (unsigned char) ((res >> 24) & 0xff);
	tag[1] = (unsigned char) ((res >> 16) & 0xff);
	tag[2] = (unsigned char) ((res >> 8) & 0xff);
	tag[3] = (unsigned char) (res  & 0xff);
	return SUCCESS;
}

int uchar2uint(unsigned int* tag, unsigned char* res)
{
	int addr = 0;
	addr = res[0] & 0xff;
	addr = (addr << 8) | (res[1] & 0xff);
	addr = (addr << 8) | (res[2] & 0xff);
	addr = (addr << 8) | (res[3] & 0xff);
	*tag = addr;
	return SUCCESS;
}

int getPtrArray(JNIEnv *env, jbyteArray bytearray, jbyte** bytesPtrPtr)
{
	jboolean isCopy = 0;
	if(NULL == bytearray)
	{
		(*bytesPtrPtr) = NULL;
		return JNIERR_PARAM;
	}

 	(*bytesPtrPtr) = (*env)->GetByteArrayElements(env, bytearray, &isCopy);

	if(NULL == *bytesPtrPtr)
	{
		return SUCCESS;
	}

	return JNIERR_PARAM;
}

void releasePtrArray(JNIEnv *env, jbyteArray bytearray, jbyte* bytesPtr)
{
	if(NULL == bytesPtr)
	{
		return;
	}	
	(*env)->ReleaseByteArrayElements(env, bytearray, bytesPtr, 0);
}

/*
 * Class:     org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:    nRandomGen
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nRandomGen
  (JNIEnv *env, jobject obj, jint length)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	jclass clazz;
	int iRet = 0;
	unsigned char ucRandom[MAX_BUFFER_LEN] = {0};
	unsigned int uiRandomLen = 0;
	//check length
	if(0 > length)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	uiRandomLen = (unsigned int)length;
	iRet = sdt_random_gen(ucRandom, uiRandomLen);
	//random data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucRandom, uiRandomLen);
		uiOutDataLen = uiRandomLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM2MakeKey
 * Signature: ([BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM2MakeKey
	(JNIEnv *env, jobject obj, jbyteArray sk, jint skLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucSk = NULL;
	unsigned int uiSkLen = 0;
	unsigned char ucPk[DEFAULT_BUFFER_LEN] = {0};
	unsigned int uiPkLen = DEFAULT_BUFFER_LEN;
	jclass clazz;
	int iRet = 0;
	jbyte *pjbSk = NULL;
	//check length
	if(0 > skLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	
	if(!getPtrArray(env, sk, &pjbSk))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbSk)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	pucSk = (unsigned char *)pjbSk;
	uiSkLen = (unsigned int)skLen;
	/////////////////////////////////////////////////////////////
	iRet = sdt_ecc_makekey(pucSk, uiSkLen, ucPk, &uiPkLen);
	
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucPk, uiPkLen);
		uiOutDataLen += uiPkLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class:	  org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	  nSM2KDF
 * Signature: ([BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM2KDF
  (JNIEnv *env, jobject obj, jbyteArray key, jint keyLen, jint length)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucKey = NULL;
	unsigned int uiKeyLen = 0;
	unsigned char ucDeriveKeyData[MAX_BUFFER_LEN] = {0};
	unsigned int uiDeriveLength = 0;
	jclass clazz;
	int iRet = 0;
	jbyte *pjbKey = NULL;	
	//check length
	if(0 > keyLen || 0 > length)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	
	if(!getPtrArray(env, key, &pjbKey))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbKey)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucKey = (unsigned char *)pjbKey;
	uiKeyLen = (unsigned int)keyLen;
	uiDeriveLength = (unsigned int)length;
	iRet = sdt_kdf(pucKey, uiKeyLen, uiDeriveLength, ucDeriveKeyData);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucDeriveKeyData, uiDeriveLength);
		uiOutDataLen += uiDeriveLength;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, key, pjbKey);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}
  
/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM2Sign
 * Signature: ([BI[BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM2Sign
  (JNIEnv *env, jobject obj, jbyteArray hash, jint hashLen, jbyteArray random, jint randomLen, jbyteArray sk, jint skLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucHash = NULL;
	unsigned int uiHashLen = 0;
	unsigned char *pucRandom = NULL;
	unsigned int uiRandomLen = 0;
	unsigned char *pucSk = NULL;
	unsigned int uiSkLen = 0;
	unsigned char ucSignData[DEFAULT_BUFFER_LEN] = {0};
	unsigned int uiSignDataLen = DEFAULT_BUFFER_LEN;
	jclass clazz;
	int iRet = 0;
	jbyte *pjbHash = NULL;
	jbyte *pjbRandom = NULL;
	jbyte *pjbSk = NULL;
	//check length
	if(0 > hashLen || 0 > randomLen || 0 > skLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	
	if(!getPtrArray(env, hash, &pjbHash) \
		|| !getPtrArray(env, random, &pjbRandom) \
		|| !getPtrArray(env, sk, &pjbSk))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbHash || NULL == pjbRandom || NULL == pjbSk)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucHash = (unsigned char *)pjbHash;
	uiHashLen = (unsigned int)hashLen;
	pucRandom = (unsigned char *)pjbRandom;
	uiRandomLen = (unsigned int)randomLen;
	pucSk = (unsigned char *)pjbSk;
	uiSkLen = (unsigned int)skLen;
	iRet = sdt_ecc_sign(pucHash, uiHashLen, pucRandom, uiRandomLen, pucSk, uiSkLen, ucSignData, &uiSignDataLen);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucSignData, uiSignDataLen);
		uiOutDataLen += uiSignDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, hash, pjbHash);
	releasePtrArray(env, random, pjbRandom);
	releasePtrArray(env, sk, pjbSk);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM2Verify
 * Signature: ([BI[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM2Verify
  (JNIEnv *env, jobject obj, jbyteArray hash, jint hashLen, jbyteArray pk, jint pkLen, jbyteArray signData, jint signDataLen)
{
	unsigned char *pucHash = NULL;
	unsigned int uiHashLen = 0;
	unsigned char *pucPk = NULL;
	unsigned int uiPkLen = 0;
	unsigned char *pucSignData = NULL;
	unsigned int uiSignDataLen = 0;
	int iRet = 0;
	jbyte *pjbHash = NULL;
	jbyte *pjbPk = NULL;
	jbyte *pjbSignData = NULL;
	//check length
	if(0 > hashLen || 0 > pkLen || 0 > signDataLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	if(!getPtrArray(env, hash, &pjbHash) \
		|| !getPtrArray(env, pk, &pjbPk) \
		|| !getPtrArray(env, signData, &pjbSignData))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbHash || NULL == pjbPk || NULL == pjbSignData)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucHash = (unsigned char *)pjbHash;
	uiHashLen = (unsigned int)hashLen;
	pucPk = (unsigned char *)pjbPk;
	uiPkLen = (unsigned int)pkLen;
	pucSignData = (unsigned char *)pjbSignData;
	uiSignDataLen = (unsigned int)signDataLen;
	iRet = sdt_ecc_verify(pucHash, uiHashLen, pucPk, uiPkLen, pucSignData, uiSignDataLen);
	
F_EXIT:
	releasePtrArray(env, hash, pjbHash);
	releasePtrArray(env, pk, pjbPk);
	releasePtrArray(env, signData, pjbSignData);
	return (jint)iRet;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM2Encrypt
 * Signature: ([BI[BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM2Encrypt
  (JNIEnv *env, jobject obj, jbyteArray plainData, jint plainDataLen, jbyteArray random, jint randomLen, jbyteArray pk, jint pkLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucPlainData = NULL;
	unsigned int uiPlainDataLen = 0;
	unsigned char *pucRandom = NULL;
	unsigned int uiRandomLen = 0;
	unsigned char *pucPk = NULL;
	unsigned int uiPkLen = 0;
	unsigned char ucCipherData[MAX_BUFFER_LEN] = {0};
	unsigned int uiCipherDataLen = MAX_BUFFER_LEN;
	jclass clazz;
	int iRet = 0;
	jbyte *pjbPlainData = NULL;
	jbyte *pjbRandom = NULL;
	jbyte *pjbPk = NULL;
	//check length
	if(0 > plainDataLen || 0 > randomLen || 0 > pkLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	
	if(!getPtrArray(env, plainData, &pjbPlainData) \
		|| !getPtrArray(env, random, &pjbRandom) \
		|| !getPtrArray(env, pk, &pjbPk))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbPlainData || NULL == pjbRandom || NULL == pjbPk)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucPlainData = (unsigned char *)pjbPlainData;
	uiPlainDataLen = (unsigned int)plainDataLen;
	pucRandom = (unsigned char *)pjbRandom;
	uiRandomLen = (unsigned int)randomLen;
	pucPk = (unsigned char *)pjbPk;
	uiPkLen = (unsigned int)pkLen;
	iRet = sdt_ecc_encrypt(pucPlainData, uiPlainDataLen, pucRandom, uiRandomLen, pucPk, uiPkLen, ucCipherData, &uiCipherDataLen);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucCipherData, uiCipherDataLen);
		uiOutDataLen += uiCipherDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, plainData, pjbPlainData);
	releasePtrArray(env, random, pjbRandom);
	releasePtrArray(env, pk, pjbPk);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM2Decrypt
 * Signature: ([BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM2Decrypt
  (JNIEnv *env, jobject obj, jbyteArray cipherData, jint cipherDataLen, jbyteArray sk, jint skLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucCipherData = NULL;
	unsigned int uiCipherDataLen = 0;
	unsigned char *pucSk = NULL;
	unsigned int uiSkLen = 0;
	unsigned char ucPlainData[MAX_BUFFER_LEN] = {0};
	unsigned int uiPlainDataLen = MAX_BUFFER_LEN;
	jclass clazz;
	int iRet = 0;
	jbyte *pjbCipherData = NULL;
	jbyte *pjbSk = NULL;
	//check length
	if(0 > cipherDataLen || 0 > skLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	
	if(!getPtrArray(env, cipherData, &pjbCipherData) \
		|| !getPtrArray(env, sk, &pjbSk))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbCipherData || NULL == pjbSk)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucCipherData = (unsigned char *)pjbCipherData;
	uiCipherDataLen = (unsigned int)cipherDataLen;
	pucSk = (unsigned char *)pjbSk;
	uiSkLen = (unsigned int)skLen;
	iRet = sdt_ecc_decrypt(pucCipherData, uiCipherDataLen, pucSk, uiSkLen, ucPlainData, &uiPlainDataLen);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucPlainData, uiPlainDataLen);
		uiOutDataLen += uiPlainDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, cipherData, pjbCipherData);
	releasePtrArray(env, sk, pjbSk);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM3Hash
 * Signature: ([BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM3Hash
  (JNIEnv *env, jobject obj, jbyteArray message, jint messageLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucMessage = NULL;
	unsigned int uiMessageLen = 0;
	unsigned char ucHashData[DEFAULT_BUFFER_LEN] = {0};
	unsigned int uiHashDataLen = DEFAULT_BUFFER_LEN;
	
	jclass clazz;
	int iRet = 0;
	jbyte *pjbMessage = NULL;
	//check length
	if(0 > messageLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	
	if(!getPtrArray(env, message, &pjbMessage))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbMessage)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucMessage = (unsigned char *)pjbMessage;
	uiMessageLen = (unsigned int)messageLen;
	iRet = sdt_hash(pucMessage, uiMessageLen, ucHashData, &uiHashDataLen);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucHashData, uiHashDataLen);
		uiOutDataLen += uiHashDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, message, pjbMessage);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM4ECBEncrypt
 * Signature: ([BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM4ECBEncrypt
  (JNIEnv *env, jobject obj, jbyteArray key, jint keyLen, jbyteArray plainData, jint plainDataLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucKey = NULL;
	unsigned int uiKeyLen = 0;
	unsigned char *pucPlainData = NULL;
	unsigned int uiPlainDataLen = 0;
	unsigned char ucCipherData[MAX_BUFFER_LEN] = {0};
	unsigned int uiCipherDataLen = MAX_BUFFER_LEN;
	
	jclass clazz;
	int iRet = 0;
	jbyte *pjbKey = NULL;
	jbyte *pjbPlainData = NULL;
	//check length
	if(0 > keyLen || 0 > plainDataLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	if(!getPtrArray(env, key, &pjbKey) || !getPtrArray(env, plainData, &pjbPlainData))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbKey || NULL == pjbPlainData)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucKey = (unsigned char *)pjbKey;
	uiKeyLen = (unsigned int)keyLen;
	pucPlainData = (unsigned char *)pjbPlainData;
	uiPlainDataLen = (unsigned int)plainDataLen;
	uiCipherDataLen = uiPlainDataLen;
	iRet = sdt_symm_ecb_enc(pucKey, uiKeyLen, pucPlainData, uiPlainDataLen, ucCipherData);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucCipherData, uiCipherDataLen);
		uiOutDataLen += uiCipherDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, key, pjbKey);
	releasePtrArray(env, plainData, pjbPlainData);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM4ECBDecrypt
 * Signature: ([BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM4ECBDecrypt
  (JNIEnv *env, jobject obj, jbyteArray key, jint keyLen, jbyteArray cipherData, jint cipherDataLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucKey = NULL;
	unsigned int uiKeyLen = 0;
	unsigned char *pucCipherData = NULL;
	unsigned int uiCipherDataLen = 0;
	unsigned char ucPlainData[MAX_BUFFER_LEN] = {0};
	unsigned int uiPlainDataLen = MAX_BUFFER_LEN;
	
	jclass clazz;
	int iRet = 0;
	jbyte *pjbKey = NULL;
	jbyte *pjbCipherData = NULL;
	//check length
	if(0 > keyLen || 0 > cipherDataLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	if(!getPtrArray(env, key, &pjbKey) || !getPtrArray(env, cipherData, &pjbCipherData))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbKey || NULL == pjbCipherData)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucKey = (unsigned char *)pjbKey;
	uiKeyLen = (unsigned int)keyLen;
	pucCipherData = (unsigned char *)pjbCipherData;
	uiCipherDataLen = (unsigned int)cipherDataLen;
	uiPlainDataLen = uiCipherDataLen;
	iRet = sdt_symm_ecb_dec(pucKey, uiKeyLen, pucCipherData, uiCipherDataLen, ucPlainData);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucPlainData, uiPlainDataLen);
		uiOutDataLen += uiPlainDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, key, pjbKey);
	releasePtrArray(env, cipherData, pjbCipherData);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}
  
/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM4CBCEncrypt
 * Signature: ([BI[BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM4CBCEncrypt
  (JNIEnv *env, jobject obj, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen, jbyteArray plainData, jint plainDataLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucKey = NULL;
	unsigned int uiKeyLen = 0;
	unsigned char *pucIv = NULL;
	unsigned int uiIvLen = 0;
	unsigned char *pucPlainData = NULL;
	unsigned int uiPlainDataLen = 0;
	unsigned char ucCipherData[MAX_BUFFER_LEN] = {0};
	unsigned int uiCipherDataLen = MAX_BUFFER_LEN;
	
	jclass clazz;
	int iRet = 0;
	jbyte *pjbKey = NULL;
	jbyte *pjbIv = NULL;
	jbyte *pjbPlainData = NULL;
	//check length
	if(0 > keyLen || 0 > ivLen || 0 > plainDataLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	if(!getPtrArray(env, key, &pjbKey) \
		|| !getPtrArray(env, iv, &pjbIv) \
		|| !getPtrArray(env, plainData, &pjbPlainData))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbKey || NULL == pjbIv || NULL == pjbPlainData)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucKey = (unsigned char *)pjbKey;
	uiKeyLen = (unsigned int)keyLen;
	pucIv = (unsigned char *)pjbIv;
	uiIvLen = (unsigned int)ivLen;
	pucPlainData = (unsigned char *)pjbPlainData;
	uiPlainDataLen = (unsigned int)plainDataLen;
	uiCipherDataLen = uiPlainDataLen;
	iRet = sdt_symm_cbc_enc(pucKey, uiKeyLen, pucIv, uiIvLen, pucPlainData, uiPlainDataLen, ucCipherData);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucCipherData, uiCipherDataLen);
		uiOutDataLen += uiCipherDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, key, pjbKey);
	releasePtrArray(env, iv, pjbIv);
	releasePtrArray(env, plainData, pjbPlainData);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
}

/*
 * Class: 	org_bcia_javachain_csp_gm_sdt_jni_SMJniApi
 * Method:	nSM4CBCDecrypt
 * Signature: ([BI[BI[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_bcia_javachain_csp_gm_sdt_jni_SMJniApi_nSM4CBCDecrypt
  (JNIEnv *env, jobject obj, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen, jbyteArray cipherData, jint cipherDataLen)
{
	jbyteArray jbaOutData = NULL;
	unsigned char ucOutData[MAX_OUT_LEN] = {0x0};
	unsigned int uiOutDataLen = 0;
	unsigned char ucErrorStr[12] = {0x0};
	unsigned char *pucKey = NULL;
	unsigned int uiKeyLen = 0;
	unsigned char *pucIv = NULL;
	unsigned int uiIvLen = 0;
	unsigned char *pucCipherData = NULL;
	unsigned int uiCipherDataLen = 0;
	unsigned char ucPlainData[MAX_BUFFER_LEN] = {0};
	unsigned int uiPlainDataLen = MAX_BUFFER_LEN;
	
	jclass clazz;
	int iRet = 0;
	jbyte *pjbKey = NULL;
	jbyte *pjbIv = NULL;
	jbyte *pjbCipherData = NULL;
	//check length
	if(0 > keyLen || 0 > ivLen || 0 > cipherDataLen)
	{
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}
	if(!getPtrArray(env, key, &pjbKey) \
		|| !getPtrArray(env, iv, &pjbIv) \
		|| !getPtrArray(env, cipherData, &pjbCipherData))
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	if(NULL == pjbKey || NULL == pjbIv || NULL == pjbCipherData)
	{
		iRet = JNIERR_MEMORY;
		goto F_EXIT;
	}
	////////////////////////////////////////
	pucKey = (unsigned char *)pjbKey;
	uiKeyLen = (unsigned int)keyLen;
	pucIv = (unsigned char *)pjbIv;
	uiIvLen = (unsigned int)ivLen;
	pucCipherData = (unsigned char *)pjbCipherData;
	uiCipherDataLen = (unsigned int)cipherDataLen;
	uiPlainDataLen = uiCipherDataLen;
	iRet = sdt_symm_cbc_dec(pucKey, uiKeyLen, pucIv, uiIvLen, pucCipherData, uiCipherDataLen, ucPlainData);
	//copy data
	if (0 == iRet)
	{
		memcpy(ucOutData+uiOutDataLen, ucPlainData, uiPlainDataLen);
		uiOutDataLen += uiPlainDataLen;
	}
	//
	jbaOutData = (*env)->NewByteArray(env, uiOutDataLen);
	if(NULL == jbaOutData) {
		iRet = JNIERR_PARAM;
		goto F_EXIT;
	}

	(*env)->SetByteArrayRegion(env, jbaOutData, 0, uiOutDataLen, (jbyte*)ucOutData);
F_EXIT:
	releasePtrArray(env, key, pjbKey);
	releasePtrArray(env, iv, pjbIv);
	releasePtrArray(env, cipherData, pjbCipherData);
	if(0 != iRet){
		clazz = (*env)->FindClass(env, "java/lang/Exception");
		if(0 != clazz){
			sprintf((char*)ucErrorStr, "%d", iRet);
			(*env)->ThrowNew(env, clazz, (const char*)ucErrorStr);
		}
	}
	return jbaOutData;
} 
