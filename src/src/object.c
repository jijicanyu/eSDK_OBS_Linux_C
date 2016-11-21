/** **************************************************************************
 * object.c
 * 
 * Copyright 2008 Bryan Ischo <bryan@ischo.com>
 * 
 * This file is part of libs3.
 * 
 * libs3 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, version 3 of the License.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of this library and its programs with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * libs3 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with libs3, in a file named COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 ************************************************************************** **/

#include <stdlib.h>
#include <string.h>
#include "eSDKOBSS3.h"
#include "request.h"
#include "securec.h"


// DTS2015112500688 每次分配内存的大小 add by cwx298983 2015.11.26 Start
#define D_CMU_DATA_DEFAULT_LEN 2048
// DTS2015112500688 每次分配内存的大小 add by cwx298983 2015.11.26 End

// The number of seconds to an hour
#define SECONDS_TO_AN_HOUR 3600

/* _TRUNCATE */
#if !defined(_TRUNCATE)
#define _TRUNCATE ((size_t)-1)
#endif

// put object without server side encryption ----------------------------------------------------------------
//lint -e26 -e31 -e63 -e64 -e78 -e101 -e119 -e129 -e144 -e156 -e438 -e505 -e515 -e516 -e522 -e530 -e533 -e534 -e546 -e551 -e578 -e601
void S3_put_object(const S3BucketContext *bucketContext, const char *key,
                   uint64_t contentLength,
                   const S3PutProperties *putProperties,
                   S3RequestContext *requestContext,
                   const S3PutObjectHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_put_object successfully !");
	
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        0,                                            // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        putProperties,                                // putProperties
		0,                                            // ServerSideEncryptionParams
        handler->responseHandler.propertiesCallback,  // propertiesCallback
        handler->putObjectDataCallback,               // toS3Callback
        contentLength,                                // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        handler->responseHandler.completeCallback,    // completeCallback
        callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_put_object successfully !");
}

void PutObject(const S3BucketContext *bucketContext, const char *key,
                   uint64_t contentLength,
                   const S3PutProperties *putProperties,
                   S3RequestContext *requestContext,
                   const S3PutObjectHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter PutObject successfully !");
	S3_put_object(bucketContext,key,contentLength,putProperties,requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave PutObject successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");  
}


// put object with server side encryption ----------------------------------------------------------------
void S3_put_object_with_serverSideEncryption(const S3BucketContext *bucketContext, const char *key,
	uint64_t contentLength,
	const S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3PutObjectHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_put_object_with_serverSideEncryption successfully !");

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}
	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypePUT,                           // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,                                          // key
		0,                                            // queryParams
		0,                                            // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  // corsConf
		putProperties,                                // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		handler->responseHandler.propertiesCallback,  // propertiesCallback
		handler->putObjectDataCallback,               // toS3Callback
		contentLength,                                // toS3CallbackTotalSize
		0,                                            // fromS3Callback
		handler->responseHandler.completeCallback,    // completeCallback
		callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_put_object_with_serverSideEncryption successfully !");
}

void PutObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	uint64_t contentLength,
	const S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3PutObjectHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter PutObjectWithServerSideEncryption successfully !");
	S3_put_object_with_serverSideEncryption(bucketContext,key,contentLength,putProperties, serverSideEncryptionParams, requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave PutObjectWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");  
}


// copy object without server side encryption ---------------------------------------------------------------
typedef struct CopyObjectData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int64_t *lastModifiedReturn;
    int eTagReturnSize;
    char *eTagReturn;
    int eTagReturnLen;
    
    string_buffer(lastModified, 256);
} CopyObjectData;


static S3Status copyObjectXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)//lint !e528
{
    CopyObjectData *coData = (CopyObjectData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "CopyObjectResult/LastModified")) {
            string_buffer_append(coData->lastModified, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "CopyObjectResult/ETag")) {
            if (coData->eTagReturnSize && coData->eTagReturn) {
                coData->eTagReturnLen +=
                    snprintf_s(&(coData->eTagReturn[coData->eTagReturnLen]), coData->eTagReturnSize - coData->eTagReturnLen,
                             coData->eTagReturnSize - 
                             coData->eTagReturnLen - 1,
                             "%.*s", dataLen, data);
                if (coData->eTagReturnLen >= coData->eTagReturnSize) {
                    return S3StatusXmlParseFailure;
                }
            }
        }
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status copyObjectPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
	
    CopyObjectData *coData = (CopyObjectData *) callbackData;
    
    return (*(coData->responsePropertiesCallback))
        (responseProperties, coData->callbackData);
}


static S3Status copyObjectDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
	
    CopyObjectData *coData = (CopyObjectData *) callbackData;
	
    return simplexml_add(&(coData->simpleXml), buffer, bufferSize);
}


static void copyObjectCompleteCallback(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails,void *callbackData)//lint !e101
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    CopyObjectData *coData = (CopyObjectData *) callbackData;

    if (coData->lastModifiedReturn) {
        time_t lastModified = -1;
        if (coData->lastModifiedLen) {
            lastModified = parseIso8601Time(coData->lastModified);
		int nTimeZone = getTimeZone();
		lastModified += nTimeZone * SECONDS_TO_AN_HOUR;
        }

        *(coData->lastModifiedReturn) = lastModified;
    }

    (void)(*(coData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, coData->callbackData);

    simplexml_deinitialize(&(coData->simpleXml));

    free(coData);
	coData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void S3_copy_object(const S3BucketContext *bucketContext, const char *key,
                    const char *destinationBucket, const char *destinationKey,
                    const char *versionId,const S3PutProperties *putProperties,
                    int64_t *lastModifiedReturn, int eTagReturnSize,
                    char *eTagReturn, S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_copy_object successfully !");	
    CopyObjectData *data = 
        (CopyObjectData *) malloc(sizeof(CopyObjectData));
    if (!data) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc CopyObjectData failed !");	
        return;
    }
	memset_s(data, sizeof(CopyObjectData), 0, sizeof(CopyObjectData));
	
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		free(data);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		data = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(eTagReturnSize < 0 || NULL == destinationBucket || NULL == destinationKey){
		COMMLOG(OBS_LOGERROR, "eTagReturnSize < 0 or destinationBucket or destinationKey is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		free(data);    //zwx367245 2016.09.30 某些参数不正确的时候不能直接退出，要先释放内存再return
		data = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	
    simplexml_initialize(&(data->simpleXml), &copyObjectXmlCallback, data);//lint !e119
	
    data->responsePropertiesCallback = handler->propertiesCallback;
    data->responseCompleteCallback = handler->completeCallback;
    data->callbackData = callbackData;
    data->lastModifiedReturn = lastModifiedReturn;
    data->eTagReturnSize = eTagReturnSize;
    data->eTagReturn = eTagReturn;
    if (data->eTagReturnSize && data->eTagReturn) {
        data->eTagReturn[0] = 0;
    }
    data->eTagReturnLen = 0;
    string_buffer_initialize(data->lastModified);

	char versionkey[1024] = {0};
	if(versionId)
	{
		snprintf_s(versionkey,sizeof(versionkey), _TRUNCATE, 
				  "%s?versionId=%s",key,versionId);
	}
	
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeCOPY,                          // httpRequestType
        { bucketContext->hostName,                    // hostName
          //destinationBucket ? destinationBucket :   // zwx367245 2016.09.30 前面已经判断过destinationBucket为空的时候退出，这里不需要再做destinationBucket是否为NULL的判断
          destinationBucket,                          // destinationBucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,			  // secretAccessKey
		  bucketContext->certificateInfo },           // certificateInfo           
        //destinationKey ? destinationKey : key,        // key
		destinationKey,                               // zwx367245 2016.09.30 前面已经判断过destinationKey为空的时候退出，这里不需要再做destinationKey是否为NULL的判断
        0,       								      // queryParams
        0,                                            // subResource
        bucketContext->bucketName,                    // copySourceBucketName
        versionkey[0] ? versionkey : key,             // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
        0,											  // corsConf
        putProperties,                                // putProperties
		0,                                            // ServerSideEncryptionParams
        &copyObjectPropertiesCallback,                // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &copyObjectDataCallback,                      // fromS3Callback
        &copyObjectCompleteCallback,                  // completeCallback
        data,                                 		  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };
    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_copy_object successfully!");
}

void CopyObject(const S3BucketContext *bucketContext, const char *key,
                    const char *destinationBucket, const char *destinationKey,
                    const char *versionId, unsigned int nIsCopy, S3PutProperties *putProperties,
                    int64_t *lastModifiedReturn, int eTagReturnSize,
                    char *eTagReturn, S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter CopyObject successfully!");

	//Modify pointer to local outside scope by jwx329074 2016.11.18
	S3PutProperties *tmpPutPro = (S3PutProperties *)malloc(sizeof(S3PutProperties));
	if (!tmpPutPro)
	{
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc CopyObject failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    

		return;
	}

	memset_s(tmpPutPro, sizeof(S3PutProperties), 0, sizeof(S3PutProperties));
	if (NULL == putProperties)
	{
		if (0 == nIsCopy)
		{   
			//S3PutProperties tmpPutPro;
			//memset_s(&tmpPutPro, sizeof(S3PutProperties), 0, sizeof(S3PutProperties));
			tmpPutPro->metaDataCount = -1;
			tmpPutPro->expires = -1;
			putProperties = tmpPutPro;
		}
	}
	else
	{
		if (0 < nIsCopy)
		{
			putProperties->metaDataCount = 0;
		}
		else
		{
			if (0 == putProperties->metaDataCount)
			{
				putProperties->metaDataCount = -1;
			}
		}
	}
	
	
	S3_copy_object(bucketContext,key,destinationBucket,destinationKey,versionId,putProperties,
	lastModifiedReturn,eTagReturnSize,eTagReturn,requestContext,handler,callbackData);//lint !e119
	
	free(tmpPutPro);
	tmpPutPro = NULL;

	COMMLOG(OBS_LOGINFO, "Leave CopyObject successfully!");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
}


// copy object with server side encryption ---------------------------------------------------------------
void S3_copy_object_with_serverSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *destinationBucket, const char *destinationKey,
	const char *versionId,const S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams,
	int64_t *lastModifiedReturn, int eTagReturnSize,
	char *eTagReturn, S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_copy_object_with_serverSideEncryption successfully !");	
	CopyObjectData *data = 
		(CopyObjectData *) malloc(sizeof(CopyObjectData));
	if (!data) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc CopyObjectData failed !");	
		return;
	}
	memset_s(data, sizeof(CopyObjectData), 0, sizeof(CopyObjectData));

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		free(data);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		data = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(eTagReturnSize < 0 || NULL == destinationBucket || NULL == destinationKey){
		COMMLOG(OBS_LOGERROR, "eTagReturnSize < 0 or destinationBucket or destinationKey is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		free(data);    //zwx367245 2016.09.30 某些参数不正确的时候不能直接退出，要先释放内存再return
		data = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

	simplexml_initialize(&(data->simpleXml), &copyObjectXmlCallback, data);//lint !e119

	data->responsePropertiesCallback = handler->propertiesCallback;
	data->responseCompleteCallback = handler->completeCallback;
	data->callbackData = callbackData;
	data->lastModifiedReturn = lastModifiedReturn;
	data->eTagReturnSize = eTagReturnSize;
	data->eTagReturn = eTagReturn;
	if (data->eTagReturnSize && data->eTagReturn) {
		data->eTagReturn[0] = 0;
	}
	data->eTagReturnLen = 0;
	string_buffer_initialize(data->lastModified);

	char versionkey[1024] = {0};
	if(versionId)
	{
		snprintf_s(versionkey,sizeof(versionkey), _TRUNCATE, 
			"%s?versionId=%s",key,versionId);
	}

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeCOPY,                          // httpRequestType
		{ bucketContext->hostName,                    // hostName
		//destinationBucket ? destinationBucket :     // zwx367245 2016.09.30 前面已经判断过destinationBucket为空的时候退出，这里不需要再做destinationBucket是否为NULL的判断
		destinationBucket,                            // destinationBucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,			      // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo           
		//destinationKey ? destinationKey : key,      // key
		destinationKey,                               // zwx367245 2016.09.30 前面已经判断过destinationKey为空的时候退出，这里不需要再做destinationKey是否为NULL的判断
		0,       								      // queryParams
		0,                                            // subResource
		bucketContext->bucketName,                    // copySourceBucketName
		versionkey[0] ? versionkey : key,             // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  // corsConf
		putProperties,                                // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		&copyObjectPropertiesCallback,                // propertiesCallback
		0,                                            // toS3Callback
		0,                                            // toS3CallbackTotalSize
		&copyObjectDataCallback,                      // fromS3Callback
		&copyObjectCompleteCallback,                  // completeCallback
		data,                                 		  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};
	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_copy_object_with_serverSideEncryption successfully!");
}

void CopyObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *destinationBucket, const char *destinationKey,
	const char *versionId, unsigned int nIsCopy, S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams,
	int64_t *lastModifiedReturn, int eTagReturnSize,
	char *eTagReturn, S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter CopyObjectWithServerSideEncryption successfully!");

	//Modify pointer to local outside scope by jwx329074 2016.11.18
	S3PutProperties *tmpPutPro = (S3PutProperties *)malloc(sizeof(S3PutProperties));
	if (!tmpPutPro)
	{
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc CopyObjectWithServerSideEncryption failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    

		return;
	}
	memset_s(tmpPutPro, sizeof(S3PutProperties), 0, sizeof(S3PutProperties));
	if (NULL == putProperties)
	{
		if (0 == nIsCopy)
		{
			//S3PutProperties tmpPutPro;
			//memset_s(&tmpPutPro, sizeof(S3PutProperties), 0, sizeof(S3PutProperties));
			tmpPutPro->metaDataCount = -1;
			tmpPutPro->expires = -1;
			putProperties = tmpPutPro;
		}
	}
	else
	{
		if (0 < nIsCopy)
		{
			putProperties->metaDataCount = 0;
		}
		else
		{
			if (0 == putProperties->metaDataCount)
			{
				putProperties->metaDataCount = -1;
			}
		}
	}


	S3_copy_object_with_serverSideEncryption(bucketContext,key,destinationBucket,destinationKey,versionId,putProperties, serverSideEncryptionParams,
		lastModifiedReturn,eTagReturnSize,eTagReturn,requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave CopyObjectWithServerSideEncryption successfully!");

	free(tmpPutPro);
	tmpPutPro = NULL;

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
}


// get object without server side encryption----------------------------------------------------------------
void S3_get_object(const S3BucketContext *bucketContext, const char *key,const char* versionId,
                   const S3GetConditions *getConditions,
                   uint64_t startByte, uint64_t byteCount,
                   S3RequestContext *requestContext,
                   const S3GetObjectHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_get_object successfully!");
	
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}
	// Compose the query params
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);
	
	//增加urlEncode()函数的返回值检查 by jwx329074 2016.10.11
#define version_append(name, value)                                     \
	do {																\
		int fit;														\
		if (amp) {														\
			string_buffer_append(queryParams, "&", 1, fit); 			\
			if (!fit) { 												\
				(void)(*(handler->responseHandler.completeCallback))	\
					(S3StatusQueryParamsTooLong, 0, callbackData);		\
				return; 												\
			}															\
		}																\
		string_buffer_append(queryParams, name "=", 					\
							 sizeof(name "=") - 1, fit);				\
		if (!fit) { 													\
			(void)(*(handler->responseHandler.completeCallback))		\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
		amp = 1;														\
		char encoded[3 * 1024]; 										\
		int isFlag = 0;												    \
		if (isFlag == urlEncode(encoded, value, 1024)) { 				\
			(void)(*(handler->responseHandler.completeCallback))		\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
		string_buffer_append(queryParams, encoded, strlen(encoded), 	\
							 fit);										\
		if (!fit) { 													\
			(void)(*(handler->responseHandler.completeCallback))		\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
	} while (0)


	int amp = 0;
	if (versionId) {
		version_append("versionId", versionId);
	}
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        getConditions,                                // getConditions
        startByte,                                    // startByte
        byteCount,                                    // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        handler->responseHandler.propertiesCallback,  // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        handler->getObjectDataCallback,               // fromS3Callback
        handler->responseHandler.completeCallback,    // completeCallback
        callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_get_object successfully!");
}
#if defined __GNUC__ || defined LINUX
void GetObject(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData)
#else
void getObject(const S3BucketContext *bucketContext, const char *key,const char* versionId,
                   const S3GetConditions *getConditions,
                   uint64_t startByte, uint64_t byteCount,
                   S3RequestContext *requestContext,
                   const S3GetObjectHandler *handler, void *callbackData)
#endif
{
    SYSTEMTIME reqTime; 
    GetLocalTime(&reqTime);

#if defined __GNUC__ || defined LINUX
	COMMLOG(OBS_LOGINFO, "Enter GetObject successfully!");
#else
	COMMLOG(OBS_LOGINFO, "Enter getObject successfully!");
#endif
	S3_get_object(bucketContext,key,versionId,getConditions,startByte,byteCount,requestContext,handler,callbackData);//lint !e119
#if defined __GNUC__ || defined LINUX
	COMMLOG(OBS_LOGINFO, "Leave GetObject successfully!");
#else
	COMMLOG(OBS_LOGINFO, "Leave getObject successfully!");
#endif

    SYSTEMTIME rspTime; 
    GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");        
}

// get object with server side encryption----------------------------------------------------------------
void S3_get_object_with_serverSideEncryption(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_get_object_with_serverSideEncryption successfully!");

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}
	// Compose the query params
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);

	//增加urlEncode()函数的返回值检查 by jwx329074 2016.10.11
#define version_append(name, value)                                     \
	do {																\
		int fit;														\
		if (amp) {														\
			string_buffer_append(queryParams, "&", 1, fit); 			\
			if (!fit) { 												\
				(void)(*(handler->responseHandler.completeCallback))	\
					(S3StatusQueryParamsTooLong, 0, callbackData);		\
				return; 												\
			}															\
		}																\
		string_buffer_append(queryParams, name "=", 					\
							 sizeof(name "=") - 1, fit);				\
		if (!fit) { 													\
			(void)(*(handler->responseHandler.completeCallback))		\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
		amp = 1;														\
		char encoded[3 * 1024]; 										\
		int isFlag = 0;												    \
		if (isFlag == urlEncode(encoded, value, 1024)) { 				\
			(void)(*(handler->responseHandler.completeCallback))		\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
		string_buffer_append(queryParams, encoded, strlen(encoded), 	\
							 fit);										\
		if (!fit) { 													\
			(void)(*(handler->responseHandler.completeCallback))		\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
	} while (0)


	int amp = 0;
	if (versionId) {
		version_append("versionId", versionId);
	}
	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeGET,                           // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,                                          // key
		queryParams[0] ? queryParams : 0,             // queryParams
		0,                                            // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		getConditions,                                // getConditions
		startByte,                                    // startByte
		byteCount,                                    // byteCount
		0,											  // corsConf
		0,                                            // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		handler->responseHandler.propertiesCallback,  // propertiesCallback
		0,                                            // toS3Callback
		0,                                            // toS3CallbackTotalSize
		handler->getObjectDataCallback,               // fromS3Callback
		handler->responseHandler.completeCallback,    // completeCallback
		callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_get_object_with_serverSideEncryption successfully!");
}

#if defined __GNUC__ || defined LINUX
void GetObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData)
#else
void getObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData)
#endif
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

#if defined __GNUC__ || defined LINUX
	COMMLOG(OBS_LOGINFO, "Enter GetObjectWithServerSideEncryption successfully!");
#else
	COMMLOG(OBS_LOGINFO, "Enter getObjectWithServerSideEncryption successfully!");
#endif
	S3_get_object_with_serverSideEncryption(bucketContext,key,versionId,getConditions,startByte,byteCount, serverSideEncryptionParams, requestContext,handler,callbackData);//lint !e119
#if defined __GNUC__ || defined LINUX
	COMMLOG(OBS_LOGINFO, "Leave GetObjectWithServerSideEncryption successfully!");
#else
	COMMLOG(OBS_LOGINFO, "Leave getObjectWithServerSideEncryption successfully!");
#endif

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");        
}

// head object ---------------------------------------------------------------

void S3_head_object(const S3BucketContext *bucketContext, const char *key,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_head_object Successfully!");
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
         (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeHEAD,                          // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        0,                                            // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        handler->propertiesCallback,                  // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        handler->completeCallback,                    // completeCallback
        callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_head_object Successfully!");
}

void HeadBucket(const S3BucketContext *bucketContext,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter HeadBucket Successfully!");
	S3_head_object(bucketContext,0,requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave HeadBucket Successfully!");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");        
}

// delete object --------------------------------------------------------------

void S3_delete_object(const S3BucketContext *bucketContext, const char *key,
                      const char* versionId,S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_delete_object successfully !");
		string_buffer(queryParams, 4096);
		string_buffer_initialize(queryParams);
	//jwx329074 2016.10.10 修改urlEncode()函数	
#define safe_append(name, value)                                            \
		do {																\
			int fit;														\
			if (amp) {														\
				string_buffer_append(queryParams, "&", 1, fit); 			\
				if (!fit) { 												\
					 (void)(*(handler->completeCallback))			        \
						(S3StatusQueryParamsTooLong, 0, callbackData);		\
					return; 												\
				}															\
			}																\
			string_buffer_append(queryParams, name "=", 					\
								 sizeof(name "=") - 1, fit);				\
			if (!fit) { 													\
				 (void)(*(handler->completeCallback))				        \
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
				return; 													\
			}																\
			amp = 1;														\
			char encoded[3 * 1024]; 										\
			int isFlag = 0;												    \
			if (isFlag == urlEncode(encoded, value, 1024)) { 				\
				 (void)(*(handler->completeCallback))				        \
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
				return; 													\
			}																\
			string_buffer_append(queryParams, encoded, strlen(encoded), 	\
								 fit);										\
			if (!fit) { 													\
				 (void)(*(handler->completeCallback))				        \
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
				return; 													\
			}																\
		} while (0)
	
		int amp = 0;
		if (versionId) {
			safe_append("versionId", versionId);
		}

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,                        // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        handler->propertiesCallback,                  // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        handler->completeCallback,                    // completeCallback
        callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_delete_object successfully !");
}

#if defined __GNUC__ || defined LINUX
void DeleteObject(const S3BucketContext *bucketContext, const char *key,
                      const char* versionId,S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
#else
void deleteObject(const S3BucketContext *bucketContext, const char *key,
	const char* versionId,S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
#endif
{
    SYSTEMTIME reqTime; 
    GetLocalTime(&reqTime);

#if defined __GNUC__ || defined LINUX    
	COMMLOG(OBS_LOGINFO, "Enter DeleteObject successfully !");
#else
	COMMLOG(OBS_LOGINFO, "Enter deleteObject successfully !");
#endif
	S3_delete_object(bucketContext,key,versionId,requestContext,handler,callbackData);//lint !e119
#if defined __GNUC__ || defined LINUX    
	COMMLOG(OBS_LOGINFO, "Leave DeleteObject successfully !");
#else
	COMMLOG(OBS_LOGINFO, "Leave deleteObject successfully !");
#endif

    SYSTEMTIME rspTime; 
    GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");        
}

// UploadPart without server side encryption-------------------------------------------------------------
void UploadPart(const S3BucketContext *bucketContext, const char *key,
                      const char *partNumber,const char *uploadId,uint64_t contentLength,const S3PutProperties *putProperties,
                      S3RequestContext *requestContext,
                      const S3UploadHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
      GetLocalTime(&reqTime);
      
	COMMLOG(OBS_LOGINFO, "Enter UploadPart successfully !");
    string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);
    
#define safe_appendh(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                 (void)(*(handler->responseHandler.completeCallback))   \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
                INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
             (void)(*(handler->responseHandler.completeCallback))       \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
             (void)(*(handler->responseHandler.completeCallback))       \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
             (void)(*(handler->responseHandler.completeCallback))       \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
    } while (0)


    int amp = 0;
		if (partNumber) {
			safe_appendh("partNumber", partNumber);
		}
		if (uploadId) {
			safe_appendh("uploadId", uploadId);
		}

    
	if(NULL == partNumber || NULL == uploadId){
		COMMLOG(OBS_LOGERROR, "partNumber or uploadId  is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
	}
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");

		return;
	}
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        putProperties,                                // putProperties
		0,                                            // ServerSideEncryptionParams
        handler->responseHandler.propertiesCallback,  // propertiesCallback
        handler->uploadDataCallback,                  // toS3Callback
        contentLength,                             	  // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        handler->responseHandler.completeCallback,    // completeCallback
        callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave UploadPart successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// UploadPart with server side encryption-------------------------------------------------------------
void UploadPartWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *partNumber,const char *uploadId,uint64_t contentLength,const S3PutProperties *putProperties,
	ServerSideEncryptionParams *serverSideEncryptionParams, S3RequestContext *requestContext,
	const S3UploadHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter UploadPartWithServerSideEncryption successfully !");
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);

#define safe_appendh(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                 (void)(*(handler->responseHandler.completeCallback))   \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
                INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
             (void)(*(handler->responseHandler.completeCallback))       \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
             (void)(*(handler->responseHandler.completeCallback))       \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
             (void)(*(handler->responseHandler.completeCallback))       \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
    } while (0)


	int amp = 0;
	if (partNumber) {
		safe_appendh("partNumber", partNumber);
	}
	if (uploadId) {
		safe_appendh("uploadId", uploadId);
	}


	if(NULL == partNumber || NULL == uploadId){
		COMMLOG(OBS_LOGERROR, "partNumber or uploadId  is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
	}
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");

		return;
	}
	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypePUT,                           // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,                                          // key
		queryParams[0] ? queryParams : 0,             // queryParams
		0,                                            // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  // corsConf
		putProperties,                                // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		handler->responseHandler.propertiesCallback,  // propertiesCallback
		handler->uploadDataCallback,                  // toS3Callback
		contentLength,                             	  // toS3CallbackTotalSize
		0,                                            // fromS3Callback
		handler->responseHandler.completeCallback,    // completeCallback
		callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave UploadPartWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// Copy Partwithout server side encryption ---------------------------------------------------------------
typedef struct CopyPartData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int64_t *lastModifiedReturn;
    int eTagReturnSize;
    char *eTagReturn;
    int eTagReturnLen;
    
    string_buffer(lastModified, 256);
} CopyPartData;


static S3Status CopyPartXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    CopyPartData *cpData = (CopyPartData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "CopyPartResult/LastModified")) {
            string_buffer_append(cpData->lastModified, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "CopyPartResult/ETag")) {
            if (cpData->eTagReturnSize && cpData->eTagReturn) {
                cpData->eTagReturnLen +=
                    snprintf_s(&(cpData->eTagReturn[cpData->eTagReturnLen]), sizeof(cpData->eTagReturn[cpData->eTagReturnLen]), 
                             cpData->eTagReturnSize - 
                             cpData->eTagReturnLen - 1,
                             "%.*s", dataLen, data);
                if (cpData->eTagReturnLen >= cpData->eTagReturnSize) {
                    return S3StatusXmlParseFailure;
                }
            }
        }
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status CopyPartPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    CopyPartData *cpData = (CopyPartData *) callbackData;
    
    return (*(cpData->responsePropertiesCallback))
        (responseProperties, cpData->callbackData);
}


static S3Status CopyPartDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    CopyPartData *cpData = (CopyPartData *) callbackData;

    return simplexml_add(&(cpData->simpleXml), buffer, bufferSize);
}


static void CopyPartCompleteCallback(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails, void *callbackData)//lint !e101
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    CopyPartData *cpData = (CopyPartData *) callbackData;

    if (cpData->lastModifiedReturn) {
        time_t lastModified = -1;
        if (cpData->lastModifiedLen) {
            lastModified = parseIso8601Time(cpData->lastModified);
		int nTimeZone = getTimeZone();
		lastModified += nTimeZone * SECONDS_TO_AN_HOUR;	
        }

        *(cpData->lastModifiedReturn) = lastModified;
    }

    (void)(*(cpData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, cpData->callbackData);

    simplexml_deinitialize(&(cpData->simpleXml));

    free(cpData);
	cpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void CopyPart(const S3BucketContext *bucketContext, const char *key,
                    const char *destinationBucket, const char *destinationKey,
                    uint64_t startByte,uint64_t byteCount,
                    const char *partNumber,const char *uploadId,int64_t *lastModifiedReturn, int eTagReturnSize,
                    char *eTagReturn, S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
    //
	COMMLOG(OBS_LOGINFO, "Enter CopyPart successfully !");
	string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);

#define safe_appendm(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->completeCallback))                    \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
	         INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");  \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");      \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");      \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");      \
            return;                                                     \
        }                                                               \
    } while (0)


    int amp = 0;
		if (partNumber) {
			safe_appendm("partNumber", partNumber);
		}
		if (uploadId) {
			safe_appendm("uploadId", uploadId);
		}


	
    CopyPartData *data = 
        (CopyPartData *) malloc(sizeof(CopyPartData));
    if (!data) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc CopyPartData failed!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

        return;
    }
	memset_s(data,sizeof(CopyPartData), 0, sizeof(CopyPartData));//add sizeof by jwx329074

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(data);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		data=NULL;
		return;
	}
	if(eTagReturnSize < 0 || NULL == partNumber || NULL == uploadId){
		COMMLOG(OBS_LOGERROR, "eTagReturnSize is invalid!  partNumber or uploadId is NULL");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(data);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		data=NULL;
		return;
	}

    simplexml_initialize(&(data->simpleXml), &CopyPartXmlCallback, data);//lint !e119

    data->responsePropertiesCallback = handler->propertiesCallback;
    data->responseCompleteCallback = handler->completeCallback;
    data->callbackData = callbackData;

    data->lastModifiedReturn = lastModifiedReturn;
    data->eTagReturnSize = eTagReturnSize;
    data->eTagReturn = eTagReturn;
    if (data->eTagReturnSize && data->eTagReturn) {
        data->eTagReturn[0] = 0;
    }
    data->eTagReturnLen = 0;
    string_buffer_initialize(data->lastModified);

    // Set up S3PutProperties
    S3PutProperties properties =
    {
        0,                                       // contentType
        0,                                       // md5
        0,                                       // cacheControl
        0,                                       // contentDispositionFilename
        0,                                       // contentEncoding
        0,										 // storagepolicy
        0,										 // websiteredirectlocation
        0,										 // getConditions
        startByte,								 // startByte
        byteCount,								 // byteCount
        0,                                       // expires
        S3CannedAclPrivate,                  	 // cannedAcl
        0,                                       // metaDataCount
        0,                                       // metaData
        0                                        // useServerSideEncryption
    };

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeCOPY,                          // httpRequestType
        { bucketContext->hostName,                    // hostName
          destinationBucket ? destinationBucket : 
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        destinationKey ? destinationKey : key,        // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                            // subResource
        bucketContext->bucketName,                    // copySourceBucketName
        key,                                          // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
        0,											  // corsConf
        &properties,                               	  // putProperties
		0,                                            // ServerSideEncryptionParams
        &CopyPartPropertiesCallback,                  // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &CopyPartDataCallback,                        // fromS3Callback
        &CopyPartCompleteCallback,                    // completeCallback
        data ,                                 		  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave CopyPart successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// Copy Part with server side encryption---------------------------------------------------------------
void CopyPartWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *destinationBucket, const char *destinationKey,
	uint64_t startByte,uint64_t byteCount,
	const char *partNumber,const char *uploadId,int64_t *lastModifiedReturn, int eTagReturnSize,
	char *eTagReturn, ServerSideEncryptionParams *serverSideEncryptionParams, S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	//
	COMMLOG(OBS_LOGINFO, "Enter CopyPartWithServerSideEncryption successfully !");
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);

#define safe_appendm(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->completeCallback))                    \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
	         INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");  \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");      \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");      \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");      \
            return;                                                     \
        }                                                               \
    } while (0)


	int amp = 0;
	if (partNumber) {
		safe_appendm("partNumber", partNumber);
	}
	if (uploadId) {
		safe_appendm("uploadId", uploadId);
	}



	CopyPartData *data = 
		(CopyPartData *) malloc(sizeof(CopyPartData));
	if (!data) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc CopyPartData failed!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
	}
	memset_s(data,sizeof(CopyPartData) + 1, 0, sizeof(CopyPartData));//add sizeof by jwx329074

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(data);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		data=NULL;
		return;
	}
	if(eTagReturnSize < 0 || NULL == partNumber || NULL == uploadId){
		COMMLOG(OBS_LOGERROR, "eTagReturnSize is invalid!  partNumber or uploadId is NULL");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(data);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		data=NULL;
		return;
	}

	simplexml_initialize(&(data->simpleXml), &CopyPartXmlCallback, data);//lint !e119

	data->responsePropertiesCallback = handler->propertiesCallback;
	data->responseCompleteCallback = handler->completeCallback;
	data->callbackData = callbackData;

	data->lastModifiedReturn = lastModifiedReturn;
	data->eTagReturnSize = eTagReturnSize;
	data->eTagReturn = eTagReturn;
	if (data->eTagReturnSize && data->eTagReturn) {
		data->eTagReturn[0] = 0;
	}
	data->eTagReturnLen = 0;
	string_buffer_initialize(data->lastModified);

	// Set up S3PutProperties
	S3PutProperties properties =
	{
		0,                                       // contentType
		0,                                       // md5
		0,                                       // cacheControl
		0,                                       // contentDispositionFilename
		0,                                       // contentEncoding
		0,										 // storagepolicy
		0,										 // websiteredirectlocation
		0,										 // getConditions
		startByte,								 // startByte
		byteCount,								 // byteCount
		0,                                       // expires
		S3CannedAclPrivate,                  	 // cannedAcl
		0,                                       // metaDataCount
		0,                                       // metaData
		0                                        // useServerSideEncryption
	};

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeCOPY,                          // httpRequestType
		{ bucketContext->hostName,                    // hostName
		destinationBucket ? destinationBucket : 
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		destinationKey ? destinationKey : key,        // key
		queryParams[0] ? queryParams : 0,             // queryParams
		0,                                            // subResource
		bucketContext->bucketName,                    // copySourceBucketName
		key,                                          // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  // corsConf
		&properties,                               	  // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		&CopyPartPropertiesCallback,                  // propertiesCallback
		0,                                            // toS3Callback
		0,                                            // toS3CallbackTotalSize
		&CopyPartDataCallback,                        // fromS3Callback
		&CopyPartCompleteCallback,                    // completeCallback
		data ,                                 		  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave CopyPartWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}
// AbortMultipartUpload without server side encryption-------------------------------------------------------------

typedef struct AbortMultipartUploadData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
} AbortMultipartUploadData;


static S3Status AbortMultipartUploadPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    AbortMultipartUploadData *amuData = (AbortMultipartUploadData *) callbackData;
    
    return (*(amuData->responsePropertiesCallback))
        (responseProperties, amuData->callbackData);
}


static void AbortMultipartUploadCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    AbortMultipartUploadData *amuData = (AbortMultipartUploadData *) callbackData;

    (*(amuData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, amuData->callbackData);

    free(amuData);
	amuData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

// AbortMultipartUpload without server side encryption-------------------------------------------------------------
void AbortMultipartUpload(const S3BucketContext *bucketContext,const char *key,const char *uploadId,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter AbortMultipartUpload successfully !");
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);
    
#define safe_appendm(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->completeCallback))                    \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
	         INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");  \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
    } while (0)


    int amp = 0;
	if (uploadId) {
		safe_appendm("uploadId", uploadId);
	}
	else
	{
		COMMLOG(OBS_LOGERROR, "uploadId is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
		
	}

    AbortMultipartUploadData *amuData = 
        (AbortMultipartUploadData *) malloc(sizeof(AbortMultipartUploadData));
    if (!amuData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGINFO, "Malloc AbortMultipartUploadData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(amuData,sizeof(AbortMultipartUploadData), 0, sizeof(AbortMultipartUploadData));

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(amuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		amuData=NULL;
		return;
	}

    amuData->responsePropertiesCallback = handler->propertiesCallback;
    amuData->responseCompleteCallback = handler->completeCallback;
    amuData->callbackData = callbackData;

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,                        // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &AbortMultipartUploadPropertiesCallback,      // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &AbortMultipartUploadCompleteCallback,        // completeCallback
        amuData,                                 	  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave AbortMultipartUpload successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// AbortMultipartUpload with server side encryption-------------------------------------------------------------
void AbortMultipartUploadWithServerSideEncryption(const S3BucketContext *bucketContext,const char *key,const char *uploadId,
	ServerSideEncryptionParams *serverSideEncryptionParams, S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter AbortMultipartUploadWithServerSideEncryption successfully !");
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);

#define safe_appendm(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->completeCallback))                    \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
	         INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");  \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))                        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
    } while (0)


	int amp = 0;
	if (uploadId) {
		safe_appendm("uploadId", uploadId);
	}
	else
	{
		COMMLOG(OBS_LOGERROR, "uploadId is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;

	}

	AbortMultipartUploadData *amuData = 
		(AbortMultipartUploadData *) malloc(sizeof(AbortMultipartUploadData));
	if (!amuData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGINFO, "Malloc AbortMultipartUploadData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
	}
	memset_s(amuData,sizeof(AbortMultipartUploadData), 0, sizeof(AbortMultipartUploadData));

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(amuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		amuData=NULL;
		return;
	}

	amuData->responsePropertiesCallback = handler->propertiesCallback;
	amuData->responseCompleteCallback = handler->completeCallback;
	amuData->callbackData = callbackData;

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeDELETE,                        // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,                                          // key
		queryParams[0] ? queryParams : 0,             // queryParams
		0,                                            // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  // corsConf
		0,                                            // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		&AbortMultipartUploadPropertiesCallback,      // propertiesCallback
		0,                                            // toS3Callback
		0,                                            // toS3CallbackTotalSize
		0,                                            // fromS3Callback
		&AbortMultipartUploadCompleteCallback,        // completeCallback
		amuData,                                 	  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave AbortMultipartUploadWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// delete objects -------------------------------------------------------------
typedef struct  DeleteObjectContents
{
    string_buffer(key, 1024);
    string_buffer(code, 256);
    string_buffer(message, 256);
    string_buffer(deleteMarker, 24);
    string_buffer(deleteMarkerVersionId, 256);
} DeleteObjectContents;


static void initialize_del_Object_contents(DeleteObjectContents *contents)
{
    string_buffer_initialize(contents->key);
    string_buffer_initialize(contents->code);
    string_buffer_initialize(contents->message);
    string_buffer_initialize(contents->deleteMarker);
    string_buffer_initialize(contents->deleteMarkerVersionId);
}

typedef struct DeleteObjectData
{
    SimpleXml simpleXml;
    
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    S3DeleteObjectDataCallback *deleteObjectDataCallback;
    void *callbackData;

    char doc[1024*10];
    int docLen, docBytesWritten;
	
	int contentsCount;
	DeleteObjectContents contents[S3_MAX_DELETE_OBJECT_NUMBER];
    
} DeleteObjectData; 

static void initialize_del_Object_data(DeleteObjectData *doData)//lint !e528
{
    doData->contentsCount = 0;
    initialize_del_Object_contents(doData->contents);
}

static S3Status make_del_Object_callback(DeleteObjectData *doData)
{
    int i;
	S3Status iRet = S3StatusOK;

    // Convert the contents
    //S3DeleteObjects contents[doData->contentsCount];
	if(doData->contentsCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusInternalError;
	}
	S3DeleteObjects *contents = (S3DeleteObjects*)malloc(sizeof(S3DeleteObjects) * doData->contentsCount);
	if (NULL == contents) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3DeleteObjects failed!");
		return S3StatusInternalError;
	}
	memset_s(contents,sizeof(S3DeleteObjects) * doData->contentsCount, 0, sizeof(S3DeleteObjects) * doData->contentsCount);

    int contentsCount = doData->contentsCount;
    for (i = 0; i < contentsCount; i++) {
        S3DeleteObjects *contentDest = &(contents[i]);
        DeleteObjectContents *contentSrc = &(doData->contents[i]);
        contentDest->key = contentSrc->key;
        contentDest->code =contentSrc->code;
        contentDest->message = contentSrc->message;
        contentDest->deleteMarker = contentSrc->deleteMarker;
        contentDest->deleteMarkerVersionId =contentSrc->deleteMarkerVersionId;
    }

	iRet = (*(doData->deleteObjectDataCallback))
		(contentsCount, contents, doData->callbackData);
	
	CHECK_NULL_FREE(contents);

	return iRet;
}


static S3Status deleteObjectXmlCallback(const char *elementPath, const char *data,
                            int dataLen, void *callbackData)
{
    DeleteObjectData *doData = (DeleteObjectData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "DeleteResult/Deleted/Key")) {
            DeleteObjectContents *contents = 
                &(doData->contents[doData->contentsCount]);
            string_buffer_append(contents->key, data, dataLen, fit);
            string_buffer_append(contents->code, "0", 1, fit);
        }
        else if (!strcmp(elementPath, "DeleteResult/Deleted/DeleteMarker")) {
            DeleteObjectContents *contents = 
                &(doData->contents[doData->contentsCount]);
            string_buffer_append(contents->deleteMarker, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "DeleteResult/Deleted/DeleteMarkerVersionId")) {
            DeleteObjectContents *contents = 
                &(doData->contents[doData->contentsCount]);
            string_buffer_append(contents->deleteMarkerVersionId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "DeleteResult/Error/Key")) {
            DeleteObjectContents *contents = 
                &(doData->contents[doData->contentsCount]);
            string_buffer_append(contents->key, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "DeleteResult/Error/Code")) {
            DeleteObjectContents *contents = 
                &(doData->contents[doData->contentsCount]);
            string_buffer_append(contents->code, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "DeleteResult/Error/Message")) {
            DeleteObjectContents *contents = 
                &(doData->contents[doData->contentsCount]);
            string_buffer_append(contents->message, data, dataLen, fit);
        }
    }    
    else {
        if (!strcmp(elementPath, "DeleteResult/Deleted") || !strcmp(elementPath, "DeleteResult/Error")) {
 
           doData->contentsCount++;
            if (doData->contentsCount == S3_MAX_DELETE_OBJECT_NUMBER) {
                // Make the callback
                S3Status status = make_del_Object_callback(doData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_del_Object_data(doData);
            }
            else {
                // Initialize the next one
                initialize_del_Object_contents
                    (&(doData->contents[doData->contentsCount]));
            }
        }
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}

static S3Status deleteObjectPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    DeleteObjectData *doData = (DeleteObjectData *) callbackData;
    
    return (*(doData->responsePropertiesCallback))
        (responseProperties, doData->callbackData);
}

static int deleteObjectDataToS3Callback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    DeleteObjectData *doData = (DeleteObjectData *) callbackData;

    if (!doData->docLen) {
        return 0;
    }

    int remaining = (doData->docLen - doData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize,  &(doData->doc[doData->docBytesWritten]), toCopy);

    doData->docBytesWritten += toCopy;

    return toCopy;
}

static S3Status deleteObjectDataFromS3Callback(int bufferSize, const char *buffer,
                             void *callbackData)
{
    DeleteObjectData *doData = (DeleteObjectData *) callbackData;

    return simplexml_add(&(doData->simpleXml), buffer, bufferSize);
}

static void deleteObjectCompleteCallback(S3Status requestStatus,
                             const S3ErrorDetails *s3ErrorDetails,
                             void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteObjectData *doData = (DeleteObjectData *) callbackData;
	
    if (doData->contentsCount) {
        make_del_Object_callback(doData);
    }
	
    (*(doData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, doData->callbackData);

    simplexml_deinitialize(&(doData->simpleXml));

    free(doData);
	doData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}



void DeleteObjects(const S3BucketContext *bucketContext, const S3DelBucketInfo *delBucketinfo,
                      const unsigned int keysNumber, int quiet, 
                      const S3PutProperties *putProperties,                      
                      S3RequestContext *requestContext,
                      const S3DeleteObjectHandler *handler, void *callbackData)
{
      SYSTEMTIME reqTime; 
      GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter DeleteObjects successfully !");
    if(keysNumber > S3_MAX_DELETE_OBJECT_NUMBER || NULL == delBucketinfo)
    {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Input param keysNumber is greater than S3_MAX_DELETE_OBJECT_NUMBER  or delBucketinfo is NULL!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
    }
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");

		return;
	}
    
    // delete the callback data
    DeleteObjectData* doData = 
        (DeleteObjectData *) malloc(sizeof(DeleteObjectData));
    if (NULL == doData) {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteObjectData failed!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(doData,sizeof(DeleteObjectData), 0, sizeof(DeleteObjectData));
    
    simplexml_initialize(&(doData->simpleXml), &deleteObjectXmlCallback, doData);//lint !e119

    doData->responsePropertiesCallback = handler->responseHandler.propertiesCallback;
    doData->responseCompleteCallback = handler->responseHandler.completeCallback;
    doData->deleteObjectDataCallback = handler->deleteObjectDataCallback;
    doData->callbackData = callbackData;

    doData->docLen = 0;
    doData->docBytesWritten = 0;

    doData->docLen += snprintf_s(doData->doc, sizeof(doData->doc), _TRUNCATE, 
                     "<Delete>"); //lint !e515
	if(quiet)
    {   
		//cheack array index by jwx329074 2016.11.17
		if (doData->docLen < 0)
		{
			COMMLOG(OBS_LOGERROR, "snprintf_s error!");
			free(doData);
			doData = NULL;
			return;
		}
     
        doData->docLen +=
            snprintf_s(doData->doc + doData->docLen, sizeof(doData->doc) - doData->docLen, _TRUNCATE,
                     "<Quiet>%s</Quiet>", "true");        
    }

    unsigned int uiLen = strlen(doData->doc);
    unsigned int uiIdx = 0;
	int mark = 0;
    for(; uiIdx < keysNumber; uiIdx++)//lint !e574
    {
        if(NULL != delBucketinfo[uiIdx].key)//lint !e409
        {
        	char*pkey = 0;
        	mark = pcre_replace(delBucketinfo[uiIdx].key,&pkey);//lint !e409
            doData->docLen += snprintf_s(doData->doc + uiLen, sizeof(doData->doc) - uiLen, _TRUNCATE,
                     "<Object><Key>%s</Key>", mark ? pkey : delBucketinfo[uiIdx].key);//lint !e409
 
            uiLen = strlen(doData->doc);
			if(mark)
			{
				free(pkey);
				pkey = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
        }
		if(NULL != delBucketinfo[uiIdx].versionId)//lint !e409
		{
 	      	char*pversionId = 0;
        	mark = pcre_replace(delBucketinfo[uiIdx].versionId,&pversionId);//lint !e409
 			doData->docLen += snprintf_s(doData->doc + uiLen, sizeof(doData->doc) - uiLen, _TRUNCATE,
					 "<VersionId>%s</VersionId></Object>", mark ? pversionId : delBucketinfo[uiIdx].versionId);//lint !e409
            uiLen = strlen(doData->doc);
			if(mark)
			{
				free(pversionId);
				pversionId = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		else
		{
			doData->docLen += snprintf_s(doData->doc + uiLen, sizeof(doData->doc) - uiLen, _TRUNCATE,
					 "</Object>");
            uiLen = strlen(doData->doc);		
		}
		if((doData->docLen >= 1024*10) && (uiIdx != (keysNumber -1)))
		{
			(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);
			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

			return;
		}
    }
    doData->docLen += snprintf_s(doData->doc + uiLen, sizeof(doData->doc) - uiLen, _TRUNCATE,
                     "</Delete>");
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePOST,						  // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "delete",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        putProperties,                                // putProperties
		0,                                            // ServerSideEncryptionParams
        &deleteObjectPropertiesCallback,              // propertiesCallback
        &deleteObjectDataToS3Callback,				  // toS3Callback
        doData->docLen,								  // toS3CallbackTotalSize
        &deleteObjectDataFromS3Callback,			  // fromS3Callback
        &deleteObjectCompleteCallback,				  // completeCallback
        doData,										  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave DeleteObjects succssfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}


// InitiateMultipartUpload ----------------------------------------------------------------
typedef struct InitiateMultipartUploadData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int uploadIdReturnSize;
    char *uploadIdReturn;

    string_buffer(uploadID, 256);
} InitiateMultipartUploadData;


static S3Status InitiateMultipartUploadXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    InitiateMultipartUploadData *imuData = (InitiateMultipartUploadData *) callbackData;

    int fit;

    if (data && !strcmp(elementPath, "InitiateMultipartUploadResult/UploadId")) {
        string_buffer_append(imuData->uploadID, data, dataLen, fit);
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status InitiateMultipartUploadPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    InitiateMultipartUploadData *imuData = (InitiateMultipartUploadData *) callbackData;
    
    return (*(imuData->responsePropertiesCallback))
        (responseProperties, imuData->callbackData);
}


static S3Status InitiateMultipartUploadDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    InitiateMultipartUploadData *imuData = (InitiateMultipartUploadData *) callbackData;

    return simplexml_add(&(imuData->simpleXml), buffer, bufferSize);
}


static void InitiateMultipartUploadCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)//lint !e101
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    InitiateMultipartUploadData *imuData = (InitiateMultipartUploadData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(imuData->uploadIdReturn, sizeof(imuData->uploadID),
             imuData->uploadIdReturnSize, "%s", 
             imuData->uploadID);

    (void)(*(imuData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, imuData->callbackData);

    simplexml_deinitialize(&(imuData->simpleXml));

    free(imuData);
	imuData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

// InitiateMultipartUpload without server side encryption----------------------------------------------------------------
void InitiateMultipartUpload(const S3BucketContext *bucketContext,const char* key,const S3PutProperties *putProperties,
                    int uploadIdReturnSize,
                    char *uploadIdReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter InitiateMultipartUpload successfully !");
    // Create the callback data
    InitiateMultipartUploadData *imuData = 
        (InitiateMultipartUploadData *) malloc(sizeof(InitiateMultipartUploadData));
    if (!imuData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc InitiateMultipartUploadData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(imuData,sizeof(InitiateMultipartUploadData), 0, sizeof(InitiateMultipartUploadData));//add sizeof by jwx329074

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(imuData);        //zwx367245 2016.10.08 return之前先释放已申请的内存
		imuData=NULL;
		return;
	}
	if(uploadIdReturnSize < 0 ){
		COMMLOG(OBS_LOGERROR, "uploadIdReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(imuData);        //zwx367245 2016.10.08 return之前先释放已申请的内存
		imuData=NULL;
		return;
	}

    simplexml_initialize(&(imuData->simpleXml), &InitiateMultipartUploadXmlCallback, imuData);//lint !e119

    imuData->responsePropertiesCallback = handler->propertiesCallback;
    imuData->responseCompleteCallback = handler->completeCallback;
    imuData->callbackData = callbackData;

    imuData->uploadIdReturnSize = uploadIdReturnSize;
    imuData->uploadIdReturn = uploadIdReturn;
    string_buffer_initialize(imuData->uploadID);

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePOST,                          // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        0,                                            // queryParams
        "uploads",                                    // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        putProperties,                                // putProperties
		0,                                            // ServerSideEncryptionParams
        &InitiateMultipartUploadPropertiesCallback,   // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &InitiateMultipartUploadDataCallback,         // fromS3Callback
        &InitiateMultipartUploadCompleteCallback,     // completeCallback
        imuData,                                 	  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave InitiateMultipartUpload successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// InitiateMultipartUpload with server side encryption----------------------------------------------------------------
void InitiateMultipartUploadWithServerSideEncryption(const S3BucketContext *bucketContext,const char* key,const S3PutProperties *putProperties,
	int uploadIdReturnSize,
	char *uploadIdReturn, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter InitiateMultipartUploadWithServerSideEncryption successfully !");
	// Create the callback data
	InitiateMultipartUploadData *imuData = 
		(InitiateMultipartUploadData *) malloc(sizeof(InitiateMultipartUploadData));
	if (!imuData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc InitiateMultipartUploadData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
	}
	memset_s(imuData,sizeof(InitiateMultipartUploadData), 0, sizeof(InitiateMultipartUploadData));//add sizeof by jwx329074

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(imuData);        //zwx367245 2016.10.08 return之前先释放已申请的内存
		imuData=NULL;
		return;
	}
	if(uploadIdReturnSize < 0 ){
		COMMLOG(OBS_LOGERROR, "uploadIdReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(imuData);        //zwx367245 2016.10.08 return之前先释放已申请的内存
		imuData=NULL;
		return;
	}

	simplexml_initialize(&(imuData->simpleXml), &InitiateMultipartUploadXmlCallback, imuData);//lint !e119

	imuData->responsePropertiesCallback = handler->propertiesCallback;
	imuData->responseCompleteCallback = handler->completeCallback;
	imuData->callbackData = callbackData;

	imuData->uploadIdReturnSize = uploadIdReturnSize;
	imuData->uploadIdReturn = uploadIdReturn;
	string_buffer_initialize(imuData->uploadID);

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypePOST,                          // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,                                          // key
		0,                                            // queryParams
		"uploads",                                    // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  // corsConf
		putProperties,                                // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		&InitiateMultipartUploadPropertiesCallback,   // propertiesCallback
		0,                                            // toS3Callback
		0,                                            // toS3CallbackTotalSize
		&InitiateMultipartUploadDataCallback,         // fromS3Callback
		&InitiateMultipartUploadCompleteCallback,     // completeCallback
		imuData,                                 	  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave InitiateMultipartUploadWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

// CompleteMultipartUpload -------------------------------------------------------------


typedef struct CompleteMultipartUploadData
{
    SimpleXml simpleXml;
    
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    S3CompleteMultipartUploadCallback *completeMultipartUploadCallback;
    void *callbackData;

    // DTS2015112500688 doc需要动态申请内存 modify by cwx298983 2015.11.26 Start
	char* doc;
	// DTS2015112500688 doc需要动态申请内存 modify by cwx298983 2015.11.26 End
    int docLen, docBytesWritten;
	string_buffer(location, 256);
	string_buffer(eTag, 256);
	string_buffer(bucket, 256);
	string_buffer(key, 256);
    
} CompleteMultipartUploadData; 

static S3Status CompleteMultipartUploadXmlCallback(const char *elementPath, const char *data,
                            int dataLen, void *callbackData)
{
    CompleteMultipartUploadData *cmuData = (CompleteMultipartUploadData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "CompleteMultipartUploadResult/Location")) {
#ifdef WIN32
		char* strTmpSource = (char*)malloc(sizeof(char) * (dataLen + 1));
		if (NULL == strTmpSource) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc strTmpSource failed!");
			return S3StatusInternalError;
		}
		memset_s(strTmpSource, sizeof(char) * (dataLen + 1), 0, dataLen + 1);
		strncpy_s(strTmpSource, dataLen+1, data, dataLen);
		char* strTmpOut = UTF8_To_String(strTmpSource);
		string_buffer_append(cmuData->location, strTmpOut, strlen(strTmpOut), fit);
		CHECK_NULL_FREE(strTmpSource);
		CHECK_NULL_FREE(strTmpOut);
#else
		string_buffer_append(cmuData->location, data, dataLen, fit);
#endif            
        }
        else if (!strcmp(elementPath, "CompleteMultipartUploadResult/Bucket")) {
            string_buffer_append(cmuData->bucket, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "CompleteMultipartUploadResult/Key")) {
#ifdef WIN32
		char* strTmpSource = (char*)malloc(sizeof(char) * (dataLen + 1));
		if (NULL == strTmpSource) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc strTmpSource failed!");
			return S3StatusInternalError;
		}
		memset_s(strTmpSource, sizeof(char) * (dataLen + 1), 0, dataLen + 1);
		strncpy_s(strTmpSource, dataLen+1, data, dataLen);
		char* strTmpOut = UTF8_To_String(strTmpSource);
		string_buffer_append(cmuData->key, strTmpOut, strlen(strTmpOut), fit);
		CHECK_NULL_FREE(strTmpSource);
		CHECK_NULL_FREE(strTmpOut);
#else
            string_buffer_append(cmuData->key, data, dataLen, fit);
#endif
        }
        else if (!strcmp(elementPath, "CompleteMultipartUploadResult/ETag")) {
            string_buffer_append(cmuData->eTag, data, dataLen, fit);
        }
    }    

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}

static S3Status CompleteMultipartUploadPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    CompleteMultipartUploadData *cmuData = (CompleteMultipartUploadData *) callbackData;
    
    return (*(cmuData->responsePropertiesCallback))
        (responseProperties, cmuData->callbackData);
}

static int CompleteMultipartUploadDataToS3Callback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    CompleteMultipartUploadData *cmuData = (CompleteMultipartUploadData *) callbackData;

    if (!cmuData->docLen) {
        return 0;
    }

    int remaining = (cmuData->docLen - cmuData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(cmuData->doc[cmuData->docBytesWritten]), toCopy);

    cmuData->docBytesWritten += toCopy;

    return toCopy;
}

static S3Status CompleteMultipartUploadDataFromS3Callback(int bufferSize, const char *buffer,
                             void *callbackData)
{
    CompleteMultipartUploadData *cmuData = (CompleteMultipartUploadData *) callbackData;

    return simplexml_add(&(cmuData->simpleXml), buffer, bufferSize);
}

static void CompleteMultipartUploadCompleteCallback(S3Status requestStatus,
                             const S3ErrorDetails *s3ErrorDetails,
                             void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    CompleteMultipartUploadData *cmuData = (CompleteMultipartUploadData *) callbackData;
	
   	(*(cmuData->completeMultipartUploadCallback))
		(cmuData->location,cmuData->bucket,cmuData->key,cmuData->eTag,cmuData->callbackData);
    (*(cmuData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, cmuData->callbackData);

    simplexml_deinitialize(&(cmuData->simpleXml));
	
	// DTS2015112500688 先释放doc的内存 modify by cwx298983 2015.11.26 Start
	if (NULL != cmuData->doc)
	{
		free(cmuData->doc);
		cmuData->doc = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	}
	// DTS2015112500688 先释放doc的内存 modify by cwx298983 2015.11.26 End
    free(cmuData);
	cmuData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}



void CompleteMultipartUpload(const S3BucketContext *bucketContext,const char*key,const char*uploadId,const S3UploadInfo *uploadInfo,
                      const unsigned int Number,const S3PutProperties *putProperties, S3RequestContext *requestContext,
                      const S3CompleteMultipartUploadHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter CompleteMultipartUpload successfully !");
	string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);
#define safe_appendh(name, value)                                        \
		do {																\
			int fit;														\
			if (amp) {														\
				string_buffer_append(queryParams, "&", 1, fit); 			\
				if (!fit) { 												\
					(void)(*(handler->responseHandler.completeCallback))			\
						(S3StatusQueryParamsTooLong, 0, callbackData);		\
					SYSTEMTIME rspTime;      \
                                   GetLocalTime(&rspTime);       \
                                   INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                                    return; 												\
				}															\
			}																\
			string_buffer_append(queryParams, name "=", 					\
								 sizeof(name "=") - 1, fit);				\
			if (!fit) { 													\
				(void)(*(handler->responseHandler.completeCallback))				\
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
                            SYSTEMTIME rspTime;      \
                            GetLocalTime(&rspTime);       \
                            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                            return; 													\
			}																\
			amp = 1;														\
			char encoded[3 * 1024] = {0}; 										\
			if (!urlEncode(encoded, value, 1024)) { 						\
				(void)(*(handler->responseHandler.completeCallback))				\
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
                            SYSTEMTIME rspTime;      \
                            GetLocalTime(&rspTime);       \
                            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                            return; 													\
			}																\
			string_buffer_append(queryParams, encoded, strlen(encoded), 	\
								 fit);										\
			if (!fit) { 													\
				(void)(*(handler->responseHandler.completeCallback))				\
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
                            SYSTEMTIME rspTime;      \
                            GetLocalTime(&rspTime);       \
                            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                            return; 													\
			}																\
		} while (0)

    int amp = 0;
	if (uploadId) {
		safe_appendh("uploadId", uploadId);
	}
	else
	{
		COMMLOG(OBS_LOGERROR, "uploadId is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
    
		return;
	}

    CompleteMultipartUploadData* cmuData = 
        (CompleteMultipartUploadData *) malloc(sizeof(CompleteMultipartUploadData));
    if (NULL == cmuData) {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc cmuData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
        return;
    }
	// 初始化CompleteMultipartUploadData结构体 by cwx298983 2015.12.01 Start
	memset_s(cmuData,sizeof(CompleteMultipartUploadData), 0, sizeof(CompleteMultipartUploadData));
	// 初始化CompleteMultipartUploadData结构体 by cwx298983 2015.12.01 End
	
	// DTS2015112500688 每次申请的字节数默认为2048 by cwx298983 2015.11.26 Start
	cmuData->doc = (char*)malloc(D_CMU_DATA_DEFAULT_LEN);
	if (NULL == cmuData->doc) {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc cmuData->doc failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
		free(cmuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		cmuData = NULL;
		return;
    }
	memset_s(cmuData->doc,D_CMU_DATA_DEFAULT_LEN, 0, D_CMU_DATA_DEFAULT_LEN);
	// DTS2015112500688 每次申请的字节数默认为2048 by cwx298983 2015.11.26 End
	
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");

		free(cmuData->doc);   //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存    先释放cmuData->doc所指内存空间
		cmuData->doc=NULL;

		free(cmuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		cmuData=NULL;
		return;
	}
    
    simplexml_initialize(&(cmuData->simpleXml), &CompleteMultipartUploadXmlCallback, cmuData);//lint !e119

    cmuData->responsePropertiesCallback = handler->responseHandler.propertiesCallback;
    cmuData->responseCompleteCallback = handler->responseHandler.completeCallback;
    cmuData->completeMultipartUploadCallback = handler->completeMultipartUploadCallback;
    cmuData->callbackData = callbackData;

    cmuData->docLen = 0;
    cmuData->docBytesWritten = 0;

    // DTS2015112500688 内存大小修改 by cwx298983 2015.11.26 Start
	cmuData->docLen += snprintf_s(cmuData->doc, D_CMU_DATA_DEFAULT_LEN, _TRUNCATE,
                     "<CompleteMultipartUpload>");
	// DTS2015112500688 内存大小修改 by cwx298983 2015.11.26 End

    unsigned int uiLen = strlen(cmuData->doc);
    unsigned int uiIdx = 0;
	// DTS2015112500688 计算内存相关变量 by cwx298983 2015.11.26 Start
	unsigned int uiRealloc = 1;					// 申请内存的次数
	unsigned int uiFixedLen = strlen("<Part><PartNumber></PartNumber><ETag></ETag></Part>");
	unsigned int uiEndLen = strlen("</CompleteMultipartUpload>");
	unsigned int uiPartLen = 0;
	unsigned int uieTagLen = 0;
	// DTS2015112500688 计算内存相关变量 by cwx298983 2015.11.26 End
    for(; uiIdx < Number; uiIdx++)//lint !e574
    {
        if(NULL != uploadInfo[uiIdx].partNumber && NULL != uploadInfo[uiIdx].eTag)//lint !e409
        {
         	char*ppartNumber = 0;
			char*peTag = 0;
			int mark1 = 0;
			int mark2 = 0;
        	mark1 = pcre_replace(uploadInfo[uiIdx].partNumber,&ppartNumber);//lint !e409
        	mark2 = pcre_replace(uploadInfo[uiIdx].eTag,&peTag);//lint !e409
			
			// DTS2015112500688 计算内存，不够重新分配 by cwx298983 2015.11.26 Start
			uiPartLen = strlen(mark1 ? ppartNumber : uploadInfo[uiIdx].partNumber);//lint !e409
			uieTagLen = strlen(mark2 ? peTag : uploadInfo[uiIdx].eTag);//lint !e409
			
			unsigned int uiTotalLen = cmuData->docLen + uiFixedLen + uiEndLen + uiPartLen + uieTagLen;
			if (uiTotalLen >= D_CMU_DATA_DEFAULT_LEN * uiRealloc)
			{
				uiRealloc++;
				char* tmpBuf = (char*)malloc(D_CMU_DATA_DEFAULT_LEN * uiRealloc);
				//cmuData->doc = (char*)malloc(D_CMU_DATA_DEFAULT_LEN * uiRealloc);
				if (NULL == tmpBuf) 
				{
					(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
					COMMLOG(OBS_LOGERROR, "Malloc tmpBuf failed !");

					SYSTEMTIME rspTime; 
					GetLocalTime(&rspTime);
					INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
					if(mark1) //zwx367245 2016.10.08 内存分配失败之后推出，否则空的指针tmpBuf传进memset_s导致程序崩溃。
					{
						free(ppartNumber);
						ppartNumber = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
					}
					if(mark2)
					{
						free(peTag);
						peTag = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
					}

					free(cmuData->doc);   //jwx329074 2016.10.09   return之前先释放cmuData->doc所指内存空间
					cmuData->doc = NULL;

					free(cmuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
					cmuData=NULL;
					return;   
				}
				memset_s(tmpBuf, D_CMU_DATA_DEFAULT_LEN * uiRealloc, 0, D_CMU_DATA_DEFAULT_LEN * uiRealloc);
				memcpy_s(tmpBuf, D_CMU_DATA_DEFAULT_LEN * uiRealloc, cmuData->doc, D_CMU_DATA_DEFAULT_LEN * (uiRealloc-1));
				free(cmuData->doc);   //jwx329074 2016.10.09   return之前先释放cmuData->doc所指内存空间
				cmuData->doc = tmpBuf;
			}
            cmuData->docLen += snprintf_s(cmuData->doc + uiLen, D_CMU_DATA_DEFAULT_LEN * uiRealloc - uiLen, _TRUNCATE, 
                     "<Part><PartNumber>%s</PartNumber><ETag>%s</ETag></Part>", mark1 ? ppartNumber : uploadInfo[uiIdx].partNumber,mark2 ? peTag : uploadInfo[uiIdx].eTag);//lint !e409
 			// DTS2015112500688 计算内存，不够重新分配 by cwx298983 2015.11.26 End
 
            uiLen = strlen(cmuData->doc);
			if(mark1)
			{
				free(ppartNumber);
				ppartNumber = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
			if(mark2)
			{
				free(peTag);
				peTag = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
        }
 	// DTS2015112500688 不需要内存越界判断，末尾补0 by cwx298983 2015.11.26 Start
	//if((cmuData->docLen >= 2048) && (uiIdx != (Number -1)))
    	//{
	//	(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);
	//	return;
	//}
    }
    cmuData->docLen += snprintf_s(cmuData->doc + uiLen, D_CMU_DATA_DEFAULT_LEN * uiRealloc - uiLen, _TRUNCATE,
                     "</CompleteMultipartUpload>");
	cmuData->doc[cmuData->docLen] = '\0';
	// DTS2015112500688 不需要内存越界判断，末尾补0 by cwx298983 2015.11.26 End
					
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePOST,                          // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                   		  // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        putProperties,                                // putProperties
		0,                                            // ServerSideEncryptionParams
        &CompleteMultipartUploadPropertiesCallback,   // propertiesCallback
        &CompleteMultipartUploadDataToS3Callback,     // toS3Callback
        cmuData->docLen,                              // toS3CallbackTotalSize
        &CompleteMultipartUploadDataFromS3Callback,   // fromS3Callback
        &CompleteMultipartUploadCompleteCallback,     // completeCallback
        cmuData,									  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave CompleteMultipartUpload successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}

// CompleteMultipartUpload with server side encryption-------------------------------------------------------------
void CompleteMultipartUploadWithServerSideEncryption(const S3BucketContext *bucketContext,const char*key,const char*uploadId,const S3UploadInfo *uploadInfo,
	const unsigned int Number,const S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams, S3RequestContext *requestContext,
	const S3CompleteMultipartUploadHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter CompleteMultipartUploadWithServerSideEncryption successfully !");
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);
#define safe_appendh(name, value)                                        \
	do {																\
	int fit;														\
	if (amp) {														\
	string_buffer_append(queryParams, "&", 1, fit); 			\
	if (!fit) { 												\
	(void)(*(handler->responseHandler.completeCallback))			\
	(S3StatusQueryParamsTooLong, 0, callbackData);		\
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);       \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return; 												\
	}															\
	}																\
	string_buffer_append(queryParams, name "=", 					\
	sizeof(name "=") - 1, fit);				\
	if (!fit) { 													\
	(void)(*(handler->responseHandler.completeCallback))				\
	(S3StatusQueryParamsTooLong, 0, callbackData);			\
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);       \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return; 													\
	}																\
	amp = 1;														\
	char encoded[3 * 1024] = {0}; 										\
	if (!urlEncode(encoded, value, 1024)) { 						\
	(void)(*(handler->responseHandler.completeCallback))				\
	(S3StatusQueryParamsTooLong, 0, callbackData);			\
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);       \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return; 													\
	}																\
	string_buffer_append(queryParams, encoded, strlen(encoded), 	\
	fit);										\
	if (!fit) { 													\
	(void)(*(handler->responseHandler.completeCallback))				\
	(S3StatusQueryParamsTooLong, 0, callbackData);			\
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);       \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return; 													\
	}																\
	} while (0)

	int amp = 0;
	if (uploadId) {
		safe_appendh("uploadId", uploadId);
	}
	else
	{
		COMMLOG(OBS_LOGERROR, "uploadId is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
	}

	CompleteMultipartUploadData* cmuData = 
		(CompleteMultipartUploadData *) malloc(sizeof(CompleteMultipartUploadData));
	if (NULL == cmuData) {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc cmuData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
		return;
	}
	// 初始化CompleteMultipartUploadData结构体 by cwx298983 2015.12.01 Start
	memset_s(cmuData,sizeof(CompleteMultipartUploadData), 0, sizeof(CompleteMultipartUploadData));
	// 初始化CompleteMultipartUploadData结构体 by cwx298983 2015.12.01 End

	// DTS2015112500688 每次申请的字节数默认为2048 by cwx298983 2015.11.26 Start
	cmuData->doc = (char*)malloc(D_CMU_DATA_DEFAULT_LEN);
	if (NULL == cmuData->doc) {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc cmuData->doc failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
		free(cmuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		cmuData = NULL;
		return;
	}
	memset_s(cmuData->doc,D_CMU_DATA_DEFAULT_LEN, 0, D_CMU_DATA_DEFAULT_LEN);
	// DTS2015112500688 每次申请的字节数默认为2048 by cwx298983 2015.11.26 End

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");

		free(cmuData->doc);   //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存    先释放cmuData->doc所指内存空间
		cmuData->doc=NULL;

		free(cmuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		cmuData=NULL;
		return;
	}

	simplexml_initialize(&(cmuData->simpleXml), &CompleteMultipartUploadXmlCallback, cmuData);//lint !e119

	cmuData->responsePropertiesCallback = handler->responseHandler.propertiesCallback;
	cmuData->responseCompleteCallback = handler->responseHandler.completeCallback;
	cmuData->completeMultipartUploadCallback = handler->completeMultipartUploadCallback;
	cmuData->callbackData = callbackData;

	cmuData->docLen = 0;
	cmuData->docBytesWritten = 0;

	// DTS2015112500688 内存大小修改 by cwx298983 2015.11.26 Start
	cmuData->docLen += snprintf_s(cmuData->doc, D_CMU_DATA_DEFAULT_LEN, _TRUNCATE,
		"<CompleteMultipartUpload>");
	// DTS2015112500688 内存大小修改 by cwx298983 2015.11.26 End

	unsigned int uiLen = strlen(cmuData->doc);
	unsigned int uiIdx = 0;
	// DTS2015112500688 计算内存相关变量 by cwx298983 2015.11.26 Start
	unsigned int uiRealloc = 1;					// 申请内存的次数
	unsigned int uiFixedLen = strlen("<Part><PartNumber></PartNumber><ETag></ETag></Part>");
	unsigned int uiEndLen = strlen("</CompleteMultipartUpload>");
	unsigned int uiPartLen = 0;
	unsigned int uieTagLen = 0;
	// DTS2015112500688 计算内存相关变量 by cwx298983 2015.11.26 End
	for(; uiIdx < Number; uiIdx++)//lint !e574
	{
		if(NULL != uploadInfo[uiIdx].partNumber && NULL != uploadInfo[uiIdx].eTag)//lint !e409
		{
			char*ppartNumber = 0;
			char*peTag = 0;
			int mark1 = 0;
			int mark2 = 0;
			mark1 = pcre_replace(uploadInfo[uiIdx].partNumber,&ppartNumber);//lint !e409
			mark2 = pcre_replace(uploadInfo[uiIdx].eTag,&peTag);//lint !e409

			// DTS2015112500688 计算内存，不够重新分配 by cwx298983 2015.11.26 Start
			uiPartLen = strlen(mark1 ? ppartNumber : uploadInfo[uiIdx].partNumber);//lint !e409
			uieTagLen = strlen(mark2 ? peTag : uploadInfo[uiIdx].eTag);//lint !e409

			unsigned int uiTotalLen = cmuData->docLen + uiFixedLen + uiEndLen + uiPartLen + uieTagLen;
			if (uiTotalLen >= D_CMU_DATA_DEFAULT_LEN * uiRealloc)
			{
				uiRealloc++;
				char* tmpBuf = (char*)malloc(D_CMU_DATA_DEFAULT_LEN * uiRealloc);
				//cmuData->doc = (char*)malloc(D_CMU_DATA_DEFAULT_LEN * uiRealloc);
				if (NULL == tmpBuf) 
				{
					(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
					COMMLOG(OBS_LOGERROR, "Malloc tmpBuf failed !");

					SYSTEMTIME rspTime; 
					GetLocalTime(&rspTime);
					INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
					if(mark1) //zwx367245 2016.10.08 内存分配失败之后推出，否则空的指针tmpBuf传进memset_s导致程序崩溃。
					{
						free(ppartNumber);
						ppartNumber = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
					}
					if(mark2)
					{
						free(peTag);
						peTag = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
					}

					free(cmuData->doc);   //jwx329074 2016.10.09   return之前先释放cmuData->doc所指内存空间
					cmuData->doc = NULL;

					free(cmuData);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
					cmuData=NULL;
					return;   
				}
				memset_s(tmpBuf, D_CMU_DATA_DEFAULT_LEN * uiRealloc, 0, D_CMU_DATA_DEFAULT_LEN * uiRealloc);
				memcpy_s(tmpBuf, D_CMU_DATA_DEFAULT_LEN * uiRealloc, cmuData->doc, D_CMU_DATA_DEFAULT_LEN * (uiRealloc-1));
				free(cmuData->doc);   //jwx329074 2016.10.09   return之前先释放cmuData->doc所指内存空间
				cmuData->doc = tmpBuf;
			}
			cmuData->docLen += snprintf_s(cmuData->doc + uiLen, D_CMU_DATA_DEFAULT_LEN * uiRealloc - uiLen, _TRUNCATE, 
				"<Part><PartNumber>%s</PartNumber><ETag>%s</ETag></Part>", mark1 ? ppartNumber : uploadInfo[uiIdx].partNumber,mark2 ? peTag : uploadInfo[uiIdx].eTag);//lint !e409
			// DTS2015112500688 计算内存，不够重新分配 by cwx298983 2015.11.26 End

			uiLen = strlen(cmuData->doc);
			if(mark1)
			{
				free(ppartNumber);
				ppartNumber = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
			if(mark2)
			{
				free(peTag);
				peTag = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		// DTS2015112500688 不需要内存越界判断，末尾补0 by cwx298983 2015.11.26 Start
		//if((cmuData->docLen >= 2048) && (uiIdx != (Number -1)))
		//{
		//	(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		//	return;
		//}
	}
	cmuData->docLen += snprintf_s(cmuData->doc + uiLen, D_CMU_DATA_DEFAULT_LEN * uiRealloc - uiLen, _TRUNCATE,
		"</CompleteMultipartUpload>");
	cmuData->doc[cmuData->docLen] = '\0';
	// DTS2015112500688 不需要内存越界判断，末尾补0 by cwx298983 2015.11.26 End

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypePOST,                          // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,                                          // key
		queryParams[0] ? queryParams : 0,             // queryParams
		0,                                   		  // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
		0,											  //corsConf
		putProperties,                                // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		&CompleteMultipartUploadPropertiesCallback,   // propertiesCallback
		&CompleteMultipartUploadDataToS3Callback,     // toS3Callback
		cmuData->docLen,                              // toS3CallbackTotalSize
		&CompleteMultipartUploadDataFromS3Callback,   // fromS3Callback
		&CompleteMultipartUploadCompleteCallback,     // completeCallback
		cmuData,									  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave CompleteMultipartUploadWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// ListParts -------------------------------------------------------------------

typedef struct Parts
{
    string_buffer(partNumber, 24);
    string_buffer(lastModified, 256);
    string_buffer(eTag, 256);
    string_buffer(size, 24);
} Parts;

static void initialize_parts(Parts *parts)
{
    string_buffer_initialize(parts->partNumber);
    string_buffer_initialize(parts->lastModified);
    string_buffer_initialize(parts->eTag);
    string_buffer_initialize(parts->size);
}

#define MAX_PARTS 32

typedef struct ListPartsData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
	S3ListPartsCallback *listPartsCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

	string_buffer(initiatorId, 1024);
	string_buffer(initiatorDisplayName, 1024);
	string_buffer(ownerId, 1024);
	string_buffer(ownerDisplayName, 1024);
	string_buffer(storageClass, 64);
	string_buffer(nextPartNumberMarker, 256);
	string_buffer(isTruncated, 64);

	int partsCount;
	Parts parts[MAX_PARTS];

} ListPartsData;

static void initialize_list_parts_data(ListPartsData *lpData)
{
    lpData->partsCount = 0;
    initialize_parts(lpData->parts);
}

static S3Status make_list_parts_callback(ListPartsData *lpData)
{
    int i;
	S3Status iRet =  S3StatusOK;

    // Convert IsTruncated
    int isTruncated = (!strcmp(lpData->isTruncated, "true") ||
                       !strcmp(lpData->isTruncated, "1")) ? 1 : 0;

	// Convert initiator
	char *initiatorId = lpData->initiatorId;
	char *initiatorDisplayName = lpData->initiatorDisplayName;

	// Convert owner
	char *ownerId = lpData->ownerId;
	char *ownerDisplayName = lpData->ownerDisplayName;

    // Convert the patrs
    //S3ListParts parts[lpData->partsCount];
	if(lpData->partsCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusInternalError;
	}
	S3ListParts *parts = (S3ListParts*)malloc(sizeof(S3ListParts) * lpData->partsCount);
	if (NULL == parts) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3ListParts failed!");
		return S3StatusInternalError;
	}
	memset_s(parts,sizeof(S3ListParts) * lpData->partsCount, 0, sizeof(S3ListParts) * lpData->partsCount);

    int partsCount = lpData->partsCount;
    for (i = 0; i < partsCount; i++) {
        S3ListParts *partsDest = &(parts[i]);
        Parts *partsSrc = &(lpData->parts[i]);
        partsDest->partNumber = partsSrc->partNumber;

        partsDest->lastModified = 
            parseIso8601Time(partsSrc->lastModified);
	int nTimeZone = getTimeZone();
	partsDest->lastModified += nTimeZone * SECONDS_TO_AN_HOUR;
        partsDest->eTag = partsSrc->eTag;
		
        partsDest->size = parseUnsignedInt(partsSrc->size);
        
    }

	iRet = (*(lpData->listPartsCallback))
		(isTruncated, lpData->nextPartNumberMarker, initiatorId, initiatorDisplayName, ownerId, ownerDisplayName,
		partsCount, parts,  lpData->callbackData);

	CHECK_NULL_FREE(parts);

    return iRet;
}


static S3Status ListPartsXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    ListPartsData *lpData = (ListPartsData *) callbackData;

    int fit;

	if (data)
		{
			if(!strcmp(elementPath, "ListPartsResult/Initiator/ID")) {
				string_buffer_append(lpData->initiatorId, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Initiator/DisplayName")) {
				string_buffer_append(lpData->initiatorDisplayName, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Owner/ID")) {
				string_buffer_append(lpData->ownerId, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Owner/DisplayName")) {
				string_buffer_append(lpData->ownerDisplayName, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/StorageClass")) {
				string_buffer_append(lpData->storageClass, data, dataLen, fit);
			}			
			else if(!strcmp(elementPath, "ListPartsResult/NextPartNumberMarker")) {
				string_buffer_append(lpData->nextPartNumberMarker, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/IsTruncated")) {
				string_buffer_append(lpData->isTruncated, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Part/PartNumber"))
			{
				Parts *parts = 
					&(lpData->parts[lpData->partsCount]);
				string_buffer_append(parts->partNumber, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Part/LastModified"))
			{
				Parts *parts = 
					&(lpData->parts[lpData->partsCount]);
				string_buffer_append(parts->lastModified, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Part/ETag"))
			{
				Parts *parts = 
					&(lpData->parts[lpData->partsCount]);
				string_buffer_append(parts->eTag, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "ListPartsResult/Part/Size"))
			{
				Parts *parts = 
					&(lpData->parts[lpData->partsCount]);
				string_buffer_append(parts->size, data, dataLen, fit);
			}
		}
	else {
		if (!strcmp(elementPath, "ListPartsResult/Part")) {
            // Finished a part
            lpData->partsCount++;
            if (lpData->partsCount == MAX_PARTS) {
                // Make the callback
                S3Status status = make_list_parts_callback(lpData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_list_parts_data(lpData);
            }
            else {
                // Initialize the next one
                initialize_parts
                    (&(lpData->parts[lpData->partsCount]));
            }
        }
	}
    


    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status ListPartsPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    ListPartsData *lpData = (ListPartsData *) callbackData;
    
    return (*(lpData->responsePropertiesCallback))
        (responseProperties, lpData->callbackData);
}


static S3Status ListPartsDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    ListPartsData *lpData = (ListPartsData *) callbackData;
    return simplexml_add(&(lpData->simpleXml), buffer, bufferSize);
}


static void ListPartsCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    ListPartsData *lpData = (ListPartsData *) callbackData;

    // Copy the location constraint into the return buffer
    if (lpData->partsCount) {
        make_list_parts_callback(lpData);
    }

    (*(lpData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, lpData->callbackData);

    simplexml_deinitialize(&(lpData->simpleXml));


    free(lpData);
	lpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void ListParts(const S3BucketContext *bucketContext, const char *key,
					const char *uploadId,
					const char *max_parts,
					const char *part_number_marker,
                    S3RequestContext *requestContext,
                    const S3ListPartsHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter ListParts successfully !");
 	// Compose the query params
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);
	
	#define ListParts_safe_append(name, value)                                        \
	do {																\
		int fit;														\
		if (amp) {														\
			string_buffer_append(queryParams, "&", 1, fit); 			\
			if (!fit) { 												\
				(void)(*(handler->responseHandler.completeCallback))			\
					(S3StatusQueryParamsTooLong, 0, callbackData);		\
                            SYSTEMTIME rspTime;     \
                            GetLocalTime(&rspTime);    \
                            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                            return; 												\
			}															\
		}																\
		string_buffer_append(queryParams, name "=", 					\
							 sizeof(name "=") - 1, fit);				\
		if (!fit) { 													\
			(void)(*(handler->responseHandler.completeCallback))				\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
                     SYSTEMTIME rspTime;     \
                     GetLocalTime(&rspTime);    \
                     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                     return; 													\
		}																\
		amp = 1;														\
		char encoded[3 * 1024] = {0}; 										\
		if (!urlEncode(encoded, value, 1024)) { 						\
			(void)(*(handler->responseHandler.completeCallback))				\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
                     SYSTEMTIME rspTime;     \
                     GetLocalTime(&rspTime);    \
                     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                     return; 													\
		}																\
		string_buffer_append(queryParams, encoded, strlen(encoded), 	\
							 fit);										\
		if (!fit) { 													\
			(void)(*(handler->responseHandler.completeCallback))				\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
                     SYSTEMTIME rspTime;     \
                     GetLocalTime(&rspTime);    \
                     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                     return; 													\
		}																\
	} while (0)

	int amp = 0;
	
	// Adjust the url order by cwx298983 2015.11.24 Start
	if (uploadId)
	{
		ListParts_safe_append("uploadId", uploadId);
	}
	if (max_parts) {
		ListParts_safe_append("max-parts", max_parts);
	}
	if (part_number_marker) {
		ListParts_safe_append("part-number-marker", part_number_marker);
	}
	// Adjust the url order by cwx298983 2015.11.24 End

    ListPartsData *lpData =
        (ListPartsData *) malloc(sizeof(ListPartsData));

    if (!lpData) {
		(void)(*(handler->responseHandler.completeCallback))
			(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGINFO, "Malloc ListPartsData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
		return;
    }
	memset_s(lpData,sizeof(ListPartsData), 0, sizeof(ListPartsData));

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(lpData);        //zwx367245 2016.10.08 return之前先释放已申请的内存 
		lpData=NULL;
		return;
	}
	if(NULL == uploadId){
		COMMLOG(OBS_LOGERROR, "uploadId is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(lpData);        //zwx367245 2016.10.08 return之前先释放已申请的内存 
		lpData=NULL;
		return;
	}

    simplexml_initialize(&(lpData->simpleXml), &ListPartsXmlCallback, lpData);//lint !e119
    
    lpData->responsePropertiesCallback = 
        handler->responseHandler.propertiesCallback;
    lpData->listPartsCallback = handler->listPartsCallback;
    lpData->responseCompleteCallback = 
        handler->responseHandler.completeCallback;
    lpData->callbackData = callbackData;

    string_buffer_initialize(lpData->initiatorId);
    string_buffer_initialize(lpData->initiatorDisplayName);
    string_buffer_initialize(lpData->ownerId);
    string_buffer_initialize(lpData->ownerDisplayName);
    string_buffer_initialize(lpData->storageClass);
    string_buffer_initialize(lpData->nextPartNumberMarker);
    string_buffer_initialize(lpData->isTruncated);

    initialize_list_parts_data(lpData);

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &ListPartsPropertiesCallback,                 // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &ListPartsDataCallback,                       // fromS3Callback
        &ListPartsCompleteCallback,                   // completeCallback
        lpData,                                 	  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
	request_perform(&params, requestContext);

	COMMLOG(OBS_LOGINFO, "Leave ListParts successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// GetObjectMetadata without server side encryption--------------------------------------------------------------------
void GetObjectMetadata(const S3BucketContext *bucketContext, const char *key,
     				const char *versionId,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
    SYSTEMTIME reqTime; 
    GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetObjectMetadata successfully !");
	if(NULL == key || !strlen(key)){
		COMMLOG(OBS_LOGERROR, "key is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidKey, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidKey, "");

		return;
	}
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		return;
	}
	 // Compose the query params
	 string_buffer(queryParams, 4096);//lint !e539
	 string_buffer_initialize(queryParams);
	 
	 #define safe_appendm(name, value)                                        \
	 do {                \
	  int fit;              \
	  if (amp) {              \
	   string_buffer_append(queryParams, "&", 1, fit);    \
	   if (!fit) {             \
	    (void)(*(handler->completeCallback))   \
	     (S3StatusQueryParamsTooLong, 0, callbackData);  \
            SYSTEMTIME rspTime;      \
            GetLocalTime(&rspTime);     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;             \
	   }               \
	  }                \
	  string_buffer_append(queryParams, name "=",      \
	        sizeof(name "=") - 1, fit);    \
	  if (!fit) {              \
	   (void)(*(handler->completeCallback))    \
	    (S3StatusQueryParamsTooLong, 0, callbackData);   \
            SYSTEMTIME rspTime;      \
            GetLocalTime(&rspTime);     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
           return;              \
	  }                \
	  amp = 1;              \
	  char encoded[3 * 1024] = {0};           \
	  if (!urlEncode(encoded, value, 1024)) {       \
	   (void)(*(handler->completeCallback))    \
	    (S3StatusQueryParamsTooLong, 0, callbackData);   \
            SYSTEMTIME rspTime;      \
            GetLocalTime(&rspTime);     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
           return;              \
	  }                \
	  string_buffer_append(queryParams, encoded, strlen(encoded),  \
	        fit);          \
	  if (!fit) {              \
	   (void)(*(handler->completeCallback))    \
	    (S3StatusQueryParamsTooLong, 0, callbackData);   \
            SYSTEMTIME rspTime;      \
            GetLocalTime(&rspTime);     \
	     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
           return;              \
	  }                \
	 } while (0)

	 int amp = 0;
	  
	 if (versionId) {
	  safe_appendm("versionId", versionId);
	 }

	 // Set up the RequestParams
	 RequestParams params =
	 {
	  HttpRequestTypeHEAD,							  // httpRequestType
	  { bucketContext->hostName,                      // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
	  key,											  // key
	  queryParams[0] ? queryParams : 0,				  // queryParams
	  0,											  // subResource
	  0,											  // copySourceBucketName
	  0,											  // copySourceKey
	  0,											  // getConditions
	  0,											  // startByte
	  0,											  // byteCount
	  0,											  // corsConf
	  0,											  // putProperties
	  0,                                              // ServerSideEncryptionParams
	  handler->propertiesCallback,					  // propertiesCallback
	  0,											  // toS3Callback
	  0,											  // toS3CallbackTotalSize
	  0,											  // fromS3Callback
	  handler->completeCallback,					  // completeCallback
	  callbackData            ,						  // callbackData
	  bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };


	 // Perform the request
	 request_perform(&params, requestContext);

	COMMLOG(OBS_LOGINFO, "Leave GetObjectMetadata successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

// GetObjectMetadata with server side encryption-------------------------------------------------------------------
void GetObjectMetadataWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *versionId, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter GetObjectMetadataWithServerSideEncryption successfully !");
	if(NULL == key || !strlen(key)){
		COMMLOG(OBS_LOGERROR, "key is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidKey, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidKey, "");

		return;
	}
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		return;
	}
	// Compose the query params
	string_buffer(queryParams, 4096);//lint !e539
	string_buffer_initialize(queryParams);

#define safe_appendm(name, value)                                        \
	do {                \
	int fit;              \
	if (amp) {              \
	string_buffer_append(queryParams, "&", 1, fit);    \
	if (!fit) {             \
	(void)(*(handler->completeCallback))   \
	(S3StatusQueryParamsTooLong, 0, callbackData);  \
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);     \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return;             \
	}               \
	}                \
	string_buffer_append(queryParams, name "=",      \
	sizeof(name "=") - 1, fit);    \
	if (!fit) {              \
	(void)(*(handler->completeCallback))    \
	(S3StatusQueryParamsTooLong, 0, callbackData);   \
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);     \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return;              \
	}                \
	amp = 1;              \
	char encoded[3 * 1024] = {0};           \
	if (!urlEncode(encoded, value, 1024)) {       \
	(void)(*(handler->completeCallback))    \
	(S3StatusQueryParamsTooLong, 0, callbackData);   \
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);     \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return;              \
	}                \
	string_buffer_append(queryParams, encoded, strlen(encoded),  \
	fit);          \
	if (!fit) {              \
	(void)(*(handler->completeCallback))    \
	(S3StatusQueryParamsTooLong, 0, callbackData);   \
	SYSTEMTIME rspTime;      \
	GetLocalTime(&rspTime);     \
	INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
	return;              \
	}                \
	} while (0)

	int amp = 0;

	if (versionId) {
		safe_appendm("versionId", versionId);
	}

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeHEAD,					      // httpRequestType
		{ bucketContext->hostName,                    // hostName
		bucketContext->bucketName,                    // bucketName
		bucketContext->protocol,                      // protocol
		bucketContext->uriStyle,                      // uriStyle
		bucketContext->accessKeyId,                   // accessKeyId
		bucketContext->secretAccessKey,               // secretAccessKey
		bucketContext->certificateInfo },             // certificateInfo
		key,										  // key
		queryParams[0] ? queryParams : 0,			  // queryParams
		0,											  // subResource
		0,											  // copySourceBucketName
		0,											  // copySourceKey
		0,											  // getConditions
		0,											  // startByte
		0,											  // byteCount
		0,											  // corsConf
		0,											  // putProperties
		serverSideEncryptionParams,                   // ServerSideEncryptionParams
		handler->propertiesCallback,				  // propertiesCallback
		0,											  // toS3Callback
		0,											  // toS3CallbackTotalSize
		0,											  // fromS3Callback
		handler->completeCallback,					  // completeCallback
		callbackData            ,						  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
	};


	// Perform the request
	request_perform(&params, requestContext);

	COMMLOG(OBS_LOGINFO, "Leave GetObjectMetadataWithServerSideEncryption successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


void GetBucketMetadata(const S3BucketContext *bucketContext,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketMetadata successfully !");
	 
	 if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
    
		return;
	 }
	 // Set up the RequestParams
	 RequestParams params =
	 {
	  HttpRequestTypeHEAD,							  // httpRequestType
	  { bucketContext->hostName,                      // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
	  0,											  // key
	  0,										      // queryParams
	  0,										      // subResource
	  0,										      // copySourceBucketName
	  0,										      // copySourceKey
	  0,										      // getConditions
	  0,										      // startByte
	  0,										      // byteCount
	  0,											  //corsConf
	  0,										      // putProperties
	  0,                                              // ServerSideEncryptionParams
	  handler->propertiesCallback,					  // propertiesCallback
	  0,											  // toS3Callback
	  0,											  // toS3CallbackTotalSize
	  0,											  // fromS3Callback
	  handler->completeCallback,					  // completeCallback
	  callbackData,									  // callbackData
	  bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };


	 // Perform the request
	 request_perform(&params, requestContext);

	COMMLOG(OBS_LOGINFO, "Leave GetBucketMetadata successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}

// OPTIONS object-------------------------------------------------------------


void OptionsObject(const S3BucketContext *bucketContext,const char* key, const char* origin,
					  const char (*requestMethod)[256],const unsigned int rmNumber,
					  const char (*requestHeader)[256],const unsigned int rhNumber,
					  S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
    GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);
	if(NULL == requestMethod || NULL == origin || NULL == key || !strlen(key)){
		COMMLOG(OBS_LOGERROR, "requestMethod or origin is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.17
        (void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
    
        return;
	}	
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.17
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");

		return;
	}
	unsigned int i = 0;
	S3CorsConf corsConf;
	corsConf.origin = origin;
	corsConf.rmNumber = rmNumber;
	corsConf.rhNumber = rhNumber;
	for(i = 0; i < rmNumber; i ++)//lint !e574
	{
		corsConf.requestMethod[i] = requestMethod[i];//lint !e409
	}

	for(i = 0; i < rhNumber; i ++)//lint !e574
	{
		corsConf.requestHeader[i] = requestHeader[i];//lint !e409
	}
	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeOPTIONS, 				      // httpRequestType
		{ bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
		key,										  // key
		0,											  // queryParams
		0,											  // subResource
		0,											  // copySourceBucketName
		0,											  // copySourceKey
		0,											  // getConditions
		0,											  // startByte
		0,											  // byteCount
		&corsConf,									  //corsConf
		0,											  // putProperties
		0,                                            // ServerSideEncryptionParams
		handler->propertiesCallback,				  // propertiesCallback
		0,											  // toS3Callback
		0,											  // toS3CallbackTotalSize
		0,											  // fromS3Callback
		handler->completeCallback,					  // completeCallback
		callbackData,								  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };
	
	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

void OptionsBucket(const S3BucketContext *bucketContext,const char* origin,
					  const char (*requestMethod)[256],const unsigned int rmNumber,
					  const char (*requestHeader)[256],const unsigned int rhNumber,
					  S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
    GetLocalTime(&reqTime);


	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);
	if(NULL == requestMethod || NULL == origin){
		COMMLOG(OBS_LOGERROR, "requestMethod or origin is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.17
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
	}	
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
    
		return;
	}
	unsigned int i = 0;
	S3CorsConf corsConf;
	corsConf.origin = origin;
	corsConf.rmNumber = rmNumber;
	corsConf.rhNumber = rhNumber;
	for(i = 0; i < rmNumber; i ++)//lint !e574
	{
		corsConf.requestMethod[i] = requestMethod[i];//lint !e409
	}

	for(i = 0; i < rhNumber; i ++)//lint !e574
	{
		corsConf.requestHeader[i] = requestHeader[i];//lint !e409
	}
	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeOPTIONS, 					  // httpRequestType
		{ bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
		0,											  // key
		0,											  // queryParams
		0,										      // subResource
		0,											  // copySourceBucketName
		0,											  // copySourceKey
		0,											  // getConditions
		0,											  // startByte
		0,											  // byteCount
		&corsConf,									  // corsConf
		0,											  // putProperties
		0,                                            // ServerSideEncryptionParams
		handler->propertiesCallback,				  // propertiesCallback
		0,											  // toS3Callback
		0,											  // toS3CallbackTotalSize
		0,										      // fromS3Callback
		handler->completeCallback,					  // completeCallback
		callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };
	
	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}
//lint +e26 +e31 +e63 +e64 +e78 +e101 +e119 +e129 +e144 +e156 +e438 +e505 +e516 +e515 +e522 +e530 +e533 +e534 +e546 +e551 +e578 +e601

