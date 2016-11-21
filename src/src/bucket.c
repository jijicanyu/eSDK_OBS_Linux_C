/** **************************************************************************
 * bucket.c
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

#include <string.h>
#include <stdlib.h>
#include "eSDKOBSS3.h"
#include "request.h"
#include "simplexml.h"
#include "securec.h"

// The number of seconds to an hour
#define SECONDS_TO_AN_HOUR 3600

#ifdef WIN32
# pragma warning (disable:4819)
# pragma warning (disable:4127)
#endif


/* _TRUNCATE */
#if !defined(_TRUNCATE)
#define _TRUNCATE ((size_t)-1)
#endif
//lint -e26 -e31 -e63 -e64 -e78 -e101 -e119 -e129 -e144 -e156 -e438 -e505 -e515 -e516 -e522 -e529 -e530 -e533 -e534 -e546 -e551 -e578 -e601
// test bucket ---------------------------------------------------------------
//lint -e601
typedef struct TestBucketData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int locationConstraintReturnSize;
    char *locationConstraintReturn;

    string_buffer(locationConstraint, 256);
} TestBucketData;
//lint +e601

static S3Status testBucketXmlCallback(const char *elementPath, const char *data, int dataLen, void *callbackData)
{
    TestBucketData *tbData = (TestBucketData *) callbackData;

    int fit;

    if (data && !strcmp(elementPath, "CreateBucketConfiguration/LocationConstraint")) {
        string_buffer_append(tbData->locationConstraint, data, dataLen, fit);
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status testBucketPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    TestBucketData *tbData = (TestBucketData *) callbackData;
    
    return (*(tbData->responsePropertiesCallback))
        (responseProperties, tbData->callbackData);
}


static S3Status testBucketDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    TestBucketData *tbData = (TestBucketData *) callbackData;

    return simplexml_add(&(tbData->simpleXml), buffer, bufferSize);
}

//lint -e101
static void testBucketCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    TestBucketData *tbData = (TestBucketData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(tbData->locationConstraintReturn, sizeof(tbData->locationConstraint),  //secure function
             tbData->locationConstraintReturnSize, "%s", 
             tbData->locationConstraint);

    (void)(*(tbData->responseCompleteCallback))(requestStatus, s3ErrorDetails, tbData->callbackData);//(void)

    simplexml_deinitialize(&(tbData->simpleXml));

    free(tbData);
	tbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void S3_test_bucket(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, 
					const char *secretAccessKey,
                    const char *hostName, 
					const char *bucketName,
                    int locationConstraintReturnSize,
                    char *locationConstraintReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter S3_test_bucket successfully !");
    // Create the callback data
    TestBucketData *tbData = 
        (TestBucketData *) malloc(sizeof(TestBucketData));
    if (!tbData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc TestBucketData failed !");
        return;
    }
	memset_s(tbData, sizeof(TestBucketData), 0, sizeof(TestBucketData));  //secure function

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);//(void)
		free(tbData);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		tbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	
	if(locationConstraintReturnSize < 0){
		COMMLOG(OBS_LOGERROR, "locationConstraintReturnSize is invalid!");
        (void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);//(void)
		free(tbData);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		tbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(tbData->simpleXml), &testBucketXmlCallback, tbData);//lint !e119

    tbData->responsePropertiesCallback = handler->propertiesCallback;
    tbData->responseCompleteCallback = handler->completeCallback;
    tbData->callbackData = callbackData;

    tbData->locationConstraintReturnSize = locationConstraintReturnSize;
    tbData->locationConstraintReturn = locationConstraintReturn;
    string_buffer_initialize(tbData->locationConstraint);

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          uriStyle,                                   // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "location",                                   // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &testBucketPropertiesCallback,                // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &testBucketDataCallback,                      // fromS3Callback
        &testBucketCompleteCallback,                  // completeCallback
        tbData,                                       // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_test_bucket successfully !");
}


void S3_test_bucket_CA(const S3BucketContext *bucketContext,
                    int locationConstraintReturnSize,
                    char *locationConstraintReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_test_bucket_CA successfully !");
    // Create the callback data
    TestBucketData *tbData = 
        (TestBucketData *) malloc(sizeof(TestBucketData));
    if (!tbData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);//(void)
		(void)COMMLOG(OBS_LOGERROR, "Malloc TestBucketData failed !");//(void)
        return;
    }
	memset_s(tbData, sizeof(TestBucketData) , 0, sizeof(TestBucketData)); //secure function

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
       (void) (*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);//(void)
		free(tbData);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		tbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(locationConstraintReturnSize < 0){
		COMMLOG(OBS_LOGERROR, "locationConstraintReturnSize is invalid!");
        (void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);//(void)
		free(tbData);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		tbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(tbData->simpleXml), &testBucketXmlCallback, tbData);//lint !e119

    tbData->responsePropertiesCallback = handler->propertiesCallback;
    tbData->responseCompleteCallback = handler->completeCallback;
    tbData->callbackData = callbackData;

    tbData->locationConstraintReturnSize = locationConstraintReturnSize;
    tbData->locationConstraintReturn = locationConstraintReturn;
    string_buffer_initialize(tbData->locationConstraint);

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
        0,                                            // key
        0,                                            // queryParams
        "location",                                   // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &testBucketPropertiesCallback,                // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &testBucketDataCallback,                      // fromS3Callback
        &testBucketCompleteCallback,                  // completeCallback
        tbData,                                       // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_test_bucket_CA successfully !");
}

//lint -e101
void GetBucketLocation(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId,
					const char *secretAccessKey,
                    const char *hostName,
					const char *bucketName,
                    int locationConstraintReturnSize,
                    char *locationConstraintReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter GetBucketLocation successfully !");
	S3_test_bucket(protocol, uriStyle, accessKeyId, secretAccessKey,
		hostName, bucketName, locationConstraintReturnSize, locationConstraintReturn,
		requestContext, handler, callbackData);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketLocation successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


void GetBucketLocationCA(const S3BucketContext *bucketContext,
                    int locationConstraintReturnSize,
                    char *locationConstraintReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketLocationCA successfully !");
	S3_test_bucket_CA(bucketContext, locationConstraintReturnSize, locationConstraintReturn, requestContext, handler, callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave GetBucketLocationCA successfully !");
    
	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// create bucket -------------------------------------------------------------
//lint -e601
typedef struct CreateBucketData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024];
    int docLen, docBytesWritten;
} CreateBucketData;                         
//lint +e601                            

static S3Status createBucketPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    CreateBucketData *cbData = (CreateBucketData *) callbackData;
    
    return (*(cbData->responsePropertiesCallback))
        (responseProperties, cbData->callbackData);
}


static int createBucketDataCallback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    CreateBucketData *cbData = (CreateBucketData *) callbackData;

    if (!cbData->docLen) {
        return 0;
    }

    int remaining = (cbData->docLen - cbData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

	memcpy_s(buffer,bufferSize,&(cbData->doc[cbData->docBytesWritten]),toCopy);//secure function
    cbData->docBytesWritten += toCopy;

    return toCopy;
}

//lint -e101
static void createBucketCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    CreateBucketData *cbData = (CreateBucketData *) callbackData;
	//Increase (void) ignore its return value by jwx329074 2016.10.13
    (void)(*(cbData->responseCompleteCallback))(requestStatus, s3ErrorDetails, cbData->callbackData);

    free(cbData);//lint !e516  
	cbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void S3_create_bucket(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName, S3CannedAcl cannedAcl,const char*storagepolicy,
                      const char *locationConstraint,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter S3_create_bucket successfully!");
    // Create the callback data
    CreateBucketData *cbData = 
        (CreateBucketData *) malloc(sizeof(CreateBucketData));
    if (!cbData) {
		COMMLOG(OBS_LOGERROR, "Malloc CreateBucketData failed!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
        return;
    }
	memset_s(cbData, sizeof(CreateBucketData), 0, sizeof(CreateBucketData));//lint !e516
	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(cbData);//lint !e516
		cbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
    cbData->responsePropertiesCallback = handler->propertiesCallback;
    cbData->responseCompleteCallback = handler->completeCallback;
    cbData->callbackData = callbackData;
	char*plocationConstraint = 0;
    if (locationConstraint) {
		int mark = pcre_replace(locationConstraint,&plocationConstraint);
        cbData->docLen =
            snprintf_s(cbData->doc, sizeof(cbData->doc), _TRUNCATE ,
                     "<CreateBucketConfiguration><LocationConstraint>"
                     "%s</LocationConstraint></CreateBucketConfiguration>",
                     mark ? plocationConstraint : locationConstraint);
        cbData->docBytesWritten = 0;
		if(mark)
		{
			free(plocationConstraint);//lint !e516
			plocationConstraint = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
    else 
	{
		COMMLOG(OBS_LOGERROR, "input param locationConstraint is NULL");
        cbData->docLen = 0;
    }    
    // Set up S3PutProperties
    S3PutProperties properties =
    {
        0,                                       // contentType
        0,                                       // md5
        0,                                       // cacheControl
        0,                                       // contentDispositionFilename
        0,                                       // contentEncoding
        storagepolicy,							 //storagepolicy
        0,										 //websiteredirectlocation
        0,										 //getConditions
        0,										 //startByte
        0,										 //byteCount
        0,                                       // expires
        cannedAcl,                               // cannedAcl
        0,                                       // metaDataCount
        0,                                       // metaData
        0                                        // useServerSideEncryption
    };
    
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          S3UriStylePath,                             // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        &properties,                                  // putProperties
		0,                                            // ServerSideEncryptionParams
        &createBucketPropertiesCallback,              // propertiesCallback
        &createBucketDataCallback,                    // toS3Callback
        cbData->docLen,                               // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &createBucketCompleteCallback,                // completeCallback
        cbData,                                       // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_create_bucket successfully!");
}


void S3_create_bucket_CA(const S3BucketContext *bucketContext,
						 S3CannedAcl cannedAcl,const char*storagepolicy,
						 const char *locationConstraint,
						 S3RequestContext *requestContext,
						 const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_create_bucket_CA successfully!");
    // Create the callback data
    CreateBucketData *cbData = 
        (CreateBucketData *) malloc(sizeof(CreateBucketData));
    if (!cbData) {
		COMMLOG(OBS_LOGERROR, "Malloc CreateBucketData failed!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
        return;
    }
	memset_s(cbData, sizeof(CreateBucketData), 0, sizeof(CreateBucketData));//lint !e516
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		 //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(cbData);//lint !e516   
		cbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
    cbData->responsePropertiesCallback = handler->propertiesCallback;
    cbData->responseCompleteCallback = handler->completeCallback;
    cbData->callbackData = callbackData;
	char*plocationConstraint = 0;
    if (locationConstraint) {
		int mark = pcre_replace(locationConstraint,&plocationConstraint);
        cbData->docLen =
            snprintf_s(cbData->doc, sizeof(cbData->doc), _TRUNCATE,   //secure function
                     "<CreateBucketConfiguration><LocationConstraint>"
                     "%s</LocationConstraint></CreateBucketConfiguration>",
                     mark ? plocationConstraint : locationConstraint);
        cbData->docBytesWritten = 0;
		if(mark)
		{
			free(plocationConstraint);//lint !e516
			plocationConstraint = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
    else 
	{
		COMMLOG(OBS_LOGERROR, "input param locationConstraint is NULL");
        cbData->docLen = 0;
    }   
    // Set up S3PutProperties
    S3PutProperties properties =
    {
        0,                                       // contentType
        0,                                       // md5
        0,                                       // cacheControl
        0,                                       // contentDispositionFilename
        0,                                       // contentEncoding
        storagepolicy,							 //storagepolicy
        0,										 //websiteredirectlocation
        0,										 //getConditions
        0,										 //startByte
        0,										 //byteCount
        0,                                       // expires
        cannedAcl,                               // cannedAcl
        0,                                       // metaDataCount
        0,                                       // metaData
        0                                        // useServerSideEncryption
    };
    
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          S3UriStylePath,							  // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        &properties,                                  // putProperties
		0,                                            // ServerSideEncryptionParams
        &createBucketPropertiesCallback,              // propertiesCallback
        &createBucketDataCallback,                    // toS3Callback
        cbData->docLen,                               // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &createBucketCompleteCallback,                // completeCallback
        cbData,                                       // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_create_bucket_CA successfully!");
}

//lint -e101
void CreateBucket(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName, S3CannedAcl cannedAcl,const char*storagepolicy,
                      const char *locationConstraint,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter CreateBucket successfully!");
	S3_create_bucket(protocol ,accessKeyId, secretAccessKey, hostName,
		bucketName, cannedAcl, storagepolicy, locationConstraint, 
		requestContext, handler, callbackData);
	COMMLOG(OBS_LOGINFO, "Leave CreateBucket successfully!");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


void CreateBucketCA(const S3BucketContext *bucketContext, 
					  S3CannedAcl cannedAcl,const char*storagepolicy,
                      const char *locationConstraint,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter CreateBucketCA successfully!");
	S3_create_bucket_CA(bucketContext,cannedAcl,storagepolicy,locationConstraint,
					requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave CreateBucketCA successfully!");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// delete bucket -------------------------------------------------------------
//lint -e601
typedef struct DeleteBucketData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
} DeleteBucketData;
//lint +e601

static S3Status deleteBucketPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    DeleteBucketData *dbData = (DeleteBucketData *) callbackData;
    
    return (*(dbData->responsePropertiesCallback))
        (responseProperties, dbData->callbackData);
}


static void deleteBucketCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteBucketData *dbData = (DeleteBucketData *) callbackData;

    (*(dbData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, dbData->callbackData);

    free(dbData);
	dbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void S3_delete_bucket(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter S3_delete_bucket successfully !");
    // Create the callback data
    DeleteBucketData *dbData = 
        (DeleteBucketData *) malloc(sizeof(DeleteBucketData));
    if (!dbData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketData failed");
		return;
    }
	memset_s(dbData, sizeof(DeleteBucketData), 0, sizeof(DeleteBucketData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		 //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(dbData);//lint !e516
		dbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	
    dbData->responsePropertiesCallback = handler->propertiesCallback;
    dbData->responseCompleteCallback = handler->completeCallback;
    dbData->callbackData = callbackData;

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,                        // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          uriStyle,                                   // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        0,                                            // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,											  // startByte
		0,											  // byteCount
		0,											  // corsConf
        0,											  // putProperties
		0,                                            // ServerSideEncryptionParams
        &deleteBucketPropertiesCallback,			  // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &deleteBucketCompleteCallback,                // completeCallback
        dbData,                                       // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_delete_bucket successfully !");
}


void S3_delete_bucket_CA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_delete_bucket_CA successfully !");
    // Create the callback data
    DeleteBucketData *dbData = 
        (DeleteBucketData *) malloc(sizeof(DeleteBucketData));
    if (!dbData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketData failed");
		return;
    }
	memset_s(dbData, sizeof(DeleteBucketData), 0, sizeof(DeleteBucketData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(dbData);//lint !e516    
		dbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	
    dbData->responsePropertiesCallback = handler->propertiesCallback;
    dbData->responseCompleteCallback = handler->completeCallback;
    dbData->callbackData = callbackData;

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
        0,                                            // key
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
        &deleteBucketPropertiesCallback,              // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &deleteBucketCompleteCallback,                // completeCallback
        dbData,                                       // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_delete_bucket_CA successfully !");
}

//lint -e101
void DeleteBucket(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter DeleteBucket successfully !");
	//Increase (void) ignore its return value by jwx329074 2016.10.13
	(void)S3_delete_bucket(protocol, uriStyle, accessKeyId, secretAccessKey,
                      hostName, bucketName, requestContext, handler, callbackData);
	COMMLOG(OBS_LOGINFO, "Leave DeleteBucket successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


void DeleteBucketCA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter DeleteBucketCA successfully !");
	S3_delete_bucket_CA(bucketContext, requestContext, handler, callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave DeleteBucketCA successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


// list bucket ----------------------------------------------------------------

typedef struct ListBucketContents
{
    string_buffer(key, 1024);
    string_buffer(lastModified, 256);
    string_buffer(eTag, 256);
    string_buffer(size, 24);
    string_buffer(ownerId, 256);
    string_buffer(ownerDisplayName, 256);
} ListBucketContents;


static void initialize_list_bucket_contents(ListBucketContents *contents)
{
    
	string_buffer_initialize(contents->key);
    string_buffer_initialize(contents->lastModified);
    string_buffer_initialize(contents->eTag);
    string_buffer_initialize(contents->size);
    string_buffer_initialize(contents->ownerId);
    string_buffer_initialize(contents->ownerDisplayName);
}

// We read up to 32 Contents at a time
#define MAX_CONTENTS 32
// We read up to 8 CommonPrefixes at a time
#define MAX_COMMON_PREFIXES 8

//lint -e601
typedef struct ListBucketData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ListBucketCallback *listBucketCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    string_buffer(isTruncated, 64);
    string_buffer(nextMarker, 1024);

    int contentsCount;
    ListBucketContents contents[MAX_CONTENTS];

    int commonPrefixesCount;
    char commonPrefixes[MAX_COMMON_PREFIXES][1024];
    int commonPrefixLens[MAX_COMMON_PREFIXES];
} ListBucketData;
//lint +e601

static void initialize_list_bucket_data(ListBucketData *lbData)
{
    lbData->contentsCount = 0;
    initialize_list_bucket_contents(lbData->contents);
    lbData->commonPrefixesCount = 0;
    lbData->commonPrefixes[0][0] = 0;
    lbData->commonPrefixLens[0] = 0;
}


static S3Status make_list_bucket_callback(ListBucketData *lbData)/*lint !e31 */
{

	S3Status iRet = S3StatusOK;

#define SIZE_INT_MAX 65535
    // Convert IsTruncated
    int isTruncated = (!strcmp(lbData->isTruncated, "true") ||
                       !strcmp(lbData->isTruncated, "1")) ? 1 : 0;

    // Convert the contents
	// 添加对malloc参数的合法性教验 by jwx329074 2016.11.18 
	if(lbData->contentsCount < 0)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusInternalError;
	}

	S3ListBucketContent *contents = (S3ListBucketContent*)malloc(sizeof(S3ListBucketContent) * lbData->contentsCount);
	if (NULL == contents) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3ListBucketContent failed!");
		return S3StatusInternalError;
	}
	memset_s(contents, sizeof(S3ListBucketContent) * lbData->contentsCount, 0, sizeof(S3ListBucketContent) * lbData->contentsCount);  //secure function

    int contentsCount = lbData->contentsCount;
	int i;
    for (i = 0; i < contentsCount; i++) {
		S3ListBucketContent *contentDest = &(contents[i]);
		ListBucketContents *contentSrc = &(lbData->contents[i]);
		contentDest->key = contentSrc->key;
		contentDest->lastModified = 
			parseIso8601Time(contentSrc->lastModified);
		int nTimeZone = getTimeZone();
		contentDest->lastModified += nTimeZone * SECONDS_TO_AN_HOUR;
		contentDest->eTag = contentSrc->eTag;
		contentDest->size = parseUnsignedInt(contentSrc->size);
		contentDest->ownerId =
			contentSrc->ownerId[0] ?contentSrc->ownerId : 0;
		contentDest->ownerDisplayName = (contentSrc->ownerDisplayName[0] ?
			contentSrc->ownerDisplayName : 0);
    }

    // Make the common prefixes array
    int commonPrefixesCount = lbData->commonPrefixesCount;
	if(commonPrefixesCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		CHECK_NULL_FREE(contents);        //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		return S3StatusInternalError;
	}
	char **commonPrefixes = (char**)malloc(sizeof(char *) * commonPrefixesCount);
	if (NULL == commonPrefixes) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc commonPrefixes failed!");
		CHECK_NULL_FREE(contents);
		return S3StatusInternalError;
	}
	//初始化
	memset_s(commonPrefixes, sizeof(char *) * commonPrefixesCount, 0, sizeof(char *) * commonPrefixesCount);

    for (i = 0; i < commonPrefixesCount; i++) {
        commonPrefixes[i] = lbData->commonPrefixes[i];
    }

	iRet = (*(lbData->listBucketCallback))
		(isTruncated, lbData->nextMarker,
		contentsCount, contents, commonPrefixesCount, 
		(const char **) commonPrefixes, lbData->callbackData);

	CHECK_NULL_FREE(contents);
	CHECK_NULL_FREE(commonPrefixes);

	return iRet;
}


static S3Status listBucketXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
	//添加打印日志
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);
    ListBucketData *lbData = (ListBucketData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "ListBucketResult/IsTruncated")) {
            string_buffer_append(lbData->isTruncated, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListBucketResult/NextMarker")) {
            string_buffer_append(lbData->nextMarker, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListBucketResult/Contents/Key")) {
            ListBucketContents *contents = 
                &(lbData->contents[lbData->contentsCount]);

#ifdef WIN32
		char* strTmpSource = (char*)malloc(sizeof(char) * (dataLen + 1));
		if (NULL == strTmpSource) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc strTmpSource failed!");
			return S3StatusInternalError;
		}
		memset_s(strTmpSource, dataLen + 1,  0, dataLen + 1);
		strncpy_s(strTmpSource, dataLen+1, data, dataLen);
		char* strTmpOut = UTF8_To_String(strTmpSource);
		string_buffer_append(contents->key, strTmpOut, strlen(strTmpOut), fit);
		CHECK_NULL_FREE(strTmpSource);
		CHECK_NULL_FREE(strTmpOut);
#else
		string_buffer_append(contents->key, data, dataLen, fit);
#endif
        }
        else if (!strcmp(elementPath, 
                         "ListBucketResult/Contents/LastModified")) {
            ListBucketContents *contents = 
                &(lbData->contents[lbData->contentsCount]);
            string_buffer_append(contents->lastModified, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListBucketResult/Contents/ETag")) {
            ListBucketContents *contents = 
                &(lbData->contents[lbData->contentsCount]);
            string_buffer_append(contents->eTag, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListBucketResult/Contents/Size")) {
            ListBucketContents *contents = 
                &(lbData->contents[lbData->contentsCount]);
            string_buffer_append(contents->size, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListBucketResult/Contents/Owner/ID")) {
            ListBucketContents *contents = 
                &(lbData->contents[lbData->contentsCount]);
            string_buffer_append(contents->ownerId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "ListBucketResult/Contents/Owner/DisplayName")) {
            ListBucketContents *contents = 
                &(lbData->contents[lbData->contentsCount]);
            string_buffer_append
                (contents->ownerDisplayName, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "ListBucketResult/CommonPrefixes/Prefix")) {
            int which = lbData->commonPrefixesCount;
            lbData->commonPrefixLens[which] +=
                snprintf_s(lbData->commonPrefixes[which], sizeof(lbData->commonPrefixes[which]), //secure function
                         sizeof(lbData->commonPrefixes[which]) -
                         lbData->commonPrefixLens[which] - 1,
                         "%.*s", dataLen, data);
            if (lbData->commonPrefixLens[which] >=
                (int) sizeof(lbData->commonPrefixes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
    }
    else {
        if (!strcmp(elementPath, "ListBucketResult/Contents")) {
            // Finished a Contents
            lbData->contentsCount++;
            if (lbData->contentsCount == MAX_CONTENTS) {
                // Make the callback
                S3Status status = make_list_bucket_callback(lbData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_list_bucket_data(lbData);
            }
            else {
                // Initialize the next one
                initialize_list_bucket_contents
                    (&(lbData->contents[lbData->contentsCount]));
            }
        }
        else if (!strcmp(elementPath,
                         "ListBucketResult/CommonPrefixes/Prefix")) {
            // Finished a Prefix
            lbData->commonPrefixesCount++;
            if (lbData->commonPrefixesCount == MAX_COMMON_PREFIXES) {
                // Make the callback
                S3Status status = make_list_bucket_callback(lbData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_list_bucket_data(lbData);
            }
            else {
                // Initialize the next one
                lbData->commonPrefixes[lbData->commonPrefixesCount][0] = 0;
                lbData->commonPrefixLens[lbData->commonPrefixesCount] = 0;
            }
        }
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status listBucketPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);
    ListBucketData *lbData = (ListBucketData *) callbackData;
    
    return (*(lbData->responsePropertiesCallback))
        (responseProperties, lbData->callbackData);
}


static S3Status listBucketDataCallback(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

	ListBucketData *lbData = (ListBucketData *) callbackData;
    
    return simplexml_add(&(lbData->simpleXml), buffer, bufferSize);
}


static void listBucketCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    ListBucketData *lbData = (ListBucketData *) callbackData;

	if (0 == lbData->contentsCount)
	{
		COMMLOG(OBS_LOGWARN, "listObjects contentsCount = %d !", lbData->contentsCount);
	}
    // Make the callback if there is anything
    if (lbData->contentsCount || lbData->commonPrefixesCount) {
		
		//Checke return value by jwx329074 2016.11.16
		S3Status callbackResult = make_list_bucket_callback(lbData);
		if (callbackResult != S3StatusOK)
		{
			COMMLOG(OBS_LOGERROR, "make_list_bucket_callback failed!");
		}
    }

    (*(lbData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, lbData->callbackData);

    simplexml_deinitialize(&(lbData->simpleXml));

    free(lbData);
	lbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void S3_list_bucket(const S3BucketContext *bucketContext, const char *prefix,
                    const char *marker, const char *delimiter, int maxkeys,
                    S3RequestContext *requestContext,
                    const S3ListBucketHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_list_bucket successfully !");
    // Compose the query params
    string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);
    
	int urlEncode_result = 0;// zwx367245 2010.10.10 防止宏定义函数中展开的过程中出现多个同名变量

#define safe_append(name, value)                                        \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (1 != fit) {                                             \
                (void)(*(handler->responseHandler.completeCallback))    \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (1 != fit) {                                                 \
            (void)(*(handler->responseHandler.completeCallback))        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
		urlEncode_result = urlEncode(encoded, value, 1024);             \
        if (1 != urlEncode_result) {                                    \
            (void)(*(handler->responseHandler.completeCallback))        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (1 != fit) {                                                 \
            (void)(*(handler->responseHandler.completeCallback))        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            return;                                                     \
        }                                                               \
    } while (0)


    int amp = 0;
	if (delimiter) {
		safe_append("delimiter", delimiter);
	}
    if (marker) {
		safe_append("marker", marker);
    }
    if (maxkeys) {
		if(maxkeys > 1000)maxkeys = 1000;
		char maxKeysString[64] = {0};
        snprintf_s(maxKeysString, sizeof(maxKeysString), _TRUNCATE,  "%d", maxkeys);  //secure function
        safe_append("max-keys", maxKeysString);
    }
    if (prefix) {
        safe_append("prefix", prefix);
    }

    ListBucketData *lbData = (ListBucketData *) malloc(sizeof(ListBucketData));

    if (!lbData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc ListBucketData failed !");
        return;
    }
	memset_s(lbData, sizeof(ListBucketData), 0, sizeof(ListBucketData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
        (void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(lbData);//lint !e516    
		lbData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
    simplexml_initialize(&(lbData->simpleXml), &listBucketXmlCallback, lbData);//lint !e119
    
    lbData->responsePropertiesCallback = 
        handler->responseHandler.propertiesCallback;
    lbData->listBucketCallback = handler->listBucketCallback;
    lbData->responseCompleteCallback = 
        handler->responseHandler.completeCallback;
    lbData->callbackData = callbackData;

    string_buffer_initialize(lbData->isTruncated);
    string_buffer_initialize(lbData->nextMarker);
    initialize_list_bucket_data(lbData);

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
        0,                                            // key
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
        &listBucketPropertiesCallback,                // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &listBucketDataCallback,                      // fromS3Callback
        &listBucketCompleteCallback,                  // completeCallback
        lbData,                                       // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };
    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_list_bucket successfully !");
}

void ListObjects(const S3BucketContext *bucketContext, const char *prefix,
                    const char *marker, const char *delimiter, int maxkeys,
                    S3RequestContext *requestContext,
                    const S3ListBucketHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter ListObjects successfully !");
	//Increase (void) ignore its return value by jwx329074 2016.10.13
	(void)S3_list_bucket(bucketContext,prefix,marker,delimiter,maxkeys,requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave ListObjects successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


// GetBucketQuota ----------------------------------------------------------------
//lint -e601
typedef struct GetBucketQuotaData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int storagequotaReturnSize;
    char *storagequotaReturn;

    string_buffer(storagequota, 256);
} GetBucketQuotaData;
//lint +e601

static S3Status GetBucketQuotaXmlCallback(const char *elementPath, const char *data, int dataLen, void *callbackData)/*lint !e31 */
{
    GetBucketQuotaData *gbqData = (GetBucketQuotaData *) callbackData;

    int fit;

    if (data && !strcmp(elementPath, "Quota/StorageQuota")) {
        string_buffer_append(gbqData->storagequota, data, dataLen, fit);
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status GetBucketQuotaPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketQuotaData *gbqData = (GetBucketQuotaData *) callbackData;
    
    return (*(gbqData->responsePropertiesCallback))
        (responseProperties, gbqData->callbackData);
}


static S3Status GetBucketQuotaDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    GetBucketQuotaData *gbqData = (GetBucketQuotaData *) callbackData;

    return simplexml_add(&(gbqData->simpleXml), buffer, bufferSize);
}

//lint -e101
static void GetBucketQuotaCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketQuotaData *gbqData = (GetBucketQuotaData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(gbqData->storagequotaReturn, sizeof(gbqData->storagequota), //secure funtion
             gbqData->storagequotaReturnSize, "%s", 
             gbqData->storagequota);

	//Increase (void) ignore its return value by jwx329074 2016.10.13
    (void)(*(gbqData->responseCompleteCallback))(requestStatus, s3ErrorDetails, gbqData->callbackData);

    simplexml_deinitialize(&(gbqData->simpleXml));

    free(gbqData);//lint !e516
	gbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void GetBucketQuota(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int storagequotaReturnSize,
                    char *storagequotaReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketQuota successfully !");
    // Create the callback data
    GetBucketQuotaData *gbqData = 
        (GetBucketQuotaData *) malloc(sizeof(GetBucketQuotaData));
    if (!gbqData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketQuotaData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");        

		return;
    }
	memset_s(gbqData, sizeof(GetBucketQuotaData), 0, sizeof(GetBucketQuotaData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(gbqData);//lint !e516   
		gbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(storagequotaReturnSize < 0){
		COMMLOG(OBS_LOGERROR, "storagequotaReturnSize is invalid!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		 //zwx367245 2016.09.30 storagequotaReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(gbqData);//lint !e516   
		gbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gbqData->simpleXml), &GetBucketQuotaXmlCallback, gbqData);//lint !e119

    gbqData->responsePropertiesCallback = handler->propertiesCallback;
    gbqData->responseCompleteCallback = handler->completeCallback;
    gbqData->callbackData = callbackData;

    gbqData->storagequotaReturnSize = storagequotaReturnSize;
    gbqData->storagequotaReturn = storagequotaReturn;
    string_buffer_initialize(gbqData->storagequota);

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          uriStyle,                                   // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "quota",                                      // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketQuotaPropertiesCallback,            // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketQuotaDataCallback,                  // fromS3Callback
        &GetBucketQuotaCompleteCallback,              // completeCallback
        gbqData,                                      // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketQuota successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


void GetBucketQuotaCA(const S3BucketContext *bucketContext,
                    int storagequotaReturnSize,
                    char *storagequotaReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter GetBucketQuotaCA successfully !");
    // Create the callback data
    GetBucketQuotaData *gbqData = 
        (GetBucketQuotaData *) malloc(sizeof(GetBucketQuotaData));
    if (!gbqData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketQuotaData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");            

		return;
    }
	memset_s(gbqData, sizeof(GetBucketQuotaData), 0, sizeof(GetBucketQuotaData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		 //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(gbqData);//lint !e516    
		gbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(storagequotaReturnSize < 0){
		COMMLOG(OBS_LOGERROR, "storagequotaReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 storagequotaReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(gbqData);//lint !e516   
		gbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gbqData->simpleXml), &GetBucketQuotaXmlCallback, gbqData);//lint !e119

    gbqData->responsePropertiesCallback = handler->propertiesCallback;
    gbqData->responseCompleteCallback = handler->completeCallback;
    gbqData->callbackData = callbackData;

    gbqData->storagequotaReturnSize = storagequotaReturnSize;
    gbqData->storagequotaReturn = storagequotaReturn;
    string_buffer_initialize(gbqData->storagequota);

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
        0,                                            // key
        0,                                            // queryParams
        "quota",                                      // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketQuotaPropertiesCallback,            // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketQuotaDataCallback,                  // fromS3Callback
        &GetBucketQuotaCompleteCallback,              // completeCallback
        gbqData,                                      // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketQuotaCA successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
    
}


// SetBucketQuota -------------------------------------------------------------
//lint -e601
typedef struct SetBucketQuotaData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024];
    int docLen, docBytesWritten;
} SetBucketQuotaData;                         
//lint +e601                            

static S3Status SetBucketQuotaPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    SetBucketQuotaData *sbqData = (SetBucketQuotaData *) callbackData;
    
    return (*(sbqData->responsePropertiesCallback))
        (responseProperties, sbqData->callbackData);
}


static int SetBucketQuotaDataCallback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    SetBucketQuotaData *sbqData = (SetBucketQuotaData *) callbackData;

    if (!sbqData->docLen) {
        return 0;
    }

    int remaining = (sbqData->docLen - sbqData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(sbqData->doc[sbqData->docBytesWritten]), toCopy); //secure function

    sbqData->docBytesWritten += toCopy;

    return toCopy;
}

//lint -e101
static void SetBucketQuotaCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketQuotaData *sbqData = (SetBucketQuotaData *) callbackData;

	//Increase (void) ignore its return value by jwx329074 2016.10.13
    (void)(*(sbqData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, sbqData->callbackData);

    free(sbqData);//lint !e516  
	sbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void SetBucketQuota(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName,
                      const char *storagequota,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketQuota successfully!");
	// Create the callback data
	SetBucketQuotaData *sbqData = 
		(SetBucketQuotaData *) malloc(sizeof(SetBucketQuotaData));
	if (!sbqData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketQuotaData falied!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    
    
		return;
	}
	memset_s(sbqData, sizeof(SetBucketQuotaData), 0, sizeof(SetBucketQuotaData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(sbqData);//lint !e516 
		sbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(NULL == storagequota){
		COMMLOG(OBS_LOGERROR, "storagequota is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");    
		free(sbqData);//lint !e516
		sbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

	sbqData->responsePropertiesCallback = handler->propertiesCallback;
	sbqData->responseCompleteCallback = handler->completeCallback;
	sbqData->callbackData = callbackData;
	char*pstoragequota = 0;
	//zwx367245 2016.10.08 前面已经对storagequota==NULL做了判断，下面的if else多余
	//if (storagequota) {
		int mark = pcre_replace(storagequota,&pstoragequota);
		sbqData->docLen =
			snprintf_s(sbqData->doc, sizeof(sbqData->doc),_TRUNCATE, //secure function
					"<Quota><StorageQuota>"
					"%s</StorageQuota></Quota>",
					mark ? pstoragequota : storagequota);
		sbqData->docBytesWritten = 0;
		if(mark)
		{
			free(pstoragequota);//lint !e516
			pstoragequota = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
	//}
	/*else {
		COMMLOG(OBS_LOGERROR, "Input param storagequota is NULL");
		sbqData->docLen = 0;
	}*/

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
		0,										 // startByte
		0,										 // byteCount
		0,                                       // expires
		S3CannedAclPrivate,                      // cannedAcl
		0,                                       // metaDataCount
		0,                                       // metaData
		0                                        // useServerSideEncryption
	};

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypePUT,                           // httpRequestType
		{ hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          S3UriStylePath,                             // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
		0,                                            // key
		0,                                            // queryParams
		"quota",                                      // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
        0,                                            // corsConf
		&properties,                                  // putProperties
		0,                                            // ServerSideEncryptionParams
		&SetBucketQuotaPropertiesCallback,            // propertiesCallback
		&SetBucketQuotaDataCallback,                  // toS3Callback
		sbqData->docLen,                              // toS3CallbackTotalSize
		0,                                            // fromS3Callback
		&SetBucketQuotaCompleteCallback,              // completeCallback
		sbqData,                                      // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, " Leave SetBucketQuota successfully!");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
    
}


void SetBucketQuotaCA(const S3BucketContext *bucketContext,
                      const char *storagequota,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketQuotaCA successfully!");
	// Create the callback data
	SetBucketQuotaData *sbqData = 
		(SetBucketQuotaData *) malloc(sizeof(SetBucketQuotaData));
	if (!sbqData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketQuotaData falied!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    

		return;
	}
	memset_s(sbqData, sizeof(SetBucketQuotaData), 0 , sizeof(SetBucketQuotaData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");    
		free(sbqData);//lint !e516
		sbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(NULL == storagequota){
		COMMLOG(OBS_LOGERROR, "storagequota is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 sizeReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(sbqData);//lint !e516
		sbqData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

	sbqData->responsePropertiesCallback = handler->propertiesCallback;
	sbqData->responseCompleteCallback = handler->completeCallback;
	sbqData->callbackData = callbackData;
	char*pstoragequota = 0;
	// zwx367245 2016.09.30 逻辑错误代码，上面已经判断如果storagequota==NULL则会退出，下面不需要再if(storagequota)
	//if (storagequota) {
		int mark = pcre_replace(storagequota,&pstoragequota);
		sbqData->docLen =
			snprintf_s(sbqData->doc, sizeof(sbqData->doc), _TRUNCATE,  //secure function
					"<Quota><StorageQuota>"
					"%s</StorageQuota></Quota>",
					mark ? pstoragequota : storagequota);
		sbqData->docBytesWritten = 0;
		if(mark)
		{
			free(pstoragequota);//lint !e516  
			pstoragequota = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
	//}
	//else {
	//	COMMLOG(OBS_LOGERROR, "Input param storagequota is NULL");
	//	sbqData->docLen = 0;
	//}

	// Set up S3PutProperties
	S3PutProperties properties =
	{
		0,                                       // contentType
		0,                                       // md5
		0,                                       // cacheControl
		0,                                       // contentDispositionFilename
		0,                                       // contentEncoding
		0,										 //storagepolicy
		0,										 //websiteredirectlocation
		0,										 //getConditions
		0,										 //startByte
		0,										 //byteCount
		0,                                       // expires
		S3CannedAclPrivate,                      // cannedAcl
		0,                                       // metaDataCount
		0,                                       // metaData
		0                                        // useServerSideEncryption
	};

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypePUT,                           // httpRequestType
		{ bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          S3UriStylePath,                    		  // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
		0,                                            // key
		0,                                            // queryParams
		"quota",                                      // subResource
		0,                                            // copySourceBucketName
		0,                                            // copySourceKey
		0,                                            // getConditions
		0,                                            // startByte
		0,                                            // byteCount
        0,                                            // corsConf
		&properties,                                  // putProperties
		0,                                            // ServerSideEncryptionParams
		&SetBucketQuotaPropertiesCallback,            // propertiesCallback
		&SetBucketQuotaDataCallback,                  // toS3Callback
		sbqData->docLen,                              // toS3CallbackTotalSize
		0,                                            // fromS3Callback
		&SetBucketQuotaCompleteCallback,              // completeCallback
		sbqData,                                      // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, " Leave SetBucketQuotaCA successfully!");

    SYSTEMTIME rspTime; 
    GetLocalTime(&rspTime);
    INTLOG(reqTime, rspTime, S3StatusOK, "");    

}


// GetBucketStorageInfo -------------------------------------------------------------------
//lint -e601
typedef struct GetBucketStorageInfoData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char *sizeReturn;
    int   sizeReturnSize;
    char *objectnumberReturn;
    int   objectnumberReturnSize;

    string_buffer(size, 256);
    string_buffer(objectnumber, 256);
} GetBucketStorageInfoData;
//lint +e601

static S3Status GetBucketStorageInfoXmlCallback(const char *elementPath, const char *data, int dataLen, void *callbackData)/*lint !e31 */
{
    GetBucketStorageInfoData *gbsiData = (GetBucketStorageInfoData *) callbackData;

    int fit;
    if (data)
    {
		if(!strcmp(elementPath, "GetBucketStorageInfoResult/Size")) {
	        string_buffer_append(gbsiData->size, data, dataLen, fit);
	    }
		else if(!strcmp(elementPath, "GetBucketStorageInfoResult/ObjectNumber")){
			string_buffer_append(gbsiData->objectnumber, data, dataLen, fit);
		}
	}

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status GetBucketStorageInfoPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketStorageInfoData *gbsiData = (GetBucketStorageInfoData *) callbackData;
    
    return (*(gbsiData->responsePropertiesCallback))
        (responseProperties, gbsiData->callbackData);
}


static S3Status GetBucketStorageInfoDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{

	GetBucketStorageInfoData *gbsiData = (GetBucketStorageInfoData *) callbackData;
    return simplexml_add(&(gbsiData->simpleXml), buffer, bufferSize);
}

//lint -e101
static void GetBucketStorageInfoCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketStorageInfoData *gbsiData = (GetBucketStorageInfoData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(gbsiData->sizeReturn, sizeof(gbsiData->size),  //secure function
             gbsiData->sizeReturnSize, "%s", 
             gbsiData->size);
    snprintf_s(gbsiData->objectnumberReturn, sizeof(gbsiData->objectnumber),   //secure function
             gbsiData->objectnumberReturnSize, "%s", 
             gbsiData->objectnumber);

	//Increase (void) ignore its return value by jwx329074 2016.10.13
    (void)(*(gbsiData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gbsiData->callbackData);

    simplexml_deinitialize(&(gbsiData->simpleXml));

    free(gbsiData);//lint !e516
	gbsiData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void GetBucketStorageInfo(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int sizeReturnSize,
                    char *sizeReturn,
                    int objectnumberReturnSize,
                    char *objectnumberReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketStorageInfo successfully !");
    // Create the callback data
    GetBucketStorageInfoData *gbsiData = 
        (GetBucketStorageInfoData *) malloc(sizeof(GetBucketStorageInfoData));
    if (!gbsiData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketStorageInfoData failed!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    

		return;
    }
	memset_s(gbsiData, sizeof(GetBucketStorageInfoData), 0, sizeof(GetBucketStorageInfoData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 sizeReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(gbsiData);//lint !e516
		gbsiData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(sizeReturnSize < 0 || objectnumberReturnSize < 0){
		COMMLOG(OBS_LOGERROR, "sizeReturnSize or objectnumberReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 sizeReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(gbsiData);//lint !e516
		gbsiData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gbsiData->simpleXml), &GetBucketStorageInfoXmlCallback, gbsiData);//lint !e119

    gbsiData->responsePropertiesCallback = handler->propertiesCallback;
    gbsiData->responseCompleteCallback = handler->completeCallback;
    gbsiData->callbackData = callbackData;

    gbsiData->sizeReturn = sizeReturn;
	gbsiData->sizeReturnSize =sizeReturnSize;
    gbsiData->objectnumberReturn= objectnumberReturn;
	gbsiData->objectnumberReturnSize =objectnumberReturnSize;
 
	string_buffer_initialize(gbsiData->size);
	string_buffer_initialize(gbsiData->objectnumber);
 
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          uriStyle,                                   // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "storageinfo",                                // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketStorageInfoPropertiesCallback,      // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketStorageInfoDataCallback,            // fromS3Callback
        &GetBucketStorageInfoCompleteCallback,        // completeCallback
        gbsiData,                                     // callbackData
		0											  // isCheckCA
    };

    // Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketStorageInfo successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
    
}


void GetBucketStorageInfoCA(const S3BucketContext *bucketContext,
                    int sizeReturnSize,
                    char *sizeReturn,
                    int objectnumberReturnSize,
                    char *objectnumberReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketStorageInfoCA successfully !");
	// Create the callback data
	GetBucketStorageInfoData *gbsiData = (GetBucketStorageInfoData *) malloc(sizeof(GetBucketStorageInfoData));
	if (!gbsiData) {
		//Increase (void) ignore its return value by jwx329074 2016.10.13
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketStorageInfoData failed!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    
    
		return;
	}
	memset_s(gbsiData, sizeof(GetBucketStorageInfoData), 0, sizeof(GetBucketStorageInfoData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(gbsiData);//lint !e516  
		gbsiData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(sizeReturnSize < 0 || objectnumberReturnSize < 0){
		COMMLOG(OBS_LOGERROR, "sizeReturnSize or objectnumberReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");    
		free(gbsiData);//lint !e516
		gbsiData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gbsiData->simpleXml), &GetBucketStorageInfoXmlCallback, gbsiData);//lint !e119

    gbsiData->responsePropertiesCallback = handler->propertiesCallback;
    gbsiData->responseCompleteCallback = handler->completeCallback;
    gbsiData->callbackData = callbackData;

    gbsiData->sizeReturn = sizeReturn;
	gbsiData->sizeReturnSize =sizeReturnSize;
    gbsiData->objectnumberReturn= objectnumberReturn;
	gbsiData->objectnumberReturnSize =objectnumberReturnSize;
 
	string_buffer_initialize(gbsiData->size);
	string_buffer_initialize(gbsiData->objectnumber);
 
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
        0,                                            // key
        0,                                            // queryParams
        "storageinfo",                                // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketStorageInfoPropertiesCallback,      // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketStorageInfoDataCallback,            // fromS3Callback
        &GetBucketStorageInfoCompleteCallback,        // completeCallback
        gbsiData,                                     // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketStorageInfoCA successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
}


// ListMultipartUploads ----------------------------------------------------------------

typedef struct ListMultipartUpload
{
    string_buffer(key, 1024);
    string_buffer(uploadId, 256);
    string_buffer(initiatorId, 256);
    string_buffer(initiatorDisplayName, 256);
    string_buffer(ownerId, 256);
    string_buffer(ownerDisplayName, 256);
    string_buffer(storageClass, 256);
    string_buffer(initiated, 256);
} ListMultipartUpload;


static void initialize_list_multipart_uploads(ListMultipartUpload *uploads)
{
    string_buffer_initialize(uploads->key);
    string_buffer_initialize(uploads->uploadId);
    string_buffer_initialize(uploads->initiatorId);
    string_buffer_initialize(uploads->initiatorDisplayName);
    string_buffer_initialize(uploads->ownerId);
    string_buffer_initialize(uploads->ownerDisplayName);
    string_buffer_initialize(uploads->storageClass);
    string_buffer_initialize(uploads->initiated);
}

// We read up to 32 Contents at a time
#define MAX_UPLOADS 32

//lint -e601
typedef struct ListMultipartUploadsData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ListMultipartUploadsCallback *listMultipartUploadsCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    string_buffer(isTruncated, 64);
    string_buffer(nextMarker, 1024);
    string_buffer(nextUploadIdMarker, 1024);

    int uploadsCount;
    ListMultipartUpload uploads[MAX_UPLOADS];

	int commonPrefixesCount;
	char commonPrefixes[MAX_COMMON_PREFIXES][1024];
	int commonPrefixLens[MAX_COMMON_PREFIXES];
} ListMultipartUploadsData;
//lint +e601

static void initialize_list_multipart_uploads_data(ListMultipartUploadsData *lmuData)
{
    lmuData->uploadsCount= 0;
    initialize_list_multipart_uploads(lmuData->uploads);

}


static S3Status make_list_multipart_uploads_callback(ListMultipartUploadsData *lmuData)/*lint !e31 */
{

	S3Status iRet = S3StatusOK;

    // Convert IsTruncated
    int isTruncated = (!strcmp(lmuData->isTruncated, "true") ||
                       !strcmp(lmuData->isTruncated, "1")) ? 1 : 0;

    // Convert the contents
    //S3ListMultipartUpload uploads[lmuData->uploadsCount];
	if(lmuData->uploadsCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusInternalError;
	}
	S3ListMultipartUpload *uploads = (S3ListMultipartUpload*)malloc(sizeof(S3ListMultipartUpload) * lmuData->uploadsCount);
	if (NULL == uploads) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3ListMultipartUpload failed!");
		return S3StatusInternalError;
	}
	memset_s(uploads, sizeof(S3ListMultipartUpload) * lmuData->uploadsCount, 0, sizeof(S3ListMultipartUpload) * lmuData->uploadsCount);  //secure function

    int uploadsCount = lmuData->uploadsCount;
	int i;
    for (i = 0; i < uploadsCount; i++) {
        S3ListMultipartUpload *uploadDest = &(uploads[i]);
        ListMultipartUpload *uploadSrc = &(lmuData->uploads[i]);
        uploadDest->key = uploadSrc->key;
        uploadDest->uploadId = uploadSrc->uploadId;
        uploadDest->ownerId =
            uploadSrc->ownerId[0] ?uploadSrc->ownerId : 0;
        uploadDest->ownerDisplayName = (uploadSrc->ownerDisplayName[0] ?
                                         uploadSrc->ownerDisplayName : 0);
        uploadDest->initiatorId =
            uploadSrc->initiatorId[0] ?uploadSrc->initiatorId : 0;
        uploadDest->initiatorDisplayName = (uploadSrc->initiatorDisplayName[0] ?
                                         uploadSrc->initiatorDisplayName : 0);
        uploadDest->storageClass = uploadSrc->storageClass;
        uploadDest->initiated = parseIso8601Time(uploadSrc->initiated);
	int nTimeZone = getTimeZone();
	uploadDest->initiated += nTimeZone * SECONDS_TO_AN_HOUR;
    }

    // Make the common prefixes array
    int commonPrefixesCount = lmuData->commonPrefixesCount;
	if(commonPrefixesCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		CHECK_NULL_FREE(uploads);       //zwx367245 2016.10.08 参数错误return之前先释放已申请的内存
		return S3StatusInternalError;
	}
	char **commonPrefixes = (char**)malloc(sizeof(char *) * commonPrefixesCount);
	if (NULL == commonPrefixes) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc commonPrefixes failed!");
		CHECK_NULL_FREE(uploads);
		return S3StatusInternalError;
	}

	memset_s(commonPrefixes, sizeof(char *) * commonPrefixesCount, 0, sizeof(char *) * commonPrefixesCount);

    for (i = 0; i < commonPrefixesCount; i++) {
        commonPrefixes[i] = lmuData->commonPrefixes[i];
    }

	iRet = (*(lmuData->listMultipartUploadsCallback))
		(isTruncated, lmuData->nextMarker,lmuData->nextUploadIdMarker,
		uploadsCount, uploads, commonPrefixesCount, (const char **)commonPrefixes, lmuData->callbackData);

	CHECK_NULL_FREE(uploads);
	CHECK_NULL_FREE(commonPrefixes);


	return iRet;
}


static S3Status listMultipartUploadsXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    ListMultipartUploadsData *lmuData = (ListMultipartUploadsData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "ListMultipartUploadsResult/IsTruncated")) {
            string_buffer_append(lmuData->isTruncated, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/NextKeyMarker")) {
            string_buffer_append(lmuData->nextMarker, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/NextUploadIdMarker")) {
            string_buffer_append(lmuData->nextUploadIdMarker, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload/Key")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
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
		string_buffer_append(uploads->key, strTmpOut, strlen(strTmpOut), fit);
		CHECK_NULL_FREE(strTmpSource);
		CHECK_NULL_FREE(strTmpOut);
#else
            string_buffer_append(uploads->key, data, dataLen, fit);
#endif
        }
        else if (!strcmp(elementPath, 
                         "ListMultipartUploadsResult/Upload/UploadId")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append(uploads->uploadId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload/Initiator/ID")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append(uploads->initiatorId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload/Initiator/DisplayName")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append(uploads->initiatorDisplayName, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload/StorageClass")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append(uploads->storageClass, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload/Initiated")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append(uploads->initiated, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload/Owner/ID")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append(uploads->ownerId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "ListMultipartUploadsResult/Upload/Owner/DisplayName")) {
            ListMultipartUpload*uploads = 
                &(lmuData->uploads[lmuData->uploadsCount]);
            string_buffer_append
                (uploads->ownerDisplayName, data, dataLen, fit);
        }
		else if (!strcmp(elementPath, 
                         "ListMultipartUploadsResult/CommonPrefixes/Prefix")) {
            int which = lmuData->commonPrefixesCount;
            lmuData->commonPrefixLens[which] +=
                snprintf_s(lmuData->commonPrefixes[which], sizeof(lmuData->commonPrefixes[which]),   //secure function
                         sizeof(lmuData->commonPrefixes[which]) -
                         lmuData->commonPrefixLens[which] - 1,
                         "%.*s", dataLen, data);
            if (lmuData->commonPrefixLens[which] >=
                (int) sizeof(lmuData->commonPrefixes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
    }
    else {
        if (!strcmp(elementPath, "ListMultipartUploadsResult/Upload")) {
            // Finished a Contents
            lmuData->uploadsCount++;
            if (lmuData->uploadsCount == MAX_UPLOADS) {
                // Make the callback
                S3Status status = make_list_multipart_uploads_callback(lmuData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_list_multipart_uploads_data(lmuData);
            }
            else {
                // Initialize the next one
                initialize_list_multipart_uploads
                    (&(lmuData->uploads[lmuData->uploadsCount]));
            }
        }
		else if (!strcmp(elementPath,
                         "ListMultipartUploadsResult/CommonPrefixes/Prefix")) {
            // Finished a Prefix
            lmuData->commonPrefixesCount++;
            if (lmuData->commonPrefixesCount == MAX_COMMON_PREFIXES) {
                // Make the callback
                S3Status status = make_list_multipart_uploads_callback(lmuData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_list_multipart_uploads_data(lmuData);
            }
            else {
                // Initialize the next one
                lmuData->commonPrefixes[lmuData->commonPrefixesCount][0] = 0;
                lmuData->commonPrefixLens[lmuData->commonPrefixesCount] = 0;
            }
        }
		

    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status listMultipartUploadsPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    ListMultipartUploadsData*lmuData = (ListMultipartUploadsData *) callbackData;
    
    return (*(lmuData->responsePropertiesCallback))
        (responseProperties, lmuData->callbackData);
}


static S3Status listMultipartUploadsDataCallback(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    ListMultipartUploadsData *lmuData = (ListMultipartUploadsData *) callbackData;
    
    return simplexml_add(&(lmuData->simpleXml), buffer, bufferSize);
}


static void listMultipartUploadsCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    ListMultipartUploadsData *lmuData = (ListMultipartUploadsData *) callbackData;

    // Make the callback if there is anything
    if (lmuData->uploadsCount || lmuData->commonPrefixesCount) {

		//Cheack return value by jwx329074 2016.11.16
        S3Status callbackResult = make_list_multipart_uploads_callback(lmuData);
		if (callbackResult != S3StatusOK)
		{
			COMMLOG(OBS_LOGERROR, "make_list_multipart_uploads_callback failed!");
		}
    }

    (*(lmuData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, lmuData->callbackData);

    simplexml_deinitialize(&(lmuData->simpleXml));

    free(lmuData);
	lmuData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void ListMultipartUploads(const S3BucketContext *bucketContext, const char *prefix,
                    const char *marker, const char *delimiter,const char* uploadidmarke, int maxuploads,
                    S3RequestContext *requestContext,
                    const S3ListMultipartUploadsHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter ListMultipartUploads successfully !");
    // Compose the query params
    string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);

#define safe_appendm(name, value)                                       \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->responseHandler.completeCallback))    \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                SYSTEMTIME rspTime;                                     \
                GetLocalTime(&rspTime);                                 \
                INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong,"");\
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->responseHandler.completeCallback))        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                   \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->responseHandler.completeCallback))        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
             return;                                                    \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->responseHandler.completeCallback))        \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            SYSTEMTIME rspTime;                                         \
            GetLocalTime(&rspTime);                                     \
            INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
            return;                                                     \
        }                                                               \
    } while (0)


    int amp = 0;
	if (delimiter) {
		safe_appendm("delimiter", delimiter);
	}
    if (marker) {
        safe_appendm("key-marker", marker);
    }
    if (maxuploads) {
		if(maxuploads > 1000)maxuploads = 1000;
		char maxUploadsString[64] = {0};
        snprintf_s(maxUploadsString, sizeof(maxUploadsString), _TRUNCATE, "%d", maxuploads);   //secure function
        safe_appendm("max-uploads", maxUploadsString);
    }
    if (prefix) {
        safe_appendm("prefix", prefix);
    }
    if (uploadidmarke) {
        safe_appendm("upload-id-marke", uploadidmarke);
    }

    ListMultipartUploadsData *lmuData =
        (ListMultipartUploadsData *) malloc(sizeof(ListMultipartUploadsData));

    if (!lmuData) {
        (void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc ListMultipartUploadsData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");   
    
        return;
    }
	memset_s(lmuData, sizeof(ListMultipartUploadsData), 0, sizeof(ListMultipartUploadsData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");    
		free(lmuData);//lint !e516
		lmuData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(lmuData->simpleXml), &listMultipartUploadsXmlCallback, lmuData);//lint !e119
    
    lmuData->responsePropertiesCallback = 
        handler->responseHandler.propertiesCallback;
    lmuData->listMultipartUploadsCallback= handler->listMultipartUploadsCallback;
    lmuData->responseCompleteCallback = 
        handler->responseHandler.completeCallback;
    lmuData->callbackData = callbackData;

    string_buffer_initialize(lmuData->isTruncated);
    string_buffer_initialize(lmuData->nextMarker);
    string_buffer_initialize(lmuData->nextUploadIdMarker);
    initialize_list_multipart_uploads_data(lmuData);

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
        0,                                            // key
        queryParams[0] ? queryParams : 0,             // queryParams
        "uploads",                                    // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &listMultipartUploadsPropertiesCallback,      // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &listMultipartUploadsDataCallback,            // fromS3Callback
        &listMultipartUploadsCompleteCallback,        // completeCallback
        lmuData,                                      // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave ListMultipartUploadsData successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
    
}

// delete bucket policy -------------------------------------------------------------
//lint -e601
typedef struct DeleteBucketPolicyData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
} DeleteBucketPolicyData;
//lint +e601

static S3Status deleteBucketPolicyPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    DeleteBucketPolicyData *dbpData = (DeleteBucketPolicyData *) callbackData;
    
    return (*(dbpData->responsePropertiesCallback))
        (responseProperties, dbpData->callbackData);
}


static void deleteBucketPolicyCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteBucketPolicyData *dbpData = (DeleteBucketPolicyData *) callbackData;

    (*(dbpData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, dbpData->callbackData);

    free(dbpData);
	dbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void DeleteBucketPolicy(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
    // Create the callback data
    DeleteBucketPolicyData *dbpData = 
        (DeleteBucketPolicyData *) malloc(sizeof(DeleteBucketPolicyData));
    if (!dbpData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
        return;
    }
	memset_s(dbpData, sizeof(DeleteBucketPolicyData), 0, sizeof(DeleteBucketPolicyData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(dbpData);//lint !e516
		dbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    dbpData->responsePropertiesCallback = handler->propertiesCallback;
    dbpData->responseCompleteCallback = handler->completeCallback;
    dbpData->callbackData = callbackData;

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,                        // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          uriStyle,                                   // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "policy",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
		0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &deleteBucketPolicyPropertiesCallback,        // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &deleteBucketPolicyCompleteCallback,          // completeCallback
        dbpData,                                      // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


void DeleteBucketPolicyCA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
    // Create the callback data
    DeleteBucketPolicyData *dbpData = 
        (DeleteBucketPolicyData *) malloc(sizeof(DeleteBucketPolicyData));
    if (!dbpData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

        return;
    }
	memset_s(dbpData, sizeof(DeleteBucketPolicyData), 0, sizeof(DeleteBucketPolicyData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(dbpData);//lint !e516  
		dbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    dbpData->responsePropertiesCallback = handler->propertiesCallback;
    dbpData->responseCompleteCallback = handler->completeCallback;
    dbpData->callbackData = callbackData;

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
        0,                                            // key
        0,                                            // queryParams
        "policy",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
		0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &deleteBucketPolicyPropertiesCallback,        // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &deleteBucketPolicyCompleteCallback,          // completeCallback
        dbpData,                                      // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// Set Bucket Lifecycle Configuration -------------------------------------------------------------
//lint -e601
typedef struct SetBucketLifecycleConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024*100];
    int docLen, docBytesWritten;
} SetBucketLifecycleConfigurationData;                         
//lint +e601                            

static S3Status SetBucketLifecycleConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    SetBucketLifecycleConfigurationData *sblcData = (SetBucketLifecycleConfigurationData *) callbackData;
    
    return (*(sblcData->responsePropertiesCallback))
        (responseProperties, sblcData->callbackData);
}


static int SetBucketLifecycleConfigurationDataCallback(int bufferSize, char *buffer, void *callbackData)
{
    SetBucketLifecycleConfigurationData *sblcData = (SetBucketLifecycleConfigurationData *) callbackData;

    if (!sblcData->docLen) {
        return 0;
    }

    int remaining = (sblcData->docLen - sblcData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(sblcData->doc[sblcData->docBytesWritten]), toCopy); //secure function

    sblcData->docBytesWritten += toCopy;

    return toCopy;
}

//lint -e101
static void SetBucketLifecycleConfigurationCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketLifecycleConfigurationData *sblcData = (SetBucketLifecycleConfigurationData *) callbackData;

    (void)(*(sblcData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, sblcData->callbackData);

    free(sblcData);//lint !e516
	sblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void SetBucketLifecycleConfiguration(const S3BucketContext *bucketContext,const char *id,
                      const char *prefix, const char *status,
                      const char *days,const char *date,const S3PutProperties *putProperties,S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
	COMMLOG(OBS_LOGINFO, "Enter SetBucketLifecycleConfiguration successfully !");
    SetBucketLifecycleConfigurationData *sblcData = 
        (SetBucketLifecycleConfigurationData *) malloc(sizeof(SetBucketLifecycleConfigurationData));
    if (!sblcData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketLifecycleConfigurationData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    
    
        return;
    }
	memset_s(sblcData, sizeof(SetBucketLifecycleConfigurationData), 0, sizeof(SetBucketLifecycleConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(sblcData);//lint !e516
		sblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(NULL == prefix || NULL == status || (NULL == days && NULL == date)){
		COMMLOG(OBS_LOGERROR, "prefix or status or days or date is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");    
		free(sblcData);//lint !e516
		sblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    sblcData->responsePropertiesCallback = handler->propertiesCallback;
    sblcData->responseCompleteCallback = handler->completeCallback;
    sblcData->callbackData = callbackData;

	sblcData->docLen = snprintf_s(sblcData->doc, sizeof(sblcData->doc), _TRUNCATE,     //secure function
                     "<LifecycleConfiguration><Rule>");
	if (sblcData->docLen < 0)// cheack array index by jwx329074 2016.11.17
	{
		COMMLOG(OBS_LOGERROR, "snprintf_s is error!");   
		free(sblcData);//lint !e516
		sblcData = NULL;
		return;
	}
	int tmplen = 0;
	int mark = 0;
    if (id) {
		char*  pid = 0;
		mark = pcre_replace(id,&pid);
        tmplen =
            snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen,_TRUNCATE,     //secure function
                     "<ID>%s</ID>",mark ? pid : id);
		sblcData->docLen += tmplen;
		if(mark)
		{
			free(pid);//lint !e516
			pid = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
    if (prefix) {
		char * pprefix = 0;
		mark = pcre_replace(prefix,&pprefix);

		//cheack array index by jwx329074 2016.11.16
		if (sblcData->docLen < 0)
		{
			COMMLOG(OBS_LOGERROR, "Negative array index read!");
			free(sblcData);//lint !e516
			free(pprefix);//lint !e516
			pprefix = NULL;
			sblcData = NULL;

			return;
		}
        tmplen =
            snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,     //secure function
                     "<Prefix>%s</Prefix>",mark ? pprefix : prefix);
		sblcData->docLen += tmplen;
		if(mark)
		{
			free(pprefix);//lint !e516
			pprefix = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
    if (status) {
		char* pstatus = 0;
		mark = pcre_replace(status,&pstatus);
        tmplen =
            snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,     //secure function
                     "<Status>%s</Status>",mark ? pstatus : status);
		sblcData->docLen += tmplen;
		if(mark)
		{
			free(pstatus);//lint !e516
			pstatus = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
	//zwx367245 2016.10.08 前面已经判断过如果days和date同是为NULL，则退出，下面的代码为逻辑代码
	/*if (NULL == days && NULL == date)
	{
		(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

              SYSTEMTIME rspTime; 
              GetLocalTime(&rspTime);
	       INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");    

              return;		
	}*/	
	tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen,  _TRUNCATE, "<Expiration>");  //secure function
	sblcData->docLen += tmplen;
    if (days) {
		char * pdays = 0;
		mark = pcre_replace(days,&pdays);
        tmplen =
            snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,     //secure function
                     "<Days>%s</Days>",mark ? pdays : days);
		sblcData->docLen += tmplen;
		if(mark)
		{
			free(pdays);//lint !e516
			pdays = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
	if(date)
	{
		char date_Iso8601[50] = {0};
		changeTimeFormat(date, date_Iso8601);
		char* pdate = 0;
		mark = pcre_replace(date_Iso8601,&pdate);
        tmplen =
            snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,     //secure function
                     "<Date>%s</Date>",mark ? pdate : date_Iso8601);
		sblcData->docLen += tmplen;
		if(mark)
		{
			free(pdate);//lint !e516
			pdate = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
	}	
	tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE, "</Expiration></Rule></LifecycleConfiguration>");  //secure function
	sblcData->docLen += tmplen;
    
	sblcData->docBytesWritten = 0;
    
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,										// httpRequestType
        { bucketContext->hostName,								// hostName
          bucketContext->bucketName,							// bucketName
          bucketContext->protocol,								// protocol
          bucketContext->uriStyle,								// uriStyle
          bucketContext->accessKeyId,							// accessKeyId
          bucketContext->secretAccessKey,						// secretAccessKey
          bucketContext->certificateInfo },						// certificateInfo
        0,														// key
        0,														// queryParams
        "lifecycle",											// subResource
        0,														// copySourceBucketName
        0,														// copySourceKey
        0,														// getConditions
        0,														// startByte
        0,														// byteCount
		0,														// corsConf
        putProperties,											// putProperties
		0,                                                      // ServerSideEncryptionParams
        &SetBucketLifecycleConfigurationPropertiesCallback,     // propertiesCallback
        &SetBucketLifecycleConfigurationDataCallback,           // toS3Callback
        sblcData->docLen,										// toS3CallbackTotalSize
        0,														// fromS3Callback
        &SetBucketLifecycleConfigurationCompleteCallback,       // completeCallback
        sblcData,												// callbackData
		bucketContext->certificateInfo ? 1 : 0					// isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketLifecycleConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
}

void SetBucketLifecycleConfigurationEx(const S3BucketContext *bucketContext, 
			S3BucketLifeCycleConf* bucketLifeCycleConf, unsigned int blccNumber, const S3PutProperties *putProperties,
			S3RequestContext *requestContext, const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketLifecycleConfiguration successfully !"); 
    SetBucketLifecycleConfigurationData *sblcData = 
        (SetBucketLifecycleConfigurationData *) malloc(sizeof(SetBucketLifecycleConfigurationData));
    if (!sblcData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketLifecycleConfigurationData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");    
    
        return;
    }
	memset_s(sblcData, sizeof(SetBucketLifecycleConfigurationData), 0, sizeof(SetBucketLifecycleConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");    
		free(sblcData);//lint !e516
		sblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(NULL == bucketLifeCycleConf){
		COMMLOG(OBS_LOGERROR, "bucketLifeCycleConf is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");    
        free(sblcData);//lint !e516
		sblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
        return;
	}

    sblcData->responsePropertiesCallback = handler->propertiesCallback;
    sblcData->responseCompleteCallback = handler->completeCallback;
    sblcData->callbackData = callbackData;

	sblcData->docLen = snprintf_s(sblcData->doc, sizeof(sblcData->doc), _TRUNCATE,   //secure function
                     "<LifecycleConfiguration>");
	if (sblcData->docLen < 0)// cheack array index by jwx329074 2016.11.17
	{
		COMMLOG(OBS_LOGERROR, "snprintf_s is error!");   
		free(sblcData);//lint !e516
		sblcData = NULL;
		return;
	}
	unsigned int i = 0;
	int tmplen = 0;
	int mark = 0;
	//lint -e574
	for (i = 0; i < blccNumber; ++i)
	{
		tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE, "<Rule>"); //secure function
		sblcData->docLen += tmplen;
		//lint -e409	
		if (bucketLifeCycleConf[i].id)
		{
			char*  pid = 0;
			mark = pcre_replace(bucketLifeCycleConf[i].id, &pid);
			tmplen =
			snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE, "<ID>%s</ID>", mark ? pid : bucketLifeCycleConf[i].id);
			sblcData->docLen += tmplen;
			if(mark)
			{
				free(pid);//lint !e516
				pid = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		if (bucketLifeCycleConf[i].prefix)
		{
			char * pprefix = 0;
			mark = pcre_replace(bucketLifeCycleConf[i].prefix, &pprefix);
			tmplen =
			snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE, "<Prefix>%s</Prefix>",mark ? pprefix : bucketLifeCycleConf[i].prefix);
			sblcData->docLen += tmplen;
			if(mark)
			{
				free(pprefix);//lint !e516
				pprefix = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		if (bucketLifeCycleConf[i].status)
		{
			char* pstatus = 0;
			mark = pcre_replace(bucketLifeCycleConf[i].status,&pstatus);
			tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE, "<Status>%s</Status>",mark ? pstatus : bucketLifeCycleConf[i].status);
			sblcData->docLen += tmplen;
			if(mark)
			{
				free(pstatus);//lint !e516
				pstatus = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}

		if (NULL == bucketLifeCycleConf[i].days && NULL == bucketLifeCycleConf[i].date)//lint !e409
		{
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
			//zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			free(sblcData);//lint !e516
			sblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;		
		}
		
		tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE, "<Expiration>"); //secure function
		sblcData->docLen += tmplen;
		if (bucketLifeCycleConf[i].days) {
			char * pdays = 0;
			mark = pcre_replace(bucketLifeCycleConf[i].days,&pdays);
			tmplen =
			snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,  //secure function
			     "<Days>%s</Days>",mark ? pdays : bucketLifeCycleConf[i].days);
			sblcData->docLen += tmplen;
			if(mark)
			{
				free(pdays);//lint !e516 
				pdays = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		if(bucketLifeCycleConf[i].date)
		{
			char date_Iso8601[50] = {0};
			changeTimeFormat(bucketLifeCycleConf[i].date, date_Iso8601);
			char* pdate = 0;
			mark = pcre_replace(date_Iso8601,&pdate);
			tmplen =
			snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,  //secure function
			     "<Date>%s</Date>",mark ? pdate : date_Iso8601);
			sblcData->docLen += tmplen;
			if(mark)
			{
				free(pdate);//lint !e516 
				pdate = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}		
		tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,  //secure function
                     "</Expiration></Rule>");
		sblcData->docLen += tmplen;

	}//lint +e574


	//cheack array index by jwx329074 2016.11.16
	if (sblcData->docLen < 0)
	{
		COMMLOG(OBS_LOGERROR, "Negative array index read!");
		free(sblcData);
		sblcData = NULL;
		return;
	}
	tmplen = snprintf_s(sblcData->doc + sblcData->docLen, sizeof(sblcData->doc) - sblcData->docLen, _TRUNCATE,  //secure function
                     "</LifecycleConfiguration>");
       sblcData->docLen += tmplen;

    
	sblcData->docBytesWritten = 0;
    
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,										// httpRequestType
        { bucketContext->hostName,								// hostName
          bucketContext->bucketName,							// bucketName
          bucketContext->protocol,								// protocol
          bucketContext->uriStyle,								// uriStyle
          bucketContext->accessKeyId,							// accessKeyId
          bucketContext->secretAccessKey,						// secretAccessKey
          bucketContext->certificateInfo },						// certificateInfo
        0,														// key
        0,														// queryParams
        "lifecycle",											// subResource
        0,														// copySourceBucketName
        0,														// copySourceKey
        0,														// getConditions
        0,														// startByte
        0,														// byteCount
		0,														// corsConf
        putProperties,											// putProperties
		0,                                                      // ServerSideEncryptionParams
        &SetBucketLifecycleConfigurationPropertiesCallback,     // propertiesCallback
        &SetBucketLifecycleConfigurationDataCallback,           // toS3Callback
        sblcData->docLen,										// toS3CallbackTotalSize
        0,														// fromS3Callback
        &SetBucketLifecycleConfigurationCompleteCallback,       // completeCallback
        sblcData,												// callbackData
		bucketContext->certificateInfo ? 1 : 0					// isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketLifecycleConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");    
}//lint +e409

// GetBucketLifecycleConfiguration -------------------------------------------------------------------
//lint -e601
typedef struct GetBucketLifecycleConfigurationData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char *dateReturn;
    int   dateReturnSize;
    char *daysReturn;
    int   daysReturnSize;
    char *idReturn;
    int   idReturnSize;
    char *prefixReturn;
    int   prefixReturnSize;
    char *statusReturn;
    int   statusReturnSize;

    string_buffer(date, 256);
    string_buffer(days, 256);
    string_buffer(id, 256);
    string_buffer(prefix, 256);
    string_buffer(status, 256);
} GetBucketLifecycleConfigurationData;
//lint +e601

static S3Status GetBucketLifecycleConfigurationXmlCallback(const char *elementPath, const char *data, int dataLen, void *callbackData)/*lint !e31 */
{
    GetBucketLifecycleConfigurationData *gblcData = (GetBucketLifecycleConfigurationData *) callbackData;

    int fit;
    if (data)
    {
		if(!strcmp(elementPath, "LifecycleConfiguration/Rule/ID")) {
	        string_buffer_append(gblcData->id, data, dataLen, fit);
	    }
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Prefix")){
			string_buffer_append(gblcData->prefix, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Status")){
			string_buffer_append(gblcData->status, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Expiration/Date")){
			string_buffer_append(gblcData->date, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Expiration/Days")){
			string_buffer_append(gblcData->days, data, dataLen, fit);
		}
	}

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status GetBucketLifecycleConfigurationPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketLifecycleConfigurationData *gblcData = (GetBucketLifecycleConfigurationData *) callbackData;
    
    return (*(gblcData->responsePropertiesCallback))
        (responseProperties, gblcData->callbackData);
}


static S3Status GetBucketLifecycleConfigurationDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    GetBucketLifecycleConfigurationData *gblcData = (GetBucketLifecycleConfigurationData *) callbackData;

    return simplexml_add(&(gblcData->simpleXml), buffer, bufferSize);
}

//lint -e101
static void GetBucketLifecycleConfigurationCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketLifecycleConfigurationData *gblcData = (GetBucketLifecycleConfigurationData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(gblcData->dateReturn, sizeof(gblcData->date),   //secure function
             gblcData->dateLen + 1, "%s", 
             gblcData->date);
    snprintf_s(gblcData->daysReturn, sizeof(gblcData->days),
             gblcData->daysLen + 1, "%s", 
             gblcData->days);
    snprintf_s(gblcData->idReturn, sizeof(gblcData->id),
             gblcData->idLen + 1, "%s", 
             gblcData->id);
    snprintf_s(gblcData->prefixReturn, sizeof(gblcData->prefix),
             gblcData->prefixLen + 1, "%s", 
             gblcData->prefix);
    snprintf_s(gblcData->statusReturn, sizeof(gblcData->status),
             gblcData->statusLen + 1, "%s", 
             gblcData->status);

    (void)(*(gblcData->responseCompleteCallback))(requestStatus, s3ErrorDetails, gblcData->callbackData);

    simplexml_deinitialize(&(gblcData->simpleXml));

    free(gblcData);//lint !e516 
	gblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void GetBucketLifecycleConfiguration(const S3BucketContext *bucketContext,
                    char*date,char*days,char*id,char*prefix,char*status,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
    // 
	COMMLOG(OBS_LOGINFO, "Enter GetBucketLifecycleConfiguration successfully !");
    GetBucketLifecycleConfigurationData *gblcData = 
        (GetBucketLifecycleConfigurationData *) malloc(sizeof(GetBucketLifecycleConfigurationData));
    if (!gblcData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketLifecycleConfigurationData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

        return;
    }
	memset_s(gblcData, sizeof(GetBucketLifecycleConfigurationData), 0, sizeof(GetBucketLifecycleConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(gblcData);//lint !e516 
		gblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gblcData->simpleXml), &GetBucketLifecycleConfigurationXmlCallback, gblcData);//lint !e119

    gblcData->responsePropertiesCallback = handler->propertiesCallback;
    gblcData->responseCompleteCallback = handler->completeCallback;
    gblcData->callbackData = callbackData;

    gblcData->dateReturn= date;
	gblcData->dateReturnSize=0;
    gblcData->daysReturn= days;
	gblcData->daysReturnSize=0;
    gblcData->idReturn= id;
	gblcData->idReturnSize=0;
    gblcData->prefixReturn= prefix;
	gblcData->prefixReturnSize=0;
    gblcData->statusReturn= status;
	gblcData->statusReturnSize=0;
 
	string_buffer_initialize(gblcData->date);
	string_buffer_initialize(gblcData->days);
	string_buffer_initialize(gblcData->id);
	string_buffer_initialize(gblcData->prefix);
	string_buffer_initialize(gblcData->status);
 
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,										 // httpRequestType
        { bucketContext->hostName,								 // hostName
          bucketContext->bucketName,							 // bucketName
          bucketContext->protocol,								 // protocol
          bucketContext->uriStyle,								 // uriStyle
          bucketContext->accessKeyId,							 // accessKeyId
          bucketContext->secretAccessKey,						 // secretAccessKey
          bucketContext->certificateInfo },						 // certificateInfo
        0,														 // key
        0,														 // queryParams
        "lifecycle",											 // subResource
        0,														 // copySourceBucketName
        0,														 // copySourceKey
        0,														 // getConditions
        0,														 // startByte
        0,														 // byteCount
		0,														 // corsConf
        0,														 // putProperties
		0,                                                       // ServerSideEncryptionParams
        &GetBucketLifecycleConfigurationPropertiesCallback,      // propertiesCallback
        0,														 // toS3Callback
        0,														 // toS3CallbackTotalSize
        &GetBucketLifecycleConfigurationDataCallback,            // fromS3Callback
        &GetBucketLifecycleConfigurationCompleteCallback,        // completeCallback
        gblcData,												 // callbackData
		bucketContext->certificateInfo ? 1 : 0					 // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketLifecycleConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// GetBucketLifecycleConfigurationEx -------------------------------------------------------------------

#define D_MAX_RULE_NUMBER 100

typedef struct BucketLifeCycleConfData
{
	string_buffer(date, 256);
	string_buffer(days, 256);
	string_buffer(id, 256);
	string_buffer(prefix, 256);
	string_buffer(status, 256);
}BucketLifeCycleConfData;

//lint -e601
typedef struct GetBucketLifecycleConfigurationDataEx
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
	GetBucketLifecycleConfigurationCallbackEx* getBucketLifecycleConfigurationCallbackEx;
    void *callbackData;

	BucketLifeCycleConfData* blccData[D_MAX_RULE_NUMBER];
	unsigned int blccNumber;
} GetBucketLifecycleConfigurationDataEx;
//lint +e601

static S3Status make_get_lifecycle_callbackEx(GetBucketLifecycleConfigurationDataEx *gblcDataEx)/*lint !e31 */
{
	S3Status iRet = S3StatusOK;

	int nCount = gblcDataEx->blccNumber - 1;
	if(nCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusOutOfMemory;
	}
	S3BucketLifeCycleConf* buckLifeCycleConf = (S3BucketLifeCycleConf*)malloc(sizeof(S3BucketLifeCycleConf) * nCount);
	if (NULL == buckLifeCycleConf)
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3BucketLifeCycleConf failed!");
		return S3StatusOutOfMemory;
	}

	//初始化
	memset_s(buckLifeCycleConf, sizeof(S3BucketLifeCycleConf) * nCount, 0, sizeof(S3BucketLifeCycleConf) * nCount);
	int i = 0;
	for (; i<nCount; ++i)
	{
		// date
		buckLifeCycleConf[i].date = gblcDataEx->blccData[i]->date;

		// days
		buckLifeCycleConf[i].days = gblcDataEx->blccData[i]->days;

		// id
		buckLifeCycleConf[i].id= gblcDataEx->blccData[i]->id;

		// prefix
		buckLifeCycleConf[i].prefix= gblcDataEx->blccData[i]->prefix;

		// status
		buckLifeCycleConf[i].status= gblcDataEx->blccData[i]->status;
	}

	iRet = (*(gblcDataEx->getBucketLifecycleConfigurationCallbackEx))
		(buckLifeCycleConf, nCount, gblcDataEx->callbackData);

	CHECK_NULL_FREE(buckLifeCycleConf);
	
    return iRet;
}


static S3Status GetBucketLifecycleConfigurationXmlCallbackEx(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
	GetBucketLifecycleConfigurationDataEx *gblcDataEx = (GetBucketLifecycleConfigurationDataEx *) callbackData;

	int fit;
	int nIndex = gblcDataEx->blccNumber - 1;
	
	if (data)
	{
		if(!strcmp(elementPath, "LifecycleConfiguration/Rule/ID")) {
		    string_buffer_append(gblcDataEx->blccData[nIndex]->id, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Prefix")){
			string_buffer_append(gblcDataEx->blccData[nIndex]->prefix, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Status")){
			string_buffer_append(gblcDataEx->blccData[nIndex]->status, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Expiration/Date")){
			string_buffer_append(gblcDataEx->blccData[nIndex]->date, data, dataLen, fit);
		}
		else if(!strcmp(elementPath, "LifecycleConfiguration/Rule/Expiration/Days")){
			string_buffer_append(gblcDataEx->blccData[nIndex]->days, data, dataLen, fit);
		}		
	}
	else
	{
		if(!strcmp(elementPath, "LifecycleConfiguration/Rule"))
		{
			BucketLifeCycleConfData* blccData = (BucketLifeCycleConfData*)malloc(sizeof(BucketLifeCycleConfData));
			if (!blccData)
			{
				(*(gblcDataEx->responseCompleteCallback))
			            (S3StatusOutOfMemory, 0, callbackData);
					COMMLOG(OBS_LOGERROR, "Malloc BucketLifeCycleConfData failed !");
					
				return S3StatusOutOfMemory;
			}
			memset_s(blccData, sizeof(BucketLifeCycleConfData), 0, sizeof(BucketLifeCycleConfData));  //secure function
			gblcDataEx->blccData[gblcDataEx->blccNumber] = blccData;
			gblcDataEx->blccNumber++;
		}
	}

	/* Avoid compiler error about variable set but not used */
	(void) fit;

	return S3StatusOK;
}


static S3Status GetBucketLifecycleConfigurationPropertiesCallbackEx
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketLifecycleConfigurationDataEx *gblcDataEx = (GetBucketLifecycleConfigurationDataEx *) callbackData;
    
    return (*(gblcDataEx->responsePropertiesCallback))
        (responseProperties, gblcDataEx->callbackData);
}


static S3Status GetBucketLifecycleConfigurationDataCallbackEx(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    GetBucketLifecycleConfigurationDataEx *gblcDataEx = (GetBucketLifecycleConfigurationDataEx *) callbackData;

    return simplexml_add(&(gblcDataEx->simpleXml), buffer, bufferSize);
}


static void GetBucketLifecycleConfigurationCompleteCallbackEx(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails,void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketLifecycleConfigurationDataEx *gblcDataEx = (GetBucketLifecycleConfigurationDataEx *) callbackData;

    // Make the callback if there is anything
     if (gblcDataEx->blccNumber) {
        make_get_lifecycle_callbackEx(gblcDataEx);
    }

    (*(gblcDataEx->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gblcDataEx->callbackData);

    simplexml_deinitialize(&(gblcDataEx->simpleXml));

	unsigned int i = 0;
	for (; i<gblcDataEx->blccNumber; ++i)
	{
		free(gblcDataEx->blccData[i]);
		gblcDataEx->blccData[i] = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	}
    free(gblcDataEx);
	gblcDataEx = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void GetBucketLifecycleConfigurationEx(const S3BucketContext *bucketContext, S3RequestContext *requestContext, const S3LifeCycleHandlerEx *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketLifecycleConfiguration successfully !");
    GetBucketLifecycleConfigurationDataEx *gblcDataEx = 
        (GetBucketLifecycleConfigurationDataEx *) malloc(sizeof(GetBucketLifecycleConfigurationDataEx));
    if (!gblcDataEx) {
        (void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketLifecycleConfigurationDataEx failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

        return;
    }
	memset_s(gblcDataEx, sizeof(GetBucketLifecycleConfigurationDataEx), 0, sizeof(GetBucketLifecycleConfigurationDataEx));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(gblcDataEx);//lint !e516
		gblcDataEx = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gblcDataEx->simpleXml), &GetBucketLifecycleConfigurationXmlCallbackEx, gblcDataEx);//lint !e119

    gblcDataEx->responsePropertiesCallback = handler->responseHandler.propertiesCallback;
    gblcDataEx->responseCompleteCallback = handler->responseHandler.completeCallback;
	gblcDataEx->getBucketLifecycleConfigurationCallbackEx = handler->getBucketLifecycleConfigurationCallbackEx;
    gblcDataEx->callbackData = callbackData;

	BucketLifeCycleConfData* blccData = (BucketLifeCycleConfData*)malloc(sizeof(BucketLifeCycleConfData));
	if (!blccData)
	{
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc BucketLifeCycleConfData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
	}
	memset_s(blccData, sizeof(BucketLifeCycleConfData), 0, sizeof(BucketLifeCycleConfData));//lint !e516
	gblcDataEx->blccData[0] = blccData;
	gblcDataEx->blccNumber = 1;
 
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,										 // httpRequestType
        { bucketContext->hostName,								 // hostName
          bucketContext->bucketName,							 // bucketName
          bucketContext->protocol,								 // protocol
          bucketContext->uriStyle,								 // uriStyle
          bucketContext->accessKeyId,							 // accessKeyId
          bucketContext->secretAccessKey,						 // secretAccessKey
          bucketContext->certificateInfo },						 // certificateInfo
        0,														 // key
        0,														 // queryParams
        "lifecycle",											 // subResource
        0,														 // copySourceBucketName
        0,														 // copySourceKey
        0,														 // getConditions
        0,														 // startByte
        0,														 // byteCount
		0,														 //corsConf
        0,														 // putProperties
		0,                                                       // ServerSideEncryptionParams
        &GetBucketLifecycleConfigurationPropertiesCallbackEx,    // propertiesCallback
        0,														 // toS3Callback
        0,														 // toS3CallbackTotalSize
        &GetBucketLifecycleConfigurationDataCallbackEx,          // fromS3Callback
        &GetBucketLifecycleConfigurationCompleteCallbackEx,      // completeCallback
        gblcDataEx,												 // callbackData
		bucketContext->certificateInfo ? 1 : 0					 // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketLifecycleConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// Delete Bucket Lifecycle Configuration -------------------------------------------------------------
//lint -e601
typedef struct DeleteBucketLifecycleConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
} DeleteBucketLifecycleConfigurationData;
//lint +e601

static S3Status DeleteBucketLifecycleConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    DeleteBucketLifecycleConfigurationData *dblcData = (DeleteBucketLifecycleConfigurationData *) callbackData;
    
    return (*(dblcData->responsePropertiesCallback))
        (responseProperties, dblcData->callbackData);
}


static void DeleteBucketLifecycleConfigurationCompleteCallback(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteBucketLifecycleConfigurationData *dblcData = (DeleteBucketLifecycleConfigurationData *) callbackData;

    (*(dblcData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, dblcData->callbackData);

    free(dblcData);
	dblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void DeleteBucketLifecycleConfiguration(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
       
    // 
	COMMLOG(OBS_LOGINFO, "Enter DeleteBucketLifecycleConfiguration successfully !");
    DeleteBucketLifecycleConfigurationData *dblcData = 
        (DeleteBucketLifecycleConfigurationData *) malloc(sizeof(DeleteBucketLifecycleConfigurationData));
    if (!dblcData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketLifecycleConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(dblcData, sizeof(DeleteBucketLifecycleConfigurationData), 0, sizeof(DeleteBucketLifecycleConfigurationData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(dblcData);//lint !e516
		dblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    dblcData->responsePropertiesCallback = handler->propertiesCallback;
    dblcData->responseCompleteCallback = handler->completeCallback;
    dblcData->callbackData = callbackData;

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,                                   // httpRequestType
        { hostName,                                              // hostName
          bucketName,                                            // bucketName
          protocol,                                              // protocol
          uriStyle,                                              // uriStyle
          accessKeyId,                                           // accessKeyId
          secretAccessKey,                                       // secretAccessKey
          "" },                                                  // certificateInfo
        0,                                                       // key
        0,                                                       // queryParams
        "lifecycle",                                             // subResource
        0,                                                       // copySourceBucketName
        0,                                                       // copySourceKey
        0,                                                       // getConditions
        0,                                                       // startByte
        0,                                                       // byteCount
		0,											             // corsConf
        0,                                                       // putProperties
		0,                                                       // ServerSideEncryptionParams
        &DeleteBucketLifecycleConfigurationPropertiesCallback,   // propertiesCallback
        0,                                                       // toS3Callback
        0,                                                       // toS3CallbackTotalSize
        0,                                                       // fromS3Callback
        &DeleteBucketLifecycleConfigurationCompleteCallback,     // completeCallback
        dblcData,                                                // callbackData
		0											             // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave DeleteBucketLifecycleConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}


void DeleteBucketLifecycleConfigurationCA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    // 
	COMMLOG(OBS_LOGINFO, "Enter DeleteBucketLifecycleConfiguration successfully !");
    DeleteBucketLifecycleConfigurationData *dblcData = 
        (DeleteBucketLifecycleConfigurationData *) malloc(sizeof(DeleteBucketLifecycleConfigurationData));
    if (!dblcData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketLifecycleConfigurationData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
        return;
    }
	memset_s(dblcData, sizeof(DeleteBucketLifecycleConfigurationData), 0, sizeof(DeleteBucketLifecycleConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(dblcData);//lint !e516
		dblcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    dblcData->responsePropertiesCallback = handler->propertiesCallback;
    dblcData->responseCompleteCallback = handler->completeCallback;
    dblcData->callbackData = callbackData;

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,									// httpRequestType
        { bucketContext->hostName,								// hostName
          bucketContext->bucketName,							// bucketName
          bucketContext->protocol,								// protocol
          bucketContext->uriStyle,								// uriStyle
          bucketContext->accessKeyId,							// accessKeyId
          bucketContext->secretAccessKey,						// secretAccessKey
          bucketContext->certificateInfo },						// certificateInfo
        0,														// key
        0,														// queryParams
        "lifecycle",											// subResource
        0,														// copySourceBucketName
        0,														// copySourceKey
        0,														// getConditions
        0,														// startByte
        0,														// byteCount
		0,														// corsConf
        0,														// putProperties
		0,                                                      // ServerSideEncryptionParams
        &DeleteBucketLifecycleConfigurationPropertiesCallback,  // propertiesCallback
        0,														// toS3Callback
        0,														// toS3CallbackTotalSize
        0,														// fromS3Callback
        &DeleteBucketLifecycleConfigurationCompleteCallback,    // completeCallback
        dblcData,												// callbackData
		bucketContext->certificateInfo ? 1 : 0					// isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave DeleteBucketLifecycleConfigurationCA successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


// SetBucketPolicy -------------------------------------------------------------
//lint -e601
typedef struct SetBucketPolicyData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024];
    int docLen, docBytesWritten;
} SetBucketPolicyData;                         
//lint +e601                           

static S3Status SetBucketPolicyPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    SetBucketPolicyData *sbpData = (SetBucketPolicyData *) callbackData;
    
    return (*(sbpData->responsePropertiesCallback))
        (responseProperties, sbpData->callbackData);
}


static int SetBucketPolicyDataCallback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    SetBucketPolicyData *sbpData = (SetBucketPolicyData *) callbackData;

    if (!sbpData->docLen) {
        return 0;
    }

    int remaining = (sbpData->docLen - sbpData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(sbpData->doc[sbpData->docBytesWritten]), toCopy); //secure function

    sbpData->docBytesWritten += toCopy;

    return toCopy;
}

//lint -e101
static void SetBucketPolicyCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketPolicyData *sbpData = (SetBucketPolicyData *) callbackData;

    (void)(*(sbpData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, sbpData->callbackData);

    free(sbpData);//lint !e516
	sbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void SetBucketPolicy(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName,
                      const char *policy,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter SetBucketPolicy successfully !");
    // Create the callback data
    SetBucketPolicyData *sbpData = 
        (SetBucketPolicyData *) malloc(sizeof(SetBucketPolicyData));
    if (!sbpData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketPolicyData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

        return;
    }
	memset_s(sbpData, sizeof(SetBucketPolicyData), 0, sizeof(SetBucketPolicyData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(sbpData);//lint !e516
		sbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    sbpData->responsePropertiesCallback = handler->propertiesCallback;
    sbpData->responseCompleteCallback = handler->completeCallback;
    sbpData->callbackData = callbackData;

    if (policy) {
        sbpData->docLen =
            snprintf_s(sbpData->doc, sizeof(sbpData->doc), _TRUNCATE,          //secure function
                     "%s",policy);
        sbpData->docBytesWritten = 0;
    }
    else {
		COMMLOG(OBS_LOGERROR, "Input param policy is NULL !");
        sbpData->docLen = 0;
    }
    
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          S3UriStylePath,                             // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "policy",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                  		  // putProperties
		0,                                            // ServerSideEncryptionParams
        &SetBucketPolicyPropertiesCallback,           // propertiesCallback
        &SetBucketPolicyDataCallback,                 // toS3Callback
        sbpData->docLen,                              // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &SetBucketPolicyCompleteCallback,             // completeCallback
        sbpData,                                      // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketPolicy successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}


void SetBucketPolicyCA(const S3BucketContext *bucketContext,
                      const char *policy,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketPolicyCA successfully !");
    // Create the callback data
    SetBucketPolicyData *sbpData = 
        (SetBucketPolicyData *) malloc(sizeof(SetBucketPolicyData));
    if (!sbpData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketPolicyData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
        return;
    }
	memset_s(sbpData, sizeof(SetBucketPolicyData), 0, sizeof(SetBucketPolicyData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(sbpData);//lint !e516
		sbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    sbpData->responsePropertiesCallback = handler->propertiesCallback;
    sbpData->responseCompleteCallback = handler->completeCallback;
    sbpData->callbackData = callbackData;

    if (policy) {
        sbpData->docLen =
            snprintf_s(sbpData->doc, sizeof(sbpData->doc), _TRUNCATE,        //secure function
                     "%s",policy);
        sbpData->docBytesWritten = 0;
    }
    else {
		COMMLOG(OBS_LOGERROR, "Input param policy is NULL !");
        sbpData->docLen = 0;
    }
    
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { bucketContext->hostName,                    // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          S3UriStylePath,                    		  // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "policy",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                  		  // putProperties
		0,                                            // ServerSideEncryptionParams
        &SetBucketPolicyPropertiesCallback,           // propertiesCallback
        &SetBucketPolicyDataCallback,                 // toS3Callback
        sbpData->docLen,                              // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &SetBucketPolicyCompleteCallback,             // completeCallback
        sbpData,                                      // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketPolicyCA successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}


// GetBucketQuota ----------------------------------------------------------------
//lint -e601
typedef struct GetBucketPolicyData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int policyReturnSize;
    char *policyReturn;

    string_buffer(policy, 1024);
} GetBucketPolicyData;
//lint +e601

static S3Status GetBucketPolicyPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    GetBucketPolicyData *gbpData = (GetBucketPolicyData *) callbackData;
    
    return (*(gbpData->responsePropertiesCallback))
        (responseProperties, gbpData->callbackData);
}


static S3Status GetBucketPolicyDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    GetBucketPolicyData *gbpData = (GetBucketPolicyData *) callbackData;
	// lost '}' in the end of policy, so bufferSize need to add one modify by cwx298983 2016.7.12 start
	snprintf_s(gbpData->policy, sizeof(gbpData->policy),   //secure function
			  bufferSize+1, "%s", 
			  buffer);
	// lost '}' in the end of policy, so bufferSize need to add one modify by cwx298983 2016.7.12 start
	
    return S3StatusOK;
}

//lint -e101
static void GetBucketPolicyCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketPolicyData *gbpData = (GetBucketPolicyData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(gbpData->policyReturn, sizeof(gbpData->policy),   //secure function
             gbpData->policyReturnSize, "%s", 
             gbpData->policy);

    (void)(*(gbpData->responseCompleteCallback))(requestStatus, s3ErrorDetails, gbpData->callbackData);


    free(gbpData);//lint !e516
	gbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

//lint -e101
void GetBucketPolicy(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int policyReturnSize,
                    char *policyReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{//lint +e101
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketPolicy successfully !");
    // Create the callback data
    GetBucketPolicyData *gbpData = 
        (GetBucketPolicyData *) malloc(sizeof(GetBucketPolicyData));
    if (!gbpData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketPolicyData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
		return;
    }
	memset_s(gbpData, sizeof(GetBucketPolicyData), 0, sizeof(GetBucketPolicyData));//lint !e516

	if(!bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(gbpData);//lint !e516
		gbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(policyReturnSize < 0 ){
		COMMLOG(OBS_LOGERROR, "policyReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 policyReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(gbpData);//lint !e516   
		gbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    gbpData->responsePropertiesCallback = handler->propertiesCallback;
    gbpData->responseCompleteCallback = handler->completeCallback;
    gbpData->callbackData = callbackData;

    gbpData->policyReturnSize = policyReturnSize;
    gbpData->policyReturn = policyReturn;
    string_buffer_initialize(gbpData->policy);


	
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { hostName,                                   // hostName
          bucketName,                                 // bucketName
          protocol,                                   // protocol
          uriStyle,                                   // uriStyle
          accessKeyId,                                // accessKeyId
          secretAccessKey,                            // secretAccessKey
          "" },                                       // certificateInfo
        0,                                            // key
        0,                                            // queryParams
        "policy",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketPolicyPropertiesCallback,           // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketPolicyDataCallback,                 // fromS3Callback
        &GetBucketPolicyCompleteCallback,             // completeCallback
        gbpData,                                      // callbackData
		0											  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketPolicy successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


void GetBucketPolicyCA(const S3BucketContext *bucketContext,
                    int policyReturnSize,
                    char *policyReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
      SYSTEMTIME reqTime; 
      GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketPolicyCA successfully !");
    // Create the callback data
    GetBucketPolicyData *gbpData = 
        (GetBucketPolicyData *) malloc(sizeof(GetBucketPolicyData));
    if (!gbpData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketPolicyData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(gbpData, sizeof(GetBucketPolicyData), 0, sizeof(GetBucketPolicyData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(gbpData);//lint !e516
		gbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(policyReturnSize < 0 ){
		COMMLOG(OBS_LOGERROR, "policyReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime); 
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 policyReturnSize < 0的时候不能直接退出，要先释放内存再return
		free(gbpData);//lint !e516
		gbpData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    gbpData->responsePropertiesCallback = handler->propertiesCallback;
    gbpData->responseCompleteCallback = handler->completeCallback;
    gbpData->callbackData = callbackData;

    gbpData->policyReturnSize = policyReturnSize;
    gbpData->policyReturn = policyReturn;
    string_buffer_initialize(gbpData->policy);


	
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
        0,                                            // key
        0,                                            // queryParams
        "policy",                                     // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketPolicyPropertiesCallback,           // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketPolicyDataCallback,                 // fromS3Callback
        &GetBucketPolicyCompleteCallback,             // completeCallback
        gbpData,                                      // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketPolicyCA successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

// DeleteBucketWithObjects-------------------------------------------------------------

/* typedef struct DeleteBucketWithObjectsData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
    char doc[1024];
    int docLen, docBytesWritten;

} DeleteBucketWithObjectsData;


static S3Status DeleteBucketWithObjectsPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    DeleteBucketWithObjectsData *dbwoData = (DeleteBucketWithObjectsData *) callbackData;
    
    return (*(dbwoData->responsePropertiesCallback))
        (responseProperties, dbwoData->callbackData);
}

static int DeleteBucketWithObjectsDataCallback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    DeleteBucketWithObjectsData *dbwoData = (DeleteBucketWithObjectsData *) callbackData;

    if (!dbwoData->docLen) {
        return 0;
    }

    int remaining = (dbwoData->docLen - dbwoData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(dbwoData->doc[dbwoData->docBytesWritten]), toCopy); //secure function

    dbwoData->docBytesWritten += toCopy;

    return toCopy;
}


static void DeleteBucketWithObjectsCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteBucketWithObjectsData *dbwoData = (DeleteBucketWithObjectsData *) callbackData;

    (*(dbwoData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, dbwoData->callbackData);

    free(dbwoData);
	dbwoData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void DeleteBucketWithObjects(const S3BucketContext *bucketContext,const S3PutProperties *putProperties,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter DeleteBucketWithObjects successfully !");
    // Create the callback data
    DeleteBucketWithObjectsData *dbwoData = 
        (DeleteBucketWithObjectsData *) malloc(sizeof(DeleteBucketWithObjectsData));
    if (!dbwoData) {
        (*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketWithObjectsData failed !");
        return;
    }
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);
		return;
	}

    dbwoData->responsePropertiesCallback = handler->propertiesCallback;
    dbwoData->responseCompleteCallback = handler->completeCallback;
    dbwoData->callbackData = callbackData;

	  if (bucketContext->bucketName) {
        dbwoData->docLen =
            snprintf_s(dbwoData->doc, sizeof(dbwoData->doc), _TRUNCATE,       //secure function
                     "<DeleteBucket><Bucket>"
                     "%s</Bucket></DeleteBucket>",
                     bucketContext->bucketName);
        dbwoData->docBytesWritten = 0;
    }
    else {
		COMMLOG(OBS_LOGERROR, "Bucket Name is NULL !");
        dbwoData->docLen = 0;
    }
    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePOST,                        // httpRequestType
        { bucketContext->hostName,                                   // hostName
          bucketContext->bucketName,                                 // bucketName
          bucketContext->protocol,                                   // protocol
          bucketContext->uriStyle,                                   // uriStyle
          bucketContext->accessKeyId,                                // accessKeyId
          bucketContext->secretAccessKey },                          // secretAccessKey
        0,                                            // key
        0,                                            // queryParams
        "deletebucket",                               // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        putProperties,                                            // putProperties
        &DeleteBucketWithObjectsPropertiesCallback,              // propertiesCallback
        &DeleteBucketWithObjectsDataCallback,                                            // toS3Callback
        dbwoData->docLen,                                            // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &DeleteBucketWithObjectsCompleteCallback,                // completeCallback
        dbwoData                                        // callbackData
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave DeleteBucketWithObjects successfully !");
}
 */


// SetBucketWebsiteConfiguration -------------------------------------------------------------
//lint -e601
typedef struct SetBucketWebsiteConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024];
    int docLen;
	int docBytesWritten;
} SetBucketWebsiteConfigurationData;                         
//lint +e601                            

static S3Status SetBucketWebsiteConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    SetBucketWebsiteConfigurationData *sbwcData = (SetBucketWebsiteConfigurationData *) callbackData;
    
    return (*(sbwcData->responsePropertiesCallback))
        (responseProperties, sbwcData->callbackData);
}


static int SetBucketWebsiteConfigurationDataCallback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    SetBucketWebsiteConfigurationData *sbwcData = (SetBucketWebsiteConfigurationData *) callbackData;

    if (!sbwcData->docLen) {
        return 0;
    }

    int remaining = (sbwcData->docLen - sbwcData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(sbwcData->doc[sbwcData->docBytesWritten]), toCopy); //secure function

    sbwcData->docBytesWritten += toCopy;

    return toCopy;
}

//lint -e101
static void SetBucketWebsiteConfigurationCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketWebsiteConfigurationData *sbwcData = (SetBucketWebsiteConfigurationData *) callbackData;

    (void)(*(sbwcData->responseCompleteCallback))(requestStatus, s3ErrorDetails, sbwcData->callbackData);

    free(sbwcData);//lint !e516
	sbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}



void SetBucketWebsiteConfiguration(const S3BucketContext *bucketContext,
						const S3SetBucketRedirectAllConf *setBucketRedirectAll, const S3SetBucketWebsiteConf *setBucketWebsiteConf,
						S3RequestContext *requestContext,
						const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketWebsiteConfiguration successfully !");
    SetBucketWebsiteConfigurationData *sbwcData = 
        (SetBucketWebsiteConfigurationData *) malloc(sizeof(SetBucketWebsiteConfigurationData));
    if (!sbwcData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketWebsiteConfigurationData failed!");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(sbwcData, sizeof(SetBucketWebsiteConfigurationData), 0, sizeof(SetBucketWebsiteConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(sbwcData);//lint !e516
		sbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}


    sbwcData->responsePropertiesCallback = handler->propertiesCallback;
    sbwcData->responseCompleteCallback = handler->completeCallback;
    sbwcData->callbackData = callbackData;

	int tmplen = 0;
	int i = 0;
	int mark = 0;
	
	sbwcData->docLen = snprintf_s(sbwcData->doc, sizeof(sbwcData->doc), _TRUNCATE, //secure function
							 "<WebsiteConfiguration>");
	if (setBucketRedirectAll)
	{
		if(NULL == setBucketRedirectAll->hostName)
		{
			COMMLOG(OBS_LOGERROR, "setBucketRedirectAll hostName is NULL!");
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

			free(sbwcData);//lint !e516
			sbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;
		}
		
		//cheack array index by jwx329074 2016.11.17
		if (sbwcData->docLen < 0)
		{
			COMMLOG(OBS_LOGERROR, "snprintf_s error!");
			free(sbwcData);//lint !e516
			sbwcData = NULL;
			return;
		}
		tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,
							 "<RedirectAllRequestsTo>");
		sbwcData->docLen += tmplen;

		//lint -e409
		if (setBucketRedirectAll->hostName && setBucketRedirectAll->hostName[0])
		{
			char* phostName = 0;
			mark = pcre_replace(setBucketRedirectAll->hostName,&phostName);
			tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc)- sbwcData->docLen, _TRUNCATE,
								 "<HostName>""%s</HostName>", mark ? phostName : setBucketRedirectAll->hostName);
			sbwcData->docLen += tmplen;
			if(mark)
			{
				free(phostName);//lint !e516
				phostName = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		
		if (setBucketRedirectAll->protocol && setBucketRedirectAll->protocol[0])
		{
			//cheack array index by jwx329074 2016.11.17
			if (sbwcData->docLen < 0)
			{
				COMMLOG(OBS_LOGERROR, "snprintf_s is error!");   
				free(sbwcData);//lint !e516
				sbwcData = NULL;
				return;
			}
			
			char*pprotocol = 0;
			mark = pcre_replace(setBucketRedirectAll->protocol,&pprotocol);
			tmplen = snprintf_s(sbwcData->doc + sbwcData->docLen, sizeof(sbwcData->doc)- sbwcData->docLen, _TRUNCATE,
								 "<Protocol>""%s</Protocol>", mark ? pprotocol : setBucketRedirectAll->protocol);
			sbwcData->docLen += tmplen;
			if(mark)
			{
				free(pprotocol);//lint !e516
				pprotocol = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		
		tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,
							 "</RedirectAllRequestsTo>");
		sbwcData->docLen += tmplen;
	}
	
	if (setBucketWebsiteConf)
	{
		if(NULL == setBucketWebsiteConf->suffix)
		{
			COMMLOG(OBS_LOGERROR, "setBucketWebsiteConf suffix is NULL!");
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

			free(sbwcData);//lint !e516
			sbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;
		}
		
		if (setBucketWebsiteConf->suffix && setBucketWebsiteConf->suffix[0])
		{
			if (sbwcData->docLen < 0)// cheack array index by jwx329074 2016.11.17
			{
				COMMLOG(OBS_LOGERROR, "snprintf_s is error!");   
				free(sbwcData);//lint !e516
				sbwcData = NULL;
				return;
			}

			char* psuffix = 0;
			mark = pcre_replace(setBucketWebsiteConf->suffix,&psuffix);
			tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,
                            "<IndexDocument><Suffix>""%s</Suffix></IndexDocument>", mark ? psuffix : setBucketWebsiteConf->suffix);
            sbwcData->docLen += tmplen;
			if(mark)
			{
				free(psuffix);//lint !e516
				psuffix = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		if (setBucketWebsiteConf->key && setBucketWebsiteConf->key[0])
		{
			if (sbwcData->docLen < 0)// cheack array index by jwx329074 2016.11.17
			{
				COMMLOG(OBS_LOGERROR, "snprintf_s is error!");   
				free(sbwcData);//lint !e516
				sbwcData = NULL;
				return;
			}
			char*pkey = 0;
			mark = pcre_replace(setBucketWebsiteConf->key,&pkey);

			tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function  ������
							"<ErrorDocument><Key>""%s</Key></ErrorDocument>", mark ? pkey : setBucketWebsiteConf->key);
            sbwcData->docLen += tmplen;
			if(mark)
			{
				free(pkey);//lint !e516
				pkey = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
		}
		if (sbwcData->docLen < 0)// cheack array index by jwx329074 2016.11.17
		{
			COMMLOG(OBS_LOGERROR, "snprintf_s is error!");   
			free(sbwcData);//lint !e516
			sbwcData = NULL;
			return;
		}
		tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen,  _TRUNCATE, "<RoutingRules>");  //secure function
        sbwcData->docLen += tmplen;
		for(i = 0; i < setBucketWebsiteConf->stCount; i++)
		{
			tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen,  _TRUNCATE, "<RoutingRule><Condition>");  //secure function
			sbwcData->docLen += tmplen;
			if (setBucketWebsiteConf->stIn[i].keyPrefixEquals){
				char* pkeyPrefixEquals = 0;
				mark = pcre_replace(setBucketWebsiteConf->stIn[i].keyPrefixEquals,&pkeyPrefixEquals);
				tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,
	                                                                 "<KeyPrefixEquals>""%s</KeyPrefixEquals>", mark ? pkeyPrefixEquals : setBucketWebsiteConf->stIn[i].keyPrefixEquals);
	            sbwcData->docLen += tmplen;
				if(mark)
				{
					free(pkeyPrefixEquals);//lint !e516
					pkeyPrefixEquals = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}else if(setBucketWebsiteConf->stIn[i].httpErrorCodeReturnedEquals) {
				char* phttpErrorCodeReturnedEquals = 0;
				mark = pcre_replace(setBucketWebsiteConf->stIn[i].httpErrorCodeReturnedEquals,&phttpErrorCodeReturnedEquals);
				tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function
	                        "<HttpErrorCodeReturnedEquals>""%s</HttpErrorCodeReturnedEquals>",mark ? phttpErrorCodeReturnedEquals : setBucketWebsiteConf->stIn[i].httpErrorCodeReturnedEquals);
	            sbwcData->docLen += tmplen;
				if(mark)
				{
					free(phttpErrorCodeReturnedEquals);//lint !e516
					phttpErrorCodeReturnedEquals = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}

			tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen,  _TRUNCATE,"</Condition><Redirect>");  //secure function
	                sbwcData->docLen += tmplen;
			
			if (setBucketWebsiteConf->stIn[i].protocol){
					char* pprotocol = 0;
					mark = pcre_replace(setBucketWebsiteConf->stIn[i].protocol,&pprotocol);
	                tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function
	                                                         "<Protocol>""%s</Protocol>", mark ? pprotocol : setBucketWebsiteConf->stIn[i].protocol);
	                sbwcData->docLen += tmplen;			
					if(mark)
					{
						free(pprotocol);//lint !e516
						pprotocol = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
					}
			}
			if (setBucketWebsiteConf->stIn[i].hostName){
				char* phostName = 0;
				mark = pcre_replace(setBucketWebsiteConf->stIn[i].hostName,&phostName);
				tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function
	                                                                 "<HostName>""%s</HostName>", mark ? phostName : setBucketWebsiteConf->stIn[i].hostName);
	            sbwcData->docLen += tmplen;
				if(mark)
				{
					free(phostName);//lint !e516
					phostName = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}
			if (setBucketWebsiteConf->stIn[i].replaceKeyPrefixWith){
				char* preplaceKeyPrefixWith = 0;
				mark = pcre_replace(setBucketWebsiteConf->stIn[i].replaceKeyPrefixWith,&preplaceKeyPrefixWith);
	            tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function
	                                                                 "<ReplaceKeyPrefixWith>""%s</ReplaceKeyPrefixWith>", mark ? preplaceKeyPrefixWith : setBucketWebsiteConf->stIn[i].replaceKeyPrefixWith);
	            sbwcData->docLen += tmplen;
				if(mark)
				{
					free(preplaceKeyPrefixWith);//lint !e516
					preplaceKeyPrefixWith = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
		    }
			if (setBucketWebsiteConf->stIn[i].replaceKeyWith){
	        	char* preplaceKeyWith = 0;
				mark = pcre_replace(setBucketWebsiteConf->stIn[i].replaceKeyWith,&preplaceKeyWith);
				tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function
	                                                                 "<ReplaceKeyWith>""%s</ReplaceKeyWith>", mark ? preplaceKeyWith : setBucketWebsiteConf->stIn[i].replaceKeyWith);
	            sbwcData->docLen += tmplen;
				if(mark)
				{
					free(preplaceKeyWith);//lint !e516
					preplaceKeyWith = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}
			if (setBucketWebsiteConf->stIn[i].httpRedirectCode){
				char*phttpRedirectCode = 0;
				mark = pcre_replace(setBucketWebsiteConf->stIn[i].httpRedirectCode,&phttpRedirectCode);
		        tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE, //secure function
		                                                   "<HttpRedirectCode>""%s</HttpRedirectCode>", mark ? phttpRedirectCode : setBucketWebsiteConf->stIn[i].httpRedirectCode);
		        //lint +e409
				sbwcData->docLen += tmplen;			
				if(mark)
				{
					free(phttpRedirectCode);//lint !e516
					phttpRedirectCode = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}
			tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,"</Redirect></RoutingRule>"); //secure function
			sbwcData->docLen += tmplen;
		}
		tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,"</RoutingRules>"); //secure function
        sbwcData->docLen += tmplen;
	}
	//cheack array index by jwx329074 2016.11.16
	if (sbwcData->docLen < 0)
	{
		COMMLOG(OBS_LOGERROR, "Negative array index read!");
		free(sbwcData);
		sbwcData = NULL;
		return;
	}
	tmplen = snprintf_s((sbwcData->doc) + (sbwcData->docLen), sizeof(sbwcData->doc) - sbwcData->docLen, _TRUNCATE,"</WebsiteConfiguration>"); //secure function
    sbwcData->docLen += tmplen;
	sbwcData->docBytesWritten = 0;




    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,									// httpRequestType
        { bucketContext->hostName,							// hostName
          bucketContext->bucketName,						// bucketName
          bucketContext->protocol,							// protocol
          bucketContext->uriStyle,							// uriStyle
          bucketContext->accessKeyId,						// accessKeyId
          bucketContext->secretAccessKey,					// secretAccessKey
          bucketContext->certificateInfo },					// certificateInfo
        0,													// key
        0,													// queryParams
        "website",											// subResource
        0,													// copySourceBucketName
        0,													// copySourceKey
        0,													// getConditions
        0,													// startByte
        0,													// byteCount
		0,													// corsConf
        0,													// putProperties
		0,                                                  // ServerSideEncryptionParams
        &SetBucketWebsiteConfigurationPropertiesCallback,   // propertiesCallback
        &SetBucketWebsiteConfigurationDataCallback,         // toS3Callback
        sbwcData->docLen,									// toS3CallbackTotalSize
        0,													// fromS3Callback
        &SetBucketWebsiteConfigurationCompleteCallback,     // completeCallback
        sbwcData,											// callbackData
		bucketContext->certificateInfo ? 1 : 0				// isCheckCA
    };


    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketWebsiteConfiguration successfully !");

    SYSTEMTIME rspTime; 
    GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

// GetBucketWebsiteConfiguration -------------------------------------------------------------------

typedef struct BucketWebsite
{
	string_buffer(keyPrefixEquals, 256);
	string_buffer(httpErrorCodeReturnedEquals, 256);
	string_buffer(replaceKeyPrefixWith, 256);
	string_buffer(replaceKeyWith, 256);
	string_buffer(httpRedirectCode, 256);
    string_buffer(hostname, 256);
	string_buffer(protocol, 256);

} BucketWebsite;
static void initialize_bucketwebsite(BucketWebsite *webdata)
{
    string_buffer_initialize(webdata->keyPrefixEquals);
    string_buffer_initialize(webdata->httpErrorCodeReturnedEquals);
    string_buffer_initialize(webdata->replaceKeyPrefixWith);
    string_buffer_initialize(webdata->replaceKeyWith);
    string_buffer_initialize(webdata->httpRedirectCode);
    string_buffer_initialize(webdata->hostname);
    string_buffer_initialize(webdata->protocol);
}


#define MAX_WEBSITE 10

//lint -e601
typedef struct GetBucketWebsiteConfigurationData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
	S3GetBucketWebsiteConfigurationCallback *getBucketWebsiteConfigurationCallback;
    void *callbackData;


    string_buffer(hostname, 256);
	string_buffer(protocol, 256);
	string_buffer(suffix, 256);
	string_buffer(key, 256);
	BucketWebsite webdata[MAX_WEBSITE];
	int webdatacount;

} GetBucketWebsiteConfigurationData;
//lint +e601
//lint -e528
static void initialize_bucketwebsitedata(GetBucketWebsiteConfigurationData *gwsData)
{
    gwsData->webdatacount= 0;
    initialize_bucketwebsite(gwsData->webdata);

}
//lint +e528
static S3Status make_get_bucket_websitedata_callback(GetBucketWebsiteConfigurationData *gwsData)/*lint !e31 */
{
	S3Status iRet = S3StatusOK;
	
    //S3SetBucketWebsiteConfIn s3websitein[gwsData->webdatacount];
	if(gwsData->webdatacount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusInternalError;
	}
	S3SetBucketWebsiteConfIn *s3websitein = (S3SetBucketWebsiteConfIn*)malloc(sizeof(S3SetBucketWebsiteConfIn) * gwsData->webdatacount);
	if (NULL == s3websitein) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3SetBucketWebsiteConfIn failed!");
		return S3StatusInternalError;
	}
	memset_s(s3websitein, sizeof(S3SetBucketWebsiteConfIn) * gwsData->webdatacount, 0, sizeof(S3SetBucketWebsiteConfIn) * gwsData->webdatacount);  //secure function

    int webdatacount = gwsData->webdatacount;
	int i ;
   for (i = 0; i < webdatacount; i++) {
        S3SetBucketWebsiteConfIn *websiteDest = &(s3websitein[i]);
        BucketWebsite *websiteSrc = &(gwsData->webdata[i]);
 
		 websiteDest->keyPrefixEquals = websiteSrc->keyPrefixEquals;
		 websiteDest->httpErrorCodeReturnedEquals = websiteSrc->httpErrorCodeReturnedEquals;
		 websiteDest->replaceKeyPrefixWith = websiteSrc->replaceKeyPrefixWith;
		 websiteDest->replaceKeyWith = websiteSrc->replaceKeyWith;
		 websiteDest->httpRedirectCode = websiteSrc->httpRedirectCode;
		 websiteDest->hostName = websiteSrc->hostname;
		 websiteDest->protocol = websiteSrc->protocol;
   	}

   iRet = (*(gwsData->getBucketWebsiteConfigurationCallback))
	   (gwsData->hostname,gwsData->protocol,gwsData->suffix,gwsData->key,s3websitein,webdatacount,gwsData->callbackData);

   CHECK_NULL_FREE(s3websitein);

   return iRet;
}

static S3Status GetBucketWebsiteConfigurationXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    GetBucketWebsiteConfigurationData *gbwcData = (GetBucketWebsiteConfigurationData *) callbackData;

    int fit;

	if (data)
		{
			if(!strcmp(elementPath, "WebsiteConfiguration/RedirectAllRequestsTo/HostName")) {
				string_buffer_append(gbwcData->hostname, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RedirectAllRequestsTo/Protocol")){
				string_buffer_append(gbwcData->protocol, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/IndexDocument/Suffix")){
				string_buffer_append(gbwcData->suffix, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/ErrorDocument/Key")){
				string_buffer_append(gbwcData->key, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Condition/KeyPrefixEquals")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->keyPrefixEquals, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Condition/HttpErrorCodeReturnedEquals")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->httpErrorCodeReturnedEquals, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Redirect/ReplaceKeyPrefixWith")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->replaceKeyPrefixWith, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Redirect/HostName")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->hostname, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Redirect/Protocol")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->protocol, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Redirect/ReplaceKeyWith")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->replaceKeyWith, data, dataLen, fit);
			}
			else if(!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule/Redirect/HttpRedirectCode")){
				BucketWebsite* bws = &(gbwcData->webdata[gbwcData->webdatacount]);
				string_buffer_append(bws->httpRedirectCode, data, dataLen, fit);
			}
		}
	    else {
        if (!strcmp(elementPath, "WebsiteConfiguration/RoutingRules/RoutingRule")) {
            // Finished a Contents
            gbwcData->webdatacount++;
            if (gbwcData->webdatacount == MAX_WEBSITE) {
                // Make the callback
                S3Status status = make_get_bucket_websitedata_callback(gbwcData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_bucketwebsitedata(gbwcData);
            }
            else {
                // Initialize the next one
                initialize_bucketwebsite
                    (&(gbwcData->webdata[gbwcData->webdatacount]));
            }
        }

    }



    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status GetBucketWebsiteConfigurationPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketWebsiteConfigurationData *gbwcData = (GetBucketWebsiteConfigurationData *) callbackData;
    
    return (*(gbwcData->responsePropertiesCallback))
        (responseProperties, gbwcData->callbackData);
}


static S3Status GetBucketWebsiteConfigurationDataCallback(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    GetBucketWebsiteConfigurationData *gbwcData = (GetBucketWebsiteConfigurationData *) callbackData;

    return simplexml_add(&(gbwcData->simpleXml), buffer, bufferSize);
}


static void GetBucketWebsiteConfigurationCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketWebsiteConfigurationData *gbwcData = (GetBucketWebsiteConfigurationData *) callbackData;

    // Copy the location constraint into the return buffer
 
    make_get_bucket_websitedata_callback(gbwcData);
	
    (*(gbwcData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gbwcData->callbackData);

    simplexml_deinitialize(&(gbwcData->simpleXml));

    free(gbwcData);
	gbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void GetBucketWebsiteConfiguration(const S3BucketContext *bucketContext,
                    S3RequestContext *requestContext,
                    const S3GetBucketWebsiteConfHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO,"Enter GetBucketWebsiteConfiguration successfully !");
	// Create the callback data
	GetBucketWebsiteConfigurationData *gbwcData = 
		(GetBucketWebsiteConfigurationData *) malloc(sizeof(GetBucketWebsiteConfigurationData));
	if (!gbwcData) {
		(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
        return;
	}
	memset_s(gbwcData, sizeof(GetBucketWebsiteConfigurationData),  0, sizeof(GetBucketWebsiteConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(gbwcData);//lint !e516
		gbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	
	simplexml_initialize(&(gbwcData->simpleXml), &GetBucketWebsiteConfigurationXmlCallback, gbwcData);//lint !e119

	gbwcData->responsePropertiesCallback = handler->responseHandler.propertiesCallback;
	gbwcData->getBucketWebsiteConfigurationCallback = handler->getBucketWebsiteConfigurationCallback;
	gbwcData->responseCompleteCallback = handler->responseHandler.completeCallback;
	gbwcData->callbackData = callbackData;


	string_buffer_initialize(gbwcData->hostname);
	string_buffer_initialize(gbwcData->protocol);
	string_buffer_initialize(gbwcData->suffix);
	string_buffer_initialize(gbwcData->key);



	// Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,									 // httpRequestType
        { bucketContext->hostName,							 // hostName
          bucketContext->bucketName,						 // bucketName
          bucketContext->protocol,							 // protocol
          bucketContext->uriStyle,							 // uriStyle
          bucketContext->accessKeyId,						 // accessKeyId
          bucketContext->secretAccessKey,					 // secretAccessKey
          bucketContext->certificateInfo },					 // certificateInfo
        0,													 // key
        0,													 // queryParams
        "website",											 // subResource
        0,													 // copySourceBucketName
        0,													 // copySourceKey
        0,													 // getConditions
        0,													 // startByte
        0,													 // byteCount
		0,													 // corsConf
        0,													 // putProperties
		0,                                                   // ServerSideEncryptionParams
        &GetBucketWebsiteConfigurationPropertiesCallback,    // propertiesCallback
        0,													 // toS3Callback
        0,													 // toS3CallbackTotalSize
        &GetBucketWebsiteConfigurationDataCallback,          // fromS3Callback
        &GetBucketWebsiteConfigurationCompleteCallback,      // completeCallback
        gbwcData,											 // callbackData
		bucketContext->certificateInfo ? 1 : 0				 // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO,"Leave GetBucketWebsiteConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// DeleteBucketWebsiteConfiguration -------------------------------------------------------------
//lint -e601
typedef struct DeleteBucketWebsiteConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
} DeleteBucketWebsiteConfigurationData;
//lint +e601

static S3Status DeleteBucketWebsiteConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    DeleteBucketWebsiteConfigurationData *dbwcData = (DeleteBucketWebsiteConfigurationData *) callbackData;
    
    return (*(dbwcData->responsePropertiesCallback))
        (responseProperties, dbwcData->callbackData);
}


static void DeleteBucketWebsiteConfigurationCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteBucketWebsiteConfigurationData *dbwcData = (DeleteBucketWebsiteConfigurationData *) callbackData;

    (*(dbwcData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, dbwcData->callbackData);

    free(dbwcData);//lint !e516
	dbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void DeleteBucketWebsiteConfiguration(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter DeleteBucketWebsiteConfiguration successfully !");
	// Create the callback data
	DeleteBucketWebsiteConfigurationData *dbwcData = 
		(DeleteBucketWebsiteConfigurationData *) malloc(sizeof(DeleteBucketWebsiteConfigurationData));
	if (!dbwcData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketWebsiteConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
	}
	memset_s(dbwcData, sizeof(DeleteBucketWebsiteConfigurationData), 0, sizeof(DeleteBucketWebsiteConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(dbwcData);//lint !e516
		dbwcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

	dbwcData->responsePropertiesCallback = handler->propertiesCallback;
	dbwcData->responseCompleteCallback = handler->completeCallback;
	dbwcData->callbackData = callbackData;

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeDELETE,									// httpRequestType
		{ bucketContext->hostName,								// hostName
          bucketContext->bucketName,							// bucketName
          bucketContext->protocol,								// protocol
          bucketContext->uriStyle,								// uriStyle
          bucketContext->accessKeyId,							// accessKeyId
          bucketContext->secretAccessKey,						// secretAccessKey
          bucketContext->certificateInfo },						// certificateInfo
		0,														// key
		0,														// queryParams
		"website",												// subResource
		0,														// copySourceBucketName
		0,														// copySourceKey
		0,														// getConditions
		0,														// startByte
		0,														// byteCount
		0,														// corsConf
		0,														// putProperties
		0,                                                      // ServerSideEncryptionParams
		&DeleteBucketWebsiteConfigurationPropertiesCallback,	// propertiesCallback
		0,														// toS3Callback
		0,														// toS3CallbackTotalSize
		0,														// fromS3Callback
		&DeleteBucketWebsiteConfigurationCompleteCallback,		// completeCallback
		dbwcData,												// callbackData
		bucketContext->certificateInfo ? 1 : 0					// isCheckCA
    };

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave DeleteBucketWebsiteConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

// SetBucketVersioningConfiguration -------------------------------------------------------------
//lint -e601
typedef struct SetBucketVersioningConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024];
    int docLen;
	int docBytesWritten;
} SetBucketVersioningConfigurationData;                         
//lint +e601                            

static S3Status SetBucketVersioningConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    SetBucketVersioningConfigurationData *sbvcData = (SetBucketVersioningConfigurationData *) callbackData;
    
    return (*(sbvcData->responsePropertiesCallback))
        (responseProperties, sbvcData->callbackData);
}


static int SetBucketVersioningConfigurationDataCallback(int bufferSize, char *buffer, 
                                    void *callbackData)
{
    SetBucketVersioningConfigurationData *sbvcData = (SetBucketVersioningConfigurationData *) callbackData;

    if (!sbvcData->docLen) {
        return 0;
    }

    int remaining = (sbvcData->docLen - sbvcData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(sbvcData->doc[sbvcData->docBytesWritten]), toCopy); //secure function

    sbvcData->docBytesWritten += toCopy;

    return toCopy;
}

//lint -e101
static void SetBucketVersioningConfigurationCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketVersioningConfigurationData *sbvcData = (SetBucketVersioningConfigurationData *) callbackData;

    (void)(*(sbvcData->responseCompleteCallback))(requestStatus, s3ErrorDetails, sbvcData->callbackData);

    free(sbvcData);//lint !e516
	sbvcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void SetBucketVersioningConfiguration(const S3BucketContext *bucketContext,
						const char *status,
						S3RequestContext *requestContext,
						const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter SetBucketVersioningConfiguration successfully !");
    SetBucketVersioningConfigurationData *sbvcData = 
        (SetBucketVersioningConfigurationData *) malloc(sizeof(SetBucketVersioningConfigurationData));
    if (!sbvcData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketVersioningConfigurationData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
        return;
    }
	memset_s(sbvcData, sizeof(SetBucketVersioningConfigurationData), 0, sizeof(SetBucketVersioningConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(sbvcData);//lint !e516
		sbvcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(NULL == status){
		COMMLOG(OBS_LOGERROR, "status is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(sbvcData);//lint !e516
		sbvcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}


    sbvcData->responsePropertiesCallback = handler->propertiesCallback;
    sbvcData->responseCompleteCallback = handler->completeCallback;
    sbvcData->callbackData = callbackData;

	sbvcData->docLen = snprintf_s(sbvcData->doc, sizeof(sbvcData->doc), _TRUNCATE,  //secure function
							 "<VersioningConfiguration>");
	int tmplen = 0;
	int mark = 0;
	char*pstatus = 0;
	mark = pcre_replace(status,&pstatus);

	//cheack array index by jwx329074 2016.11.16
	if (sbvcData->docLen < 0)
	{
		COMMLOG(OBS_LOGERROR, "Negative array index read!");
		free(sbvcData);//lint !e516
		free(pstatus);//lint !e516
		pstatus = NULL;
		sbvcData = NULL;
		return;
	}
	tmplen = snprintf_s((sbvcData->doc) + (sbvcData->docLen), sizeof((sbvcData->doc)) - (sbvcData->docLen), _TRUNCATE, 
							 "<Status>""%s</Status></VersioningConfiguration>",mark ? pstatus : status);// add sizeof by jwx329074 2016.11.02
	sbvcData->docLen += tmplen;
	if(mark)
	{
		free(pstatus);//lint !e516
		pstatus = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	}
		
	sbvcData->docBytesWritten = 0;



    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,										 // httpRequestType
        { bucketContext->hostName,								 // hostName
          bucketContext->bucketName,							 // bucketName
          bucketContext->protocol,								 // protocol
          bucketContext->uriStyle,								 // uriStyle
          bucketContext->accessKeyId,							 // accessKeyId
          bucketContext->secretAccessKey,						 // secretAccessKey
          bucketContext->certificateInfo },						 // certificateInfo
        0,														 // key
        0,														 // queryParams
        "versioning",											 // subResource
        0,														 // copySourceBucketName
        0,														 // copySourceKey
        0,														 // getConditions
        0,														 // startByte
        0,														 // byteCount
		0,														 // corsConf
        0,														 // putProperties
		0,                                                       // ServerSideEncryptionParams
        &SetBucketVersioningConfigurationPropertiesCallback,     // propertiesCallback
        &SetBucketVersioningConfigurationDataCallback,           // toS3Callback
        sbvcData->docLen,										 // toS3CallbackTotalSize
        0,														 // fromS3Callback
        &SetBucketVersioningConfigurationCompleteCallback,       // completeCallback
        sbvcData,												 // callbackData
		bucketContext->certificateInfo ? 1 : 0					 // isCheckCA
    };


    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketVersioningConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}

// GetBucketVersioningConfiguration -------------------------------------------------------------------

//lint -e601
typedef struct GetBucketVersioningConfigurationData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

	int statusReturnSize;
	char *statusReturn;

    string_buffer(status, 256);

}GetBucketVersioningConfigurationData;
//lint +e601

static S3Status GetBucketVersioningConfigurationXmlCallback(const char *elementPath,const char *data, int dataLen, void *callbackData)/*lint !e31 */
{
    GetBucketVersioningConfigurationData *gbvcData = (GetBucketVersioningConfigurationData *) callbackData;

    int fit;

	if (data)
		{
			if(!strcmp(elementPath, "VersioningConfiguration/Status")) {
				string_buffer_append(gbvcData->status, data, dataLen, fit);
			}
		}


    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status GetBucketVersioningConfigurationPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketVersioningConfigurationData *gbvcData = (GetBucketVersioningConfigurationData *) callbackData;
    
    return (*(gbvcData->responsePropertiesCallback))
        (responseProperties, gbvcData->callbackData);
}


static S3Status GetBucketVersioningConfigurationDataCallback(int bufferSize, const char *buffer,
                                       void *callbackData)
{
    GetBucketVersioningConfigurationData *gbvcData = (GetBucketVersioningConfigurationData *) callbackData;

    return simplexml_add(&(gbvcData->simpleXml), buffer, bufferSize);
}

//lint -e101
static void GetBucketVersioningConfigurationCompleteCallback(S3Status requestStatus, 
                                       const S3ErrorDetails *s3ErrorDetails,
                                       void *callbackData)
{//lint +e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketVersioningConfigurationData *gbvcData = (GetBucketVersioningConfigurationData *) callbackData;

    // Copy the location constraint into the return buffer
    snprintf_s(gbvcData->statusReturn, sizeof(gbvcData->status),  //secure function
             gbvcData->statusReturnSize, "%s", 
             gbvcData->status);
    //printf("GetBucketVersioningConfigurationCompleteCallback - status : %s\n", gbvcData->status);

    (void)(*(gbvcData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gbvcData->callbackData);

    simplexml_deinitialize(&(gbvcData->simpleXml));

    free(gbvcData);//lint !e516
	gbvcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}



void GetBucketVersioningConfiguration(const S3BucketContext *bucketContext,
					int statusReturnSize, char *statusReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketVersioningConfiguration successfully !");
	// Create the callback data
	GetBucketVersioningConfigurationData *gbvcData = 
		(GetBucketVersioningConfigurationData *) malloc(sizeof(GetBucketVersioningConfigurationData));
	if (!gbvcData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketVersioningConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
	}
	memset_s(gbvcData, sizeof(GetBucketVersioningConfigurationData), 0, sizeof(GetBucketVersioningConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(gbvcData);//lint !e516
		gbvcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(statusReturnSize < 0 ){
		COMMLOG(OBS_LOGERROR, "statusReturnSize is invalid!");
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(gbvcData);//lint !e516
		gbvcData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}	
	simplexml_initialize(&(gbvcData->simpleXml), &GetBucketVersioningConfigurationXmlCallback, gbvcData);//lint !e119

	gbvcData->responsePropertiesCallback = handler->propertiesCallback;
	gbvcData->responseCompleteCallback = handler->completeCallback;
	gbvcData->callbackData = callbackData;

	gbvcData->statusReturn= statusReturn;
	gbvcData->statusReturnSize= statusReturnSize;
	string_buffer_initialize(gbvcData->status);	

	// Set up the RequestParams
	RequestParams params =
	{
		HttpRequestTypeGET, 									 // httpRequestType
		{ bucketContext->hostName,								 // hostName
          bucketContext->bucketName,							 // bucketName
          bucketContext->protocol,								 // protocol
          bucketContext->uriStyle,								 // uriStyle
          bucketContext->accessKeyId,							 // accessKeyId
          bucketContext->secretAccessKey,						 // secretAccessKey
          bucketContext->certificateInfo },						 // certificateInfo
		0,														 // key
		0,														 // queryParams
		"versioning",											 // subResource
		0,														 // copySourceBucketName
		0,														 // copySourceKey
		0,														 // getConditions
		0,														 // startByte
		0,														 // byteCount
		0,														 // corsConf
		0,														 // putProperties
		0,                                                       // ServerSideEncryptionParams
		&GetBucketVersioningConfigurationPropertiesCallback,	 // propertiesCallback
		0,													 	 // toS3Callback
		0,														 // toS3CallbackTotalSize
		&GetBucketVersioningConfigurationDataCallback, 			 // fromS3Callback
		&GetBucketVersioningConfigurationCompleteCallback, 		 // completeCallback
		gbvcData,												 // callbackData
		bucketContext->certificateInfo ? 1 : 0					 // isCheckCA
    };

	// Perform the request
	request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave GetBucketVersioningConfiguration successfully !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// ListVersions -------------------------------------------------------------------

typedef struct ListBucketVersions
{
    string_buffer(key, 1024);
	string_buffer(versionId, 256);
	string_buffer(isLatest, 64);
    string_buffer(lastModified, 256);
    string_buffer(eTag, 256);
    string_buffer(size, 24);
    string_buffer(ownerId, 256);
    string_buffer(ownerDisplayName, 256);
	string_buffer(storageClass, 64);
} ListBucketVersions;

typedef struct ListCommonPrefixes
{
	string_buffer(prefix, 1024);
}ListCommonPrefixes;

static void initialize_list_versions(ListBucketVersions *versions)
{
    string_buffer_initialize(versions->key);
	string_buffer_initialize(versions->versionId);
    string_buffer_initialize(versions->isLatest);
    string_buffer_initialize(versions->lastModified);
    string_buffer_initialize(versions->eTag);
    string_buffer_initialize(versions->size);
    string_buffer_initialize(versions->ownerId);
    string_buffer_initialize(versions->ownerDisplayName);
	string_buffer_initialize(versions->storageClass);
}

static void initialize_list_common_prefixes(ListCommonPrefixes* commonPrefixes)
{
	string_buffer_initialize(commonPrefixes->prefix);
}


#define MAX_VERSIONS 32
#define MAX_COMMONPREFIXES 64

//lint -e601
typedef struct ListVersionsData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ListVersionsCallback *listVersionsCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;


    string_buffer(nextKeyMarker, 1024);
	string_buffer(nextVersionIdMarker, 1024);
	string_buffer(isTruncated, 64);

	// add by cwx298983 2016.10.19 Start
	string_buffer(bucketName, 1024);
	string_buffer(prefix, 1024);
	string_buffer(keyMarker, 64);
	string_buffer(delimiter, 64);
	string_buffer(maxKeys, 32);
	// add by cwx298983 2016.10.19 End

	int versionsCount;
	ListBucketVersions versions[MAX_VERSIONS];

	int commonPrefixesCount;
	ListCommonPrefixes commonPrefixes[MAX_COMMONPREFIXES];
	
}ListVersionsData;
//lint +e601

static void initialize_list_versions_data(ListVersionsData *lvData)
{
    lvData->versionsCount = 0;
    initialize_list_versions(lvData->versions);

	lvData->commonPrefixesCount = 0;
	initialize_list_common_prefixes(lvData->commonPrefixes);
}

static S3Status make_list_versions_callback(ListVersionsData *lvData)/*lint !e31 */
{
	int i;
	S3Status iRet = S3StatusOK;

	// Convert IsTruncated
	int isTruncated = (!strcmp(lvData->isTruncated, "true") ||
		!strcmp(lvData->isTruncated, "1")) ? 1 : 0;

	// Convert the versions
	S3ListVersions *listVersions = (S3ListVersions*)malloc(sizeof(S3ListVersions));
	if (NULL == listVersions) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3ListVersions failed!");
		return S3StatusOutOfMemory;
	}
	memset_s(listVersions, sizeof(S3ListVersions), 0, sizeof(S3ListVersions));

	listVersions->versions = (S3Version*)malloc(sizeof(S3Version) * lvData->versionsCount);
	if (NULL == listVersions->versions) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3Version failed!");
		CHECK_NULL_FREE(listVersions);
		return S3StatusOutOfMemory;
	}
	memset_s(listVersions->versions, sizeof(S3Version) * lvData->versionsCount, 0, sizeof(S3Version) * lvData->versionsCount);

	listVersions->commonPrefixes = (const char**)malloc(sizeof(char*) * lvData->commonPrefixesCount);
	if (NULL == listVersions->commonPrefixes) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc commonPrefixes failed!");
		CHECK_NULL_FREE(listVersions->versions);
		CHECK_NULL_FREE(listVersions);
		return S3StatusOutOfMemory;
	}
	memset_s(listVersions->commonPrefixes, sizeof(char*) * lvData->commonPrefixesCount, 0, sizeof(char*) * lvData->commonPrefixesCount);

	listVersions->bucketName = lvData->bucketName;
	listVersions->prefix = lvData->prefix;
	listVersions->keyMarker = lvData->keyMarker;
	listVersions->delimiter = lvData->delimiter;
	listVersions->maxKeys = lvData->maxKeys;

	listVersions->versionsCount = lvData->versionsCount;
	for (i=0; i<listVersions->versionsCount; i++) {
		ListBucketVersions *versionSrc = &(lvData->versions[i]);

		listVersions->versions[i].key = versionSrc->key;
		listVersions->versions[i].versionId = versionSrc->versionId;
		listVersions->versions[i].isLatest = versionSrc->isLatest;

		listVersions->versions[i].lastModified = parseIso8601Time(versionSrc->lastModified);
		int nTimeZone = getTimeZone();
		listVersions->versions[i].lastModified += nTimeZone * SECONDS_TO_AN_HOUR;

		listVersions->versions[i].eTag = versionSrc->eTag;
		listVersions->versions[i].size = parseUnsignedInt(versionSrc->size);
		listVersions->versions[i].ownerId = versionSrc->ownerId[0] ?versionSrc->ownerId : 0;
		listVersions->versions[i].ownerDisplayName = (versionSrc->ownerDisplayName[0] ?
			versionSrc->ownerDisplayName : 0);
		listVersions->versions[i].storageClass = (versionSrc->storageClass[0] ?
			versionSrc->storageClass : 0);
	}

	listVersions->commonPrefixesCount = lvData->commonPrefixesCount;
	for (i=0; i<listVersions->commonPrefixesCount; i++)
	{
		listVersions->commonPrefixes[i] = lvData->commonPrefixes[i].prefix;
	}

	iRet = (*(lvData->listVersionsCallback))
		(isTruncated, lvData->nextKeyMarker, lvData->nextVersionIdMarker,
		listVersions, lvData->callbackData);

	CHECK_NULL_FREE(listVersions->commonPrefixes);
	CHECK_NULL_FREE(listVersions->versions);
	CHECK_NULL_FREE(listVersions);

	return iRet;
}


static S3Status ListVersionsXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    ListVersionsData *lvData = (ListVersionsData *) callbackData;

    int fit;

    if (data) {
		if (!strcmp(elementPath, "ListVersionsResult/NextKeyMarker")){
			string_buffer_append(lvData->nextKeyMarker, data, dataLen, fit);
		}
		else if (!strcmp(elementPath, "ListVersionsResult/NextVersionIdMarker")){
			string_buffer_append(lvData->nextVersionIdMarker, data, dataLen, fit);
		}
        else if (!strcmp(elementPath, "ListVersionsResult/IsTruncated")) {
            string_buffer_append(lvData->isTruncated, data, dataLen, fit);
        }
		//  add by cwx298983 2016.10.19 Start
		else if (!strcmp(elementPath, "ListVersionsResult/Name")) {
			string_buffer_append(lvData->bucketName, data, dataLen, fit);
		}
		else if (!strcmp(elementPath, "ListVersionsResult/Prefix")) {
			string_buffer_append(lvData->prefix, data, dataLen, fit);
		}
		else if (!strcmp(elementPath, "ListVersionsResult/KeyMarker")) {
			string_buffer_append(lvData->keyMarker, data, dataLen, fit);
		}
		else if (!strcmp(elementPath, "ListVersionsResult/Delimiter")) {
			string_buffer_append(lvData->delimiter, data, dataLen, fit);
		}
		else if (!strcmp(elementPath, "ListVersionsResult/MaxKeys")) {
			string_buffer_append(lvData->maxKeys, data, dataLen, fit);
		}
		//  add by cwx298983 2016.10.19 End
        else if (!strcmp(elementPath, "ListVersionsResult/Version/Key")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
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
		string_buffer_append(versions->key, strTmpOut, strlen(strTmpOut), fit);
		CHECK_NULL_FREE(strTmpSource);
		CHECK_NULL_FREE(strTmpOut);
#else			
            string_buffer_append(versions->key, data, dataLen, fit);
#endif
        }
        else if (!strcmp(elementPath, 
                         "ListVersionsResult/Version/VersionId")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append(versions->versionId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "ListVersionsResult/Version/IsLatest")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append(versions->isLatest, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "ListVersionsResult/Version/LastModified")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append(versions->lastModified, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListVersionsResult/Version/ETag")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append(versions->eTag, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListVersionsResult/Version/Size")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append(versions->size, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListVersionsResult/Version/Owner/ID")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append(versions->ownerId, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "ListVersionsResult/Version/Owner/DisplayName")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append
                (versions->ownerDisplayName, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "ListVersionsResult/Version/StorageClass")) {
            ListBucketVersions *versions = 
                &(lvData->versions[lvData->versionsCount]);
            string_buffer_append
                (versions->storageClass, data, dataLen, fit);
        }
	else if(!strcmp(elementPath,
		"ListVersionsResult/CommonPrefixes/Prefix")) {
		ListCommonPrefixes* commonPrefixes = &(lvData->commonPrefixes[lvData->commonPrefixesCount]);
		string_buffer_append(commonPrefixes->prefix, data, dataLen, fit);
	}
    }
	else {
		if (!strcmp(elementPath, "ListVersionsResult/Version")) {
            // Finished a Version
            lvData->versionsCount++;
            if (lvData->versionsCount == MAX_VERSIONS) {
                // Make the callback
                S3Status status = make_list_versions_callback(lvData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_list_versions_data(lvData);
            }
            else {
                // Initialize the next one
                initialize_list_versions
                    (&(lvData->versions[lvData->versionsCount]));
            }
        }
		if (!strcmp(elementPath, "ListVersionsResult/CommonPrefixes")) {
			// Finished a commonPrefix
			lvData->commonPrefixesCount++;
			if (lvData->commonPrefixesCount == MAX_COMMONPREFIXES)
			{
				// Make the callback
				S3Status status = make_list_versions_callback(lvData);
				if (status != S3StatusOK)
				{
                   			 return status;
                		}
				initialize_list_versions_data(lvData);
			}
			else
			{
				initialize_list_common_prefixes(&(lvData->commonPrefixes[lvData->commonPrefixesCount]));
			}
		}
	}
    
    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status ListVersionsPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    ListVersionsData *lvData = (ListVersionsData *) callbackData;
    
    return (*(lvData->responsePropertiesCallback))
        (responseProperties, lvData->callbackData);
}


static S3Status ListVersionsDataCallback(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    ListVersionsData *lvData = (ListVersionsData *) callbackData;
    
    return simplexml_add(&(lvData->simpleXml), buffer, bufferSize);
}


static void ListVersionsCompleteCallback(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    ListVersionsData *lvData = (ListVersionsData *) callbackData;

    // Make the callback if there is anything
    if (lvData->versionsCount) {

		//Checke return value by jwx329074 2016.11.16
		S3Status callbackResult = make_list_versions_callback(lvData);
		if (callbackResult != S3StatusOK)
		{
			COMMLOG(OBS_LOGERROR, "make_list_versions_callback failed!");
		}
    }

    (*(lvData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, lvData->callbackData);

    simplexml_deinitialize(&(lvData->simpleXml));

    free(lvData);
	lvData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void ListVersions(const S3BucketContext *bucketContext, const char *prefix, const char *keymarker,
					const char *delimiter, int maxkeys, const char *version_id_marker,
                    S3RequestContext *requestContext,
                    const S3ListVersionsHandler *handler, void *callbackData)
{
    SYSTEMTIME reqTime; 
    GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter ListVersions successfully !");
	if(version_id_marker && !strlen(version_id_marker))
	{
		COMMLOG(OBS_LOGERROR, "version_id_marker is \"\"!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");

		return;
	}
	// Compose the query params
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);
		
	/*#define safe_appendm(name, value)                                        \
		do {																\
			int fit;														\
			if (amp) {														\
				string_buffer_append(queryParams, "&", 1, fit); 			\
				if (!fit) { 												\
					(void)(*(handler->responseHandler.completeCallback))			\
						(S3StatusQueryParamsTooLong, 0, callbackData);		\
                                    SYSTEMTIME rspTime;   \
                                    GetLocalTime(&rspTime);   \
	                             INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                                    return; 												\
				}															\
			}																\
			string_buffer_append(queryParams, name "=", 					\
								 sizeof(name "=") - 1, fit);				\
			if (!fit) { 													\
				(void)(*(handler->responseHandler.completeCallback))				\
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
                            SYSTEMTIME rspTime;   \
                            GetLocalTime(&rspTime);   \
	                     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                            return; 													\
			}																\
			amp = 1;														\
			char encoded[3 * 1024] = {0}; 										\
			if (!urlEncode(encoded, value, 1024)) { 						\
				(void)(*(handler->responseHandler.completeCallback))				\
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
                            SYSTEMTIME rspTime;   \
                            GetLocalTime(&rspTime);   \
	                     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                             return; 													\
			}																\
			string_buffer_append(queryParams, encoded, strlen(encoded), 	\
								 fit);										\
			if (!fit) { 													\
				(void)(*(handler->responseHandler.completeCallback))				\
					(S3StatusQueryParamsTooLong, 0, callbackData);			\
                            SYSTEMTIME rspTime;   \
                            GetLocalTime(&rspTime);   \
	                     INTLOG(reqTime, rspTime, S3StatusQueryParamsTooLong, "");   \
                            return; 													\
			}																\
		} while (0)*/
	
	
		int amp = 0;
		if (delimiter) {
			safe_appendm("delimiter", delimiter);
		}
		if (keymarker) {
			safe_appendm("key-marker", keymarker);
		}
		if (maxkeys) {
			if(maxkeys > 1000)maxkeys = 1000;
			char maxKeysString[64] = {0};
			snprintf_s(maxKeysString, sizeof(maxKeysString), _TRUNCATE, "%d", maxkeys);  //secure function
			safe_appendm("max-keys", maxKeysString);
		}
		if (prefix) {
			safe_appendm("prefix", prefix);
		}

		if (version_id_marker)
        {
            safe_appendm("version-id-marker",version_id_marker);
        }
	
		ListVersionsData *lvData =
			(ListVersionsData *) malloc(sizeof(ListVersionsData));
	
		if (!lvData) {
			(void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
			COMMLOG(OBS_LOGERROR, "Malloc ListVersionsData failed !");

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

			return;
		} 
		memset_s(lvData, sizeof(ListVersionsData), 0, sizeof(ListVersionsData));//lint !e516

		if(!bucketContext->bucketName){
			COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
			(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
			//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
			free(lvData);//lint !e516 
			lvData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;
		}
	
		simplexml_initialize(&(lvData->simpleXml), &ListVersionsXmlCallback, lvData);//lint !e119
		
		lvData->responsePropertiesCallback = 
			handler->responseHandler.propertiesCallback;
		lvData->listVersionsCallback = handler->listVersionsCallback;
		lvData->responseCompleteCallback = 
			handler->responseHandler.completeCallback;
		lvData->callbackData = callbackData;
	
		string_buffer_initialize(lvData->isTruncated);
		string_buffer_initialize(lvData->nextKeyMarker);
		string_buffer_initialize(lvData->nextVersionIdMarker);
		initialize_list_versions_data(lvData);
	
		// Set up the RequestParams
		RequestParams params =
		{
			HttpRequestTypeGET, 						  // httpRequestType
			{ bucketContext->hostName,                    // hostName
			  bucketContext->bucketName,                  // bucketName
			  bucketContext->protocol,                    // protocol
			  bucketContext->uriStyle,                    // uriStyle
			  bucketContext->accessKeyId,                 // accessKeyId
			  bucketContext->secretAccessKey,             // secretAccessKey
			  bucketContext->certificateInfo },           // certificateInfo
			0,											  // key
			queryParams[0] ? queryParams : 0,			  // queryParams
			"versions",									  // subResource
			0,											  // copySourceBucketName
			0,											  // copySourceKey
			0,											  // getConditions
			0,											  // startByte
			0,											  // byteCount
			0,											  // corsConf
			0,											  // putProperties
			0,                                            // ServerSideEncryptionParams
			&ListVersionsPropertiesCallback,			  // propertiesCallback
			0,											  // toS3Callback
			0,											  // toS3CallbackTotalSize
			&ListVersionsDataCallback,					  // fromS3Callback
			&ListVersionsCompleteCallback,				  // completeCallback
			lvData,										  // callbackData
			bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
		};
	
		// Perform the request
		request_perform(&params, requestContext);
		COMMLOG(OBS_LOGINFO, "Leave ListVersions successfully !");

              SYSTEMTIME rspTime; 
              GetLocalTime(&rspTime);
              INTLOG(reqTime, rspTime, S3StatusOK, "");
        
}

// set cors -------------------------------------------------------------
//lint -e601
typedef struct SetBucketCorsConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char doc[1024*100];
    int docLen, docBytesWritten;
}SetBucketCorsConfigurationData;                         
//lint +e601                            

static S3Status SetBucketCorsConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    SetBucketCorsConfigurationData *sbccData = (SetBucketCorsConfigurationData *) callbackData;
    
    return (*(sbccData->responsePropertiesCallback))
        (responseProperties, sbccData->callbackData);
}


static int SetBucketCorsConfigurationDataCallback(int bufferSize, char *buffer, void *callbackData)
{
    SetBucketCorsConfigurationData *sbccData = (SetBucketCorsConfigurationData *) callbackData;

    if (!sbccData->docLen) {
        return 0;
    }

    int remaining = (sbccData->docLen - sbccData->docBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, bufferSize, &(sbccData->doc[sbccData->docBytesWritten]), toCopy);//lint !e516

    sbccData->docBytesWritten += toCopy;

    return toCopy;
}


static void SetBucketCorsConfigurationCompleteCallback(S3Status requestStatus, 
                                         const S3ErrorDetails *s3ErrorDetails,
                                         void *callbackData)
{//lint !e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketCorsConfigurationData *sbccData = (SetBucketCorsConfigurationData *) callbackData;

    (void)(*(sbccData->responseCompleteCallback))(requestStatus, s3ErrorDetails, sbccData->callbackData);

    free(sbccData);//lint !e516
	sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);
}
//lint -e601
void SetBucketCorsConfiguration(const S3BucketContext *bucketContext, const char* id,const char (*allowedMethod)[10],const unsigned int amNumber,
                      const char (*allowedOrigin)[256],const unsigned int aoNumber,const char (*allowedHeader)[256],const unsigned int ahNumber,
                      const char *maxAgeSeconds,const char (*exposeHeader)[256],const unsigned int ehNumber,const char* md5,
                      S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData)//lint +e601
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketCorsConfigurationData *sbccData = 
        (SetBucketCorsConfigurationData *) malloc(sizeof(SetBucketCorsConfigurationData));
    if (!sbccData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketCorsConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
		return;
    }
	memset_s(sbccData, sizeof(SetBucketCorsConfigurationData), 0, sizeof(SetBucketCorsConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(sbccData);//lint !e516
		sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if((ahNumber + amNumber + aoNumber + ehNumber) > 100)
	{
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "ahNumber + amNumber + aoNumber + ehNumber is greater than 100 !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 (ahNumber + amNumber + aoNumber + ehNumber) > 100的时候不能直接退出，要先释放内存再return
		free(sbccData);//lint !e516
		sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(NULL == allowedMethod || NULL == allowedOrigin)
	{
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "allowedMethod or allowedOrigin is NULL");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		free(sbccData);//lint !e516
		sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    sbccData->responsePropertiesCallback = handler->propertiesCallback;
    sbccData->responseCompleteCallback = handler->completeCallback;
    sbccData->callbackData = callbackData;

    sbccData->docLen = 0;
    sbccData->docBytesWritten = 0;

    sbccData->docLen += snprintf_s(sbccData->doc, sizeof(sbccData->doc), _TRUNCATE,   //secure function
                     "<CORSConfiguration><CORSRule>");
	int mark = 0;
	if(id)
    {   
		//cheack array index by jwx329074 2016.11.17
		if (sbccData->docLen < 0)
		{
			COMMLOG(OBS_LOGERROR, "snprintf_s failed !");
			free(sbccData);//lint !e516
			sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;
		}
		char*pid=0; 
		mark = pcre_replace(id,&pid);
        sbccData->docLen +=
            snprintf_s(sbccData->doc + sbccData->docLen, sizeof(sbccData->doc) - sbccData->docLen, _TRUNCATE,  //secure function
                     "<ID>%s</ID>",mark ? pid : id);
		if(mark)
		{
			free(pid);//lint !e516
			pid = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}        
    }
    unsigned int uiLen = strlen(sbccData->doc);
    unsigned int uiIdx = 0;
	//lint -e409 -e574
    for(uiIdx = 0; uiIdx < amNumber; uiIdx++)
    {
        if(NULL != allowedMethod[uiIdx])
        {
        	char*pallowedMethod = 0;
			mark = pcre_replace(allowedMethod[uiIdx],&pallowedMethod);
            sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,  //secure function
                     "<AllowedMethod>%s</AllowedMethod>", mark ? pallowedMethod : allowedMethod[uiIdx]);
 
            uiLen = strlen(sbccData->doc);
			if(mark)
			{
				free(pallowedMethod);//lint !e516
				pallowedMethod = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
			
        }

		if((sbccData->docLen >= 1024*10) && (uiIdx != (amNumber -1)))
		{
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
			free(sbccData);//lint !e516
			sbccData = NULL;
			return;
		}
    }
    for(uiIdx = 0; uiIdx < aoNumber; uiIdx++)
    {
        if(NULL != allowedOrigin[uiIdx])
        {
        	char*pallowedOrigin = 0;
			mark = pcre_replace(allowedOrigin[uiIdx],&pallowedOrigin);
            sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,  //secure function
                     "<AllowedOrigin>%s</AllowedOrigin>",  mark ? pallowedOrigin : allowedOrigin[uiIdx]);
 
            uiLen = strlen(sbccData->doc);
			if(mark)
			{
				free(pallowedOrigin);//lint !e516
				pallowedOrigin = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
        }

		if((sbccData->docLen >= 1024*10) && (uiIdx != (aoNumber -1)))
    	{
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
			//zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			free(sbccData);//lint !e516
			sbccData = NULL;
			return;
		}
    }
    for(uiIdx = 0; uiIdx < ahNumber; uiIdx++)
    {
        if(NULL != allowedHeader[uiIdx])
        {
	       	char*pallowedHeader = 0;
			mark = pcre_replace(allowedHeader[uiIdx],&pallowedHeader);
         	sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,  //secure function
                     "<AllowedHeader>%s</AllowedHeader>", mark ? pallowedHeader : allowedHeader[uiIdx]);
 
            uiLen = strlen(sbccData->doc);
			if(mark)
			{
				free(pallowedHeader);//lint !e516
				pallowedHeader = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
        }

		if((sbccData->docLen >= 1024*10) && (uiIdx != (ahNumber -1)))
    	{
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
			//zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			free(sbccData);//lint !e516    
			sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;
		}
    }
	if(maxAgeSeconds)
    {    
		char*pmaxAgeSeconds = 0;
		mark = pcre_replace(maxAgeSeconds,&pmaxAgeSeconds);
		sbccData->docLen +=
		snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,  //secure function
					"<MaxAgeSeconds>%s</MaxAgeSeconds>", mark ? pmaxAgeSeconds : maxAgeSeconds);
		uiLen = strlen(sbccData->doc);
		if(mark)
		{
			free(pmaxAgeSeconds);//lint !e516 
			pmaxAgeSeconds = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		}
    }
    for(uiIdx = 0; uiIdx < ehNumber; uiIdx++)
    {
        if(NULL != exposeHeader[uiIdx])
        {
	       	char* pexposeHeader = 0;
			mark = pcre_replace(exposeHeader[uiIdx],&pexposeHeader);
            sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,  //secure function
                     "<ExposeHeader>%s</ExposeHeader>", mark ? pexposeHeader : exposeHeader[uiIdx]);
			//lint +e409
            uiLen = strlen(sbccData->doc);
			if(mark)
			{
				free(pexposeHeader);//lint !e516
				pexposeHeader = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}
        }

		if((sbccData->docLen >= 1024*10) && (uiIdx != (ehNumber -1)))
    	{
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
			//zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			free(sbccData);//lint !e516 
			sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			return;
		}
    }//lint +e574

    sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,  //secure function
                     "</CORSRule></CORSConfiguration>");
	if((sbccData->docLen >= 1024*10))
   	{
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.10.08 不能直接退出，要先释放内存再return
		free(sbccData);//lint !e516  
		sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
    

   // Set up S3PutProperties
    S3PutProperties properties =
    {
        0,                                       // contentType
        md5,                                       // md5
        0,                                       // cacheControl
        0,                                       // contentDispositionFilename
        0,                                       // contentEncoding
        0,										 //storagepolicy
        0,										 //websiteredirectlocation
        0,										 //getConditions
        0,										 //startByte
        0,										 //byteCount
        0,                                       // expires
        S3CannedAclPrivate,                      // cannedAcl
        0,                                       // metaDataCount
        0,                                       // metaData
        0                                        // useServerSideEncryption
    };
	// Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,								// httpRequestType
        { bucketContext->hostName,						// hostName
          bucketContext->bucketName,					// bucketName
          bucketContext->protocol,						// protocol
          bucketContext->uriStyle,						// uriStyle
          bucketContext->accessKeyId,					// accessKeyId
          bucketContext->secretAccessKey,				// secretAccessKey
          bucketContext->certificateInfo },				// certificateInfo
        0,												// key
        0,												// queryParams
        "cors",											// subResource
        0,												// copySourceBucketName
        0,												// copySourceKey
        0,												// getConditions
        0,												// startByte
        0,												// byteCount
		0,												// corsConf
        &properties,									// putProperties
		0,                                              // ServerSideEncryptionParams
        &SetBucketCorsConfigurationPropertiesCallback,	// propertiesCallback
        &SetBucketCorsConfigurationDataCallback,		// toS3Callback
        sbccData->docLen,								// toS3CallbackTotalSize
        0,												// fromS3Callback
        &SetBucketCorsConfigurationCompleteCallback,	// completeCallback
        sbccData,										// callbackData
		bucketContext->certificateInfo ? 1 : 0			// isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");


}

void SetBucketCorsConfigurationEx(const S3BucketContext *bucketContext, S3BucketCorsConf* bucketCorsConf, const unsigned int bccNumber, const char* md5,
                      S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetBucketCorsConfigurationData *sbccData = 
        (SetBucketCorsConfigurationData *) malloc(sizeof(SetBucketCorsConfigurationData));
    if (!sbccData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetBucketCorsConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");
    
		return;
    }
	memset_s(sbccData, sizeof(SetBucketCorsConfigurationData), 0, sizeof(SetBucketCorsConfigurationData));//lint !e516

	if(!bucketContext->bucketName)
	{
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(sbccData);//lint !e516    
		sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	if(bccNumber > 100)
	{
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "The number of rules is greater than 100 !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 bccNumber > 100的时候不能直接退出，要先释放内存再return
		free(sbccData);//lint !e516    
		sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    sbccData->responsePropertiesCallback = handler->propertiesCallback;
    sbccData->responseCompleteCallback = handler->completeCallback;
    sbccData->callbackData = callbackData;

    sbccData->docLen = 0;
    sbccData->docBytesWritten = 0;

    sbccData->docLen += snprintf_s(sbccData->doc, sizeof(sbccData->doc), _TRUNCATE,    //secure function
                     "<CORSConfiguration>");

	unsigned int i = 0;
	unsigned int uiLen = strlen(sbccData->doc);
	unsigned int uiIdx = 0;
	//lint -e409 -e574
	for (i = 0; i< bccNumber; ++i)
	{
		if(NULL == bucketCorsConf[i].allowedMethod || NULL == bucketCorsConf[i].allowedOrigin)
		{
			(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);
			COMMLOG(OBS_LOGERROR, "allowedMethod or allowedOrigin is NULL");

			SYSTEMTIME rspTime; 
			GetLocalTime(&rspTime);
			INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
			//zwx367245 2016.09.30 参数不正确不能直接退出，要先释放内存再return
			free(sbccData);//lint !e516
			sbccData = NULL;
			return;
		}

		sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
                     "<CORSRule>");
		int mark = 0;
		if(bucketCorsConf[i].id)
		{   
			//cheack array index by jwx329074 2016.11.17
			if (sbccData->docLen < 0)
			{
				COMMLOG(OBS_LOGERROR, "snprintf_s error!");
				free(sbccData);//lint !e516
				sbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				return;
			}
			char*pid=0; 
			mark = pcre_replace(bucketCorsConf[i].id,&pid);
			sbccData->docLen +=
		       snprintf_s(sbccData->doc + sbccData->docLen, sizeof(sbccData->doc) - sbccData->docLen, _TRUNCATE,    //secure function
		                 "<ID>%s</ID>",mark ? pid : bucketCorsConf[i].id);
			
			uiLen = strlen(sbccData->doc);
			
			if(mark)
			{
				free(pid);//lint !e516
				pid = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			}        
		}
		
		for(uiIdx=0; uiIdx < bucketCorsConf[i].amNumber; uiIdx++)
		{
			if(NULL != bucketCorsConf[i].allowedMethod[uiIdx])
			{
				char*pallowedMethod = 0;
				mark = pcre_replace(bucketCorsConf[i].allowedMethod[uiIdx],&pallowedMethod);
				sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
						"<AllowedMethod>%s</AllowedMethod>", mark ? pallowedMethod : bucketCorsConf[i].allowedMethod[uiIdx]);

				uiLen = strlen(sbccData->doc);
				if(mark)
				{
					free(pallowedMethod);//lint !e516
					pallowedMethod = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}

			if((sbccData->docLen >= 1024*10) && (uiIdx != (bucketCorsConf[i].amNumber -1)))
			{
				(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

				SYSTEMTIME rspTime; 
				GetLocalTime(&rspTime);
				INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
				//zwx367245 2016.09.30 参数不正确不能直接退出，要先释放内存再return
				free(sbccData);//lint !e516    
				sbccData = NULL;
				return;
			}
		}
		for(uiIdx = 0; uiIdx < bucketCorsConf[i].aoNumber; uiIdx++)
		{
			if(NULL != bucketCorsConf[i].allowedOrigin[uiIdx])
			{
				char*pallowedOrigin = 0;
				mark = pcre_replace(bucketCorsConf[i].allowedOrigin[uiIdx],&pallowedOrigin);
				sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
				"<AllowedOrigin>%s</AllowedOrigin>",  mark ? pallowedOrigin : bucketCorsConf[i].allowedOrigin[uiIdx]);

				uiLen = strlen(sbccData->doc);
				if(mark)
				{
					free(pallowedOrigin);//lint !e516
					pallowedOrigin = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}

			if((sbccData->docLen >= 1024*10) && (uiIdx != (bucketCorsConf[i].aoNumber -1)))
			{
				(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

				SYSTEMTIME rspTime; 
				GetLocalTime(&rspTime);
				INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
				//zwx367245 2016.09.30 参数不正确不能直接退出，要先释放内存再return
				free(sbccData);//lint !e516
				sbccData = NULL;
				return;
			}
		}
		for(uiIdx = 0; uiIdx < bucketCorsConf[i].ahNumber; uiIdx++)
		{
			if(NULL != bucketCorsConf[i].allowedHeader[uiIdx])
			{
				char*pallowedHeader = 0;
				mark = pcre_replace(bucketCorsConf[i].allowedHeader[uiIdx],&pallowedHeader);
				sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
				"<AllowedHeader>%s</AllowedHeader>", mark ? pallowedHeader : bucketCorsConf[i].allowedHeader[uiIdx]);

				uiLen = strlen(sbccData->doc);
				if(mark)
				{
					free(pallowedHeader);//lint !e516
					pallowedHeader = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}

			if((sbccData->docLen >= 1024*10) && (uiIdx != (bucketCorsConf[i].ahNumber -1)))
			{
				(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

				SYSTEMTIME rspTime; 
				GetLocalTime(&rspTime);
				INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
				//zwx367245 2016.09.30 参数不正确不能直接退出，要先释放内存再return
				free(sbccData);//lint !e516    
				sbccData = NULL;
				return;
			}
		}
		if(bucketCorsConf[i].maxAgeSeconds)
		{    
			char*pmaxAgeSeconds = 0;
			mark = pcre_replace(bucketCorsConf[i].maxAgeSeconds,&pmaxAgeSeconds);
		    	sbccData->docLen +=
		        snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
		                 "<MaxAgeSeconds>%s</MaxAgeSeconds>", mark ? pmaxAgeSeconds : bucketCorsConf[i].maxAgeSeconds);
			 uiLen = strlen(sbccData->doc);
			 if(mark)
			 {
				 free(pmaxAgeSeconds);//lint !e516
				 pmaxAgeSeconds = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
			 }
		}
		for(uiIdx = 0; uiIdx < bucketCorsConf[i].ehNumber; uiIdx++)
		{
			if(NULL != bucketCorsConf[i].exposeHeader[uiIdx])
			{
			   	char*pexposeHeader = 0;
				mark = pcre_replace(bucketCorsConf[i].exposeHeader[uiIdx],&pexposeHeader);
			    sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
			             "<ExposeHeader>%s</ExposeHeader>", mark ? pexposeHeader : bucketCorsConf[i].exposeHeader[uiIdx]);

			    uiLen = strlen(sbccData->doc);
				if(mark)
				{
					free(pexposeHeader);//lint !e516 
					pexposeHeader = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
				}
			}

			if((sbccData->docLen >= 1024*10) && (uiIdx != (bucketCorsConf[i].ehNumber -1)))
			{//lint +e409
				(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

				SYSTEMTIME rspTime; 
				GetLocalTime(&rspTime);
				INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
				//zwx367245 2016.09.30 参数不正确不能直接退出，要先释放内存再return
				free(sbccData);//lint !e516
				sbccData = NULL;
				return;
			}
    	}
		sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
                     "</CORSRule>");
		uiLen = strlen(sbccData->doc);
	}//lint +e574


    sbccData->docLen += snprintf_s(sbccData->doc + uiLen, sizeof(sbccData->doc) - uiLen, _TRUNCATE,    //secure function
                     "</CORSConfiguration>");
	if((sbccData->docLen >= 1024*10))
   	{
		(void)(*(handler->completeCallback))(S3StatusInvalidParameter, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidParameter, "");
		//zwx367245 2016.09.30 参数不正确不能直接退出，要先释放内存再return
		free(sbccData);//lint !e516
		sbccData = NULL;
		return;
	}
    

   // Set up S3PutProperties
    S3PutProperties properties =
    {
        0,                                       // contentType
        md5,                                       // md5
        0,                                       // cacheControl
        0,                                       // contentDispositionFilename
        0,                                       // contentEncoding
        0,										 //storagepolicy
        0,										 //websiteredirectlocation
        0,										 //getConditions
        0,										 //startByte
        0,										 //byteCount
        0,                                       // expires
        S3CannedAclPrivate,                      // cannedAcl
        0,                                       // metaDataCount
        0,                                       // metaData
        0                                        // useServerSideEncryption
    };
        // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,								// httpRequestType
        { bucketContext->hostName,						// hostName
          bucketContext->bucketName,					// bucketName
          bucketContext->protocol,						// protocol
          bucketContext->uriStyle,						// uriStyle
          bucketContext->accessKeyId,					// accessKeyId
          bucketContext->secretAccessKey,				// secretAccessKey
          bucketContext->certificateInfo },				// certificateInfo
        0,												// key
        0,												// queryParams
        "cors",											// subResource
        0,												// copySourceBucketName
        0,												// copySourceKey
        0,												// getConditions
        0,												// startByte
        0,												// byteCount
		0,												// corsConf
        &properties,									// putProperties
		0,                                              // ServerSideEncryptionParams
        &SetBucketCorsConfigurationPropertiesCallback,	// propertiesCallback
        &SetBucketCorsConfigurationDataCallback,		// toS3Callback
        sbccData->docLen,								// toS3CallbackTotalSize
        0,												// fromS3Callback
        &SetBucketCorsConfigurationCompleteCallback,	// completeCallback
        sbccData,										// callbackData
		bucketContext->certificateInfo ? 1 : 0			// isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");

}

//DeleteBucketCorsConfiguration-----------------------------------------------------------------
//lint -e601
typedef struct DeleteBucketCorsConfigurationData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;
} DeleteBucketCorsConfigurationData;
//lint +e601

static S3Status DeleteBucketCorsConfigurationPropertiesCallback(const S3ResponseProperties *responseProperties, void *callbackData)/*lint !e31 */
{
    DeleteBucketCorsConfigurationData *dbccData = (DeleteBucketCorsConfigurationData *) callbackData;
    
    return (*(dbccData->responsePropertiesCallback))
        (responseProperties, dbccData->callbackData);
}


static void DeleteBucketCorsConfigurationCompleteCallback(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    DeleteBucketCorsConfigurationData *dbccData = (DeleteBucketCorsConfigurationData *) callbackData;

    (*(dbccData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, dbccData->callbackData);

    free(dbccData);//lint !e516
	dbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void DeleteBucketCorsConfiguration(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    // Create the callback data
    DeleteBucketCorsConfigurationData *dbccData = 
        (DeleteBucketCorsConfigurationData *) malloc(sizeof(DeleteBucketCorsConfigurationData));
    if (!dbccData) {
		(void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc DeleteBucketCorsConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(dbccData, sizeof(DeleteBucketCorsConfigurationData), 0, sizeof(DeleteBucketCorsConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	   INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
	   //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
       free(dbccData);//lint !e516
	   dbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
       return;
	}

    dbccData->responsePropertiesCallback = handler->propertiesCallback;
    dbccData->responseCompleteCallback = handler->completeCallback;
    dbccData->callbackData = callbackData;

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeDELETE,								// httpRequestType
        { bucketContext->hostName,							// hostName
          bucketContext->bucketName,						// bucketName
          bucketContext->protocol,							// protocol
          bucketContext->uriStyle,							// uriStyle
          bucketContext->accessKeyId,						// accessKeyId
          bucketContext->secretAccessKey,					// secretAccessKey
          bucketContext->certificateInfo },					// certificateInfo
        0,													// key
        0,													// queryParams
        "cors",												// subResource
        0,													// copySourceBucketName
        0,													// copySourceKey
        0,													// getConditions
        0,													// startByte
        0,													// byteCount
		0,													// corsConf
        0,													// putProperties
		0,                                                  // ServerSideEncryptionParams
        &DeleteBucketCorsConfigurationPropertiesCallback,   // propertiesCallback
        0,													// toS3Callback
        0,													// toS3CallbackTotalSize
        0,													// fromS3Callback
        &DeleteBucketCorsConfigurationCompleteCallback,     // completeCallback
        dbccData,											// callbackData
		bucketContext->certificateInfo ? 1 : 0				// isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}


// Get Bucket Cors Configuration ----------------------------------------------------------------

#define MAX_CORSRULE 100

//lint -e601
typedef struct GetBucketCorsConfigurationData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3GetBucketCorsConfigurationCallback *getBucketCorsConfigurationCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    string_buffer(id, 256);
    string_buffer(maxAgeSeconds, 100);

    int allowedMethodCount;
    char allowedMethodes[MAX_CORSRULE][1024];
    int allowedMethodLens[MAX_CORSRULE];

    int allowedOriginCount;
    char allowedOrigines[MAX_CORSRULE][1024];
    int allowedOriginLens[MAX_CORSRULE];

    int allowedHeaderCount;
    char allowedHeaderes[MAX_CORSRULE][1024];
    int allowedHeaderLens[MAX_CORSRULE];

    int exposeHeaderCount;
    char exposeHeaderes[MAX_CORSRULE][1024];
    int exposeHeaderLens[MAX_CORSRULE];
}GetBucketCorsConfigurationData;
//lint +e601

static void initialize_get_cors_data(GetBucketCorsConfigurationData *gbccData)
{
    gbccData->allowedHeaderCount= 0;
    gbccData->allowedHeaderes[0][0] = 0;
    gbccData->allowedHeaderLens[0] = 0;
	
    gbccData->allowedMethodCount= 0;
    gbccData->allowedMethodes[0][0] = 0;
    gbccData->allowedMethodLens[0] = 0;
	
    gbccData->allowedOriginCount= 0;
    gbccData->allowedOrigines[0][0] = 0;
    gbccData->allowedOriginLens[0] = 0;
	
    gbccData->exposeHeaderCount= 0;
    gbccData->exposeHeaderes[0][0] = 0;
    gbccData->exposeHeaderLens[0] = 0;
	
}
static S3Status make_get_cors_callback(GetBucketCorsConfigurationData *gbccData)/*lint !e31 */
{
	S3Status iRet = S3StatusOK;

    int allowedHeaderCount = gbccData->allowedHeaderCount;
	if(allowedHeaderCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusInternalError;
	}
	char **allowedHeaderes = (char **)malloc(sizeof(char *) * allowedHeaderCount);
	if (NULL == allowedHeaderes) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc allowedHeaderes failed!");
		return S3StatusInternalError;
	}

	memset_s(allowedHeaderes, sizeof(char *) * allowedHeaderCount, 0, sizeof(char *) * allowedHeaderCount);
    int i;
	for (i = 0; i < allowedHeaderCount; i++) {
        allowedHeaderes[i] = gbccData->allowedHeaderes[i];
    }

    int allowedMethodCount = gbccData->allowedMethodCount;
	if(allowedMethodCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		CHECK_NULL_FREE(allowedHeaderes);    //zwx367245 2016.09.30 不能直接退出，要先释放内存再return
		return S3StatusInternalError;
	}
	char **allowedMethodes = (char **)malloc(sizeof(char *) * allowedMethodCount);
	if (NULL == allowedMethodes) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc allowedMethodes failed!");
		CHECK_NULL_FREE(allowedHeaderes);
		return S3StatusInternalError;
	}
	memset_s(allowedMethodes, sizeof(char *) * allowedMethodCount, 0, sizeof(char *) * allowedMethodCount);
    for (i = 0; i < allowedMethodCount; i++) {
        allowedMethodes[i] = gbccData->allowedMethodes[i];
    }

    int allowedOriginCount = gbccData->allowedOriginCount;
	if(allowedOriginCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		CHECK_NULL_FREE(allowedHeaderes);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
		CHECK_NULL_FREE(allowedMethodes);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
		return S3StatusInternalError;
	}
	char **allowedOrigines = (char **)malloc(sizeof(char *) * allowedOriginCount);
	if (NULL == allowedOrigines) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc allowedOrigines failed!");
		CHECK_NULL_FREE(allowedHeaderes);
		CHECK_NULL_FREE(allowedMethodes);
		return S3StatusInternalError;
	}
	memset_s(allowedOrigines, sizeof(char *) * allowedOriginCount, 0, sizeof(char *) * allowedOriginCount);
    for (i = 0; i < allowedOriginCount; i++) {
        allowedOrigines[i] = gbccData->allowedOrigines[i];
    }

    int exposeHeaderCount = gbccData->exposeHeaderCount;
	if(exposeHeaderCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		CHECK_NULL_FREE(allowedHeaderes);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
		CHECK_NULL_FREE(allowedMethodes);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
		CHECK_NULL_FREE(allowedOrigines);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
		return S3StatusInternalError;
	}
	char **exposeHeaderes = (char **)malloc(sizeof(char *) * exposeHeaderCount);
	if (NULL == exposeHeaderes) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc exposeHeaderes failed!");
		CHECK_NULL_FREE(allowedHeaderes);
		CHECK_NULL_FREE(allowedMethodes);
		CHECK_NULL_FREE(allowedOrigines);
		return S3StatusInternalError;
	}
	memset_s(exposeHeaderes, sizeof(char *) * exposeHeaderCount, 0, sizeof(char *) * exposeHeaderCount);
    for (i = 0; i < exposeHeaderCount; i++) {
        exposeHeaderes[i] = gbccData->exposeHeaderes[i];
    }

	iRet = (*(gbccData->getBucketCorsConfigurationCallback))
		(gbccData->id, gbccData->maxAgeSeconds,allowedMethodCount,(const char **)allowedMethodes,allowedOriginCount,(const char **)allowedOrigines,
		allowedHeaderCount,(const char **) allowedHeaderes,exposeHeaderCount,(const char **) exposeHeaderes, gbccData->callbackData);

	CHECK_NULL_FREE(allowedHeaderes);
	CHECK_NULL_FREE(allowedMethodes);
	CHECK_NULL_FREE(allowedOrigines);
	CHECK_NULL_FREE(exposeHeaderes);	

    return iRet;
}

static S3Status GetBucketCorsConfigurationXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    GetBucketCorsConfigurationData *gbccData = (GetBucketCorsConfigurationData *) callbackData;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "CORSConfiguration/CORSRule/ID")) {
            string_buffer_append(gbccData->id, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "CORSConfiguration/CORSRule/MaxAgeSeconds")) {
            string_buffer_append(gbccData->maxAgeSeconds, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/AllowedMethod")) {
            int which = gbccData->allowedMethodCount;
            gbccData->allowedMethodLens[which] +=
                snprintf_s(gbccData->allowedMethodes[which], sizeof(gbccData->allowedMethodes[which]),  //secure function
                         sizeof(gbccData->allowedMethodes[which]) -
                         gbccData->allowedMethodLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccData->allowedMethodLens[which] >=
                (int) sizeof(gbccData->allowedMethodes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/AllowedOrigin")) {
            int which = gbccData->allowedOriginCount;
            gbccData->allowedOriginLens[which] +=
                snprintf_s(gbccData->allowedOrigines[which], sizeof(gbccData->allowedOrigines[which]),  //secure function
                         sizeof(gbccData->allowedOrigines[which]) -
                         gbccData->allowedOriginLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccData->allowedOriginLens[which] >=
                (int) sizeof(gbccData->allowedOrigines[which])) {
                return S3StatusXmlParseFailure;
            }
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/AllowedHeader")) {
            int which = gbccData->allowedHeaderCount;
            gbccData->allowedHeaderLens[which] +=
                snprintf_s(gbccData->allowedHeaderes[which], sizeof(gbccData->allowedHeaderes[which]),  //secure function
                         sizeof(gbccData->allowedHeaderes[which]) -
                         gbccData->allowedHeaderLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccData->allowedHeaderLens[which] >=
                (int) sizeof(gbccData->allowedHeaderes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/ExposeHeader")) {
            int which = gbccData->exposeHeaderCount;
            gbccData->exposeHeaderLens[which] +=
                snprintf_s(gbccData->exposeHeaderes[which], sizeof(gbccData->exposeHeaderes[which]),  //secure function
                         sizeof(gbccData->exposeHeaderes[which]) -
                         gbccData->exposeHeaderLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccData->exposeHeaderLens[which] >=
                (int) sizeof(gbccData->exposeHeaderes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
    }
    else {
         if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/AllowedMethod")) {
            // Finished a Prefix
            gbccData->allowedMethodCount++;
            if (gbccData->allowedMethodCount == MAX_COMMON_PREFIXES) {
                // Make the callback
                S3Status status = make_get_cors_callback(gbccData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_get_cors_data(gbccData);
            }
            else {
                // Initialize the next one
                gbccData->allowedMethodes[gbccData->allowedMethodCount][0] = 0;
                gbccData->allowedMethodLens[gbccData->allowedMethodCount] = 0;
            }
        }
         else if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/AllowedOrigin")) {
            // Finished a Prefix
            gbccData->allowedOriginCount++;
            if (gbccData->allowedOriginCount == MAX_COMMON_PREFIXES) {
                // Make the callback
                S3Status status = make_get_cors_callback(gbccData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_get_cors_data(gbccData);
            }
            else {
                // Initialize the next one
                gbccData->allowedOrigines[gbccData->allowedOriginCount][0] = 0;
                gbccData->allowedOriginLens[gbccData->allowedOriginCount] = 0;
            }
        }
         else if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/AllowedHeader")) {
            // Finished a Prefix
            gbccData->allowedHeaderCount++;
            if (gbccData->allowedHeaderCount == MAX_COMMON_PREFIXES) {
                // Make the callback
                S3Status status = make_get_cors_callback(gbccData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_get_cors_data(gbccData);
            }
            else {
                // Initialize the next one
                gbccData->allowedHeaderes[gbccData->allowedHeaderCount][0] = 0;
                gbccData->allowedHeaderLens[gbccData->allowedHeaderCount] = 0;
            }
        }
         else if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/ExposeHeader")) {
            // Finished a Prefix
            gbccData->exposeHeaderCount++;
            if (gbccData->exposeHeaderCount == MAX_COMMON_PREFIXES) {
                // Make the callback
                S3Status status = make_get_cors_callback(gbccData);
                if (status != S3StatusOK) {
                    return status;
                }
                initialize_get_cors_data(gbccData);
            }
            else {
                // Initialize the next one
                gbccData->exposeHeaderes[gbccData->exposeHeaderCount][0] = 0;
                gbccData->exposeHeaderLens[gbccData->exposeHeaderCount] = 0;
            }
        }
    }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}


static S3Status GetBucketCorsConfigurationPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketCorsConfigurationData *gbccData = (GetBucketCorsConfigurationData *) callbackData;
    
    return (*(gbccData->responsePropertiesCallback))
        (responseProperties, gbccData->callbackData);
}


static S3Status GetBucketCorsConfigurationDataCallback(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    GetBucketCorsConfigurationData *gbccData = (GetBucketCorsConfigurationData *) callbackData;
    
    return simplexml_add(&(gbccData->simpleXml), buffer, bufferSize);
}


static void GetBucketCorsConfigurationCompleteCallback(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);
    GetBucketCorsConfigurationData *gbccData = (GetBucketCorsConfigurationData *) callbackData;

    // Make the callback if there is anything
    if (gbccData->allowedHeaderCount || gbccData->allowedMethodCount || gbccData->allowedOriginCount|| gbccData->exposeHeaderCount) {

		//Checke return value by jwx329074 2016.11.16
        S3Status callbackResult = make_get_cors_callback(gbccData);
		if (callbackResult != S3StatusOK)
		{
			COMMLOG(OBS_LOGERROR, "make_get_cors_callback failed!");
		}
    }

    (*(gbccData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gbccData->callbackData);

    simplexml_deinitialize(&(gbccData->simpleXml));

    free(gbccData);
	gbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void GetBucketCorsConfiguration(const S3BucketContext *bucketContext, 
                    S3RequestContext *requestContext,
                    const S3CORSHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketCorsConfigurationData *gbccData =
        (GetBucketCorsConfigurationData *) malloc(sizeof(GetBucketCorsConfigurationData));

    if (!gbccData) {
        (void)(*(handler->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketCorsConfigurationData failed !");

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

        return;
    }
	memset_s(gbccData, sizeof(GetBucketCorsConfigurationData), 0, sizeof(GetBucketCorsConfigurationData));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handler->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		free(gbccData);//lint !e516
		gbccData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gbccData->simpleXml), &GetBucketCorsConfigurationXmlCallback, gbccData);//lint !e119
    
    gbccData->responsePropertiesCallback = 
        handler->responseHandler.propertiesCallback;
    gbccData->getBucketCorsConfigurationCallback= handler->getBucketCorsConfigurationCallback;
    gbccData->responseCompleteCallback = 
        handler->responseHandler.completeCallback;
    gbccData->callbackData = callbackData;

    string_buffer_initialize(gbccData->id);
    string_buffer_initialize(gbccData->maxAgeSeconds);
    initialize_get_cors_data(gbccData);

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
        0,                                            // key
        0,								              // queryParams
        "cors",                                       // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketCorsConfigurationPropertiesCallback,// propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketCorsConfigurationDataCallback,      // fromS3Callback
        &GetBucketCorsConfigurationCompleteCallback,  // completeCallback
        gbccData,                                     // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}

// Get Bucket Cors ConfigurationEx ----------------------------------------------------------------

#define MAX_COUNT 20

typedef struct BucketCorsConfData
{
    string_buffer(id, 256);
    string_buffer(maxAgeSeconds, 100);

    int allowedMethodCount;
    char allowedMethodes[MAX_COUNT][1024];
    int allowedMethodLens[MAX_COUNT];

    int allowedOriginCount;
    char allowedOrigines[MAX_COUNT][1024];
    int allowedOriginLens[MAX_COUNT];

    int allowedHeaderCount;
    char allowedHeaderes[MAX_COUNT][1024];
    int allowedHeaderLens[MAX_COUNT];

    int exposeHeaderCount;
    char exposeHeaderes[MAX_COUNT][1024];
    int exposeHeaderLens[MAX_COUNT];
}BucketCorsConfData;

//lint -e601
typedef struct GetBucketCorsConfigurationDataEx
{
	SimpleXml simpleXml;

	S3ResponsePropertiesCallback *responsePropertiesCallback;
	S3GetBucketCorsConfigurationCallbackEx *getBucketCorsConfigurationCallbackEx;
	S3ResponseCompleteCallback *responseCompleteCallback;
	void *callbackData;

	BucketCorsConfData* bccData[MAX_CORSRULE];

	unsigned int bccdNumber;
	
}GetBucketCorsConfigurationDataEx;
//lint +e601

static S3Status make_get_cors_callbackEx(GetBucketCorsConfigurationDataEx *gbccDataEx)/*lint !e31 */
{
	S3Status iRet = S3StatusOK;

	int nCount = gbccDataEx->bccdNumber - 1;
	if(nCount<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return S3StatusOutOfMemory;
	}
	S3BucketCorsConf* bucketCorsConf = (S3BucketCorsConf*)malloc(sizeof(S3BucketCorsConf) * nCount);
	if (NULL == bucketCorsConf) 
	{
		COMMLOG(OBS_LOGERROR, "Malloc S3BucketCorsConf failed!");
		return S3StatusOutOfMemory;
	}
	memset_s(bucketCorsConf, sizeof(S3BucketCorsConf) * nCount, 0, sizeof(S3BucketCorsConf) * nCount);
	int i = 0;
	int j = 0;
	for (; i<nCount; ++i)
	{
		// id
		bucketCorsConf[i].id = gbccDataEx->bccData[i]->id;

		// allowedMethod
		if(gbccDataEx->bccData[i]->allowedMethodCount<1)
		{
			COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
			free(bucketCorsConf);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		bucketCorsConf[i].allowedMethod = (const char**)malloc(sizeof(char *) * gbccDataEx->bccData[i]->allowedMethodCount);
		if (NULL == bucketCorsConf[i].allowedMethod) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc allowedMethod failed!");
			int nIndex = 0;
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		memset_s(bucketCorsConf[i].allowedMethod, sizeof(char *) * gbccDataEx->bccData[i]->allowedMethodCount, 0, sizeof(char *) * gbccDataEx->bccData[i]->allowedMethodCount);
		for (j=0; j<gbccDataEx->bccData[i]->allowedMethodCount; j++)
		{
			bucketCorsConf[i].allowedMethod[j] = gbccDataEx->bccData[i]->allowedMethodes[j];
		}			
		bucketCorsConf[i].amNumber = gbccDataEx->bccData[i]->allowedMethodCount;

		// allowedOrigin
		if(gbccDataEx->bccData[i]->allowedOriginCount<1)
		{
			COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
			int nIndex = 0;          //zwx367245 2016.10.08 不能直接退出，要先释放内存再return
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		bucketCorsConf[i].allowedOrigin = (const char**)malloc(sizeof(char *) * gbccDataEx->bccData[i]->allowedOriginCount);
		if (NULL == bucketCorsConf[i].allowedOrigin) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc allowedOrigin failed!");
			int nIndex = 0;
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		memset_s(bucketCorsConf[i].allowedOrigin, sizeof(char *) * gbccDataEx->bccData[i]->allowedOriginCount, 0, sizeof(char *) * gbccDataEx->bccData[i]->allowedOriginCount);
		for (j=0; j<gbccDataEx->bccData[i]->allowedOriginCount; j++)
		{
			bucketCorsConf[i].allowedOrigin[j] = gbccDataEx->bccData[i]->allowedOrigines[j];
		}
		bucketCorsConf[i].aoNumber= gbccDataEx->bccData[i]->allowedOriginCount;

		// allowedHeader
		if(gbccDataEx->bccData[i]->allowedHeaderCount<1)
		{
			COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
			int nIndex = 0;
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		bucketCorsConf[i].allowedHeader = (const char**)malloc(sizeof(char *) * gbccDataEx->bccData[i]->allowedHeaderCount);
		if (NULL == bucketCorsConf[i].allowedHeader) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc allowedHeader failed!");
			int nIndex = 0;
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		memset_s(bucketCorsConf[i].allowedHeader, sizeof(char *) * gbccDataEx->bccData[i]->allowedHeaderCount, 0, sizeof(char *) * gbccDataEx->bccData[i]->allowedHeaderCount);
		for (j=0; j<gbccDataEx->bccData[i]->allowedHeaderCount; j++)
		{
			bucketCorsConf[i].allowedHeader[j] = gbccDataEx->bccData[i]->allowedHeaderes[j];
		}
		bucketCorsConf[i].ahNumber = gbccDataEx->bccData[i]->allowedHeaderCount;

		// maxAgeSeconds
		bucketCorsConf[i].maxAgeSeconds= gbccDataEx->bccData[i]->maxAgeSeconds;

		// exposeHeader
		if(gbccDataEx->bccData[i]->exposeHeaderCount<1)
		{
			COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
			int nIndex = 0;
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		bucketCorsConf[i].exposeHeader = (const char**)malloc(sizeof(char *) * gbccDataEx->bccData[i]->exposeHeaderCount);
		if (NULL == bucketCorsConf[i].exposeHeader) 
		{
			COMMLOG(OBS_LOGERROR, "Malloc exposeHeader failed!");
			int nIndex = 0;
			for (nIndex=0; nIndex<i; nIndex++)
			{
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedMethod);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedOrigin);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].allowedHeader);
				CHECK_NULL_FREE(bucketCorsConf[nIndex].exposeHeader);
			}
			free(bucketCorsConf);    
			bucketCorsConf=NULL;
			return S3StatusOutOfMemory;
		}
		memset_s(bucketCorsConf[i].exposeHeader, sizeof(char *) * gbccDataEx->bccData[i]->exposeHeaderCount, 0, sizeof(char *) * gbccDataEx->bccData[i]->exposeHeaderCount);
		for (j=0; j<gbccDataEx->bccData[i]->exposeHeaderCount; j++)
		{
			bucketCorsConf[i].exposeHeader[j] = gbccDataEx->bccData[i]->exposeHeaderes[j];
		}
		bucketCorsConf[i].ehNumber = gbccDataEx->bccData[i]->exposeHeaderCount;
	}

	iRet = (*(gbccDataEx->getBucketCorsConfigurationCallbackEx))
		(bucketCorsConf, nCount, gbccDataEx->callbackData);
	
	for (i=0; i<nCount; i++)
	{
		CHECK_NULL_FREE(bucketCorsConf[i].allowedMethod);
		CHECK_NULL_FREE(bucketCorsConf[i].allowedOrigin);
		CHECK_NULL_FREE(bucketCorsConf[i].allowedHeader);
		CHECK_NULL_FREE(bucketCorsConf[i].exposeHeader);
	}
	CHECK_NULL_FREE(bucketCorsConf);
	
    return iRet;
}

static S3Status GetBucketCorsConfigurationXmlCallbackEx(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    GetBucketCorsConfigurationDataEx *gbccDataEx = (GetBucketCorsConfigurationDataEx *) callbackData;
	int nIndex = gbccDataEx->bccdNumber - 1;

    int fit;

    if (data) {
        if (!strcmp(elementPath, "CORSConfiguration/CORSRule/ID")) {
            string_buffer_append(gbccDataEx->bccData[nIndex]->id, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, "CORSConfiguration/CORSRule/MaxAgeSeconds")) {
            string_buffer_append(gbccDataEx->bccData[nIndex]->maxAgeSeconds, data, dataLen, fit);
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/AllowedMethod")) {
            int which = gbccDataEx->bccData[nIndex]->allowedMethodCount;
            gbccDataEx->bccData[nIndex]->allowedMethodLens[which] +=
                snprintf_s(gbccDataEx->bccData[nIndex]->allowedMethodes[which], sizeof(gbccDataEx->bccData[nIndex]->allowedMethodes[which]), //secure function
                         sizeof(gbccDataEx->bccData[nIndex]->allowedMethodes[which]) -
                         gbccDataEx->bccData[nIndex]->allowedMethodLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccDataEx->bccData[nIndex]->allowedMethodLens[which] >=
                (int) sizeof(gbccDataEx->bccData[nIndex]->allowedMethodes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/AllowedOrigin")) {
            int which = gbccDataEx->bccData[nIndex]->allowedOriginCount;
            gbccDataEx->bccData[nIndex]->allowedOriginLens[which] +=
                snprintf_s(gbccDataEx->bccData[nIndex]->allowedOrigines[which],sizeof(gbccDataEx->bccData[nIndex]->allowedOrigines[which]), //secure function
                         sizeof(gbccDataEx->bccData[nIndex]->allowedOrigines[which]) -
                         gbccDataEx->bccData[nIndex]->allowedOriginLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccDataEx->bccData[nIndex]->allowedOriginLens[which] >=
                (int) sizeof(gbccDataEx->bccData[nIndex]->allowedOrigines[which])) {
                return S3StatusXmlParseFailure;
            }
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/AllowedHeader")) {
            int which = gbccDataEx->bccData[nIndex]->allowedHeaderCount;
            gbccDataEx->bccData[nIndex]->allowedHeaderLens[which] +=
                snprintf_s(gbccDataEx->bccData[nIndex]->allowedHeaderes[which], sizeof(gbccDataEx->bccData[nIndex]->allowedHeaderes[which]), //secure function
                         sizeof(gbccDataEx->bccData[nIndex]->allowedHeaderes[which]) -
                         gbccDataEx->bccData[nIndex]->allowedHeaderLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccDataEx->bccData[nIndex]->allowedHeaderLens[which] >=
                (int) sizeof(gbccDataEx->bccData[nIndex]->allowedHeaderes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
        else if (!strcmp(elementPath, 
                         "CORSConfiguration/CORSRule/ExposeHeader")) {
            int which = gbccDataEx->bccData[nIndex]->exposeHeaderCount;
            gbccDataEx->bccData[nIndex]->exposeHeaderLens[which] +=
                snprintf_s(gbccDataEx->bccData[nIndex]->exposeHeaderes[which], sizeof(gbccDataEx->bccData[nIndex]->exposeHeaderes[which]), //secure function
                         sizeof(gbccDataEx->bccData[nIndex]->exposeHeaderes[which]) -
                         gbccDataEx->bccData[nIndex]->exposeHeaderLens[which] - 1,
                         "%.*s", dataLen, data);
            if (gbccDataEx->bccData[nIndex]->exposeHeaderLens[which] >=
                (int) sizeof(gbccDataEx->bccData[nIndex]->exposeHeaderes[which])) {
                return S3StatusXmlParseFailure;
            }
        }
    }
    else {
		if (!strcmp(elementPath, "CORSConfiguration/CORSRule"))
		{
			BucketCorsConfData* bccData = (BucketCorsConfData*) malloc(sizeof(BucketCorsConfData));
			if (!bccData) {
			        (*(gbccDataEx->responseCompleteCallback))
			            (S3StatusOutOfMemory, 0, callbackData);
					COMMLOG(OBS_LOGERROR, "Malloc BucketCorsConfData failed !");

			        return S3StatusOutOfMemory;
		   	}
			memset_s(bccData, sizeof(BucketCorsConfData), 0, sizeof(BucketCorsConfData));  //secure function
			gbccDataEx->bccData[gbccDataEx->bccdNumber] = bccData;
			gbccDataEx->bccdNumber++;
		}
		
         if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/AllowedMethod")) {
            // Finished a Prefix
            gbccDataEx->bccData[nIndex]->allowedMethodCount++;
                gbccDataEx->bccData[nIndex]->allowedMethodes[gbccDataEx->bccData[nIndex]->allowedMethodCount][0] = 0;
                gbccDataEx->bccData[nIndex]->allowedMethodLens[gbccDataEx->bccData[nIndex]->allowedMethodCount] = 0;
            }
         else if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/AllowedOrigin")) {
                gbccDataEx->bccData[nIndex]->allowedOriginCount++;
                gbccDataEx->bccData[nIndex]->allowedOrigines[gbccDataEx->bccData[nIndex]->allowedOriginCount][0] = 0;
                gbccDataEx->bccData[nIndex]->allowedOriginLens[gbccDataEx->bccData[nIndex]->allowedOriginCount] = 0;
            }
         else if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/AllowedHeader")) {
                gbccDataEx->bccData[nIndex]->allowedHeaderCount++;
                gbccDataEx->bccData[nIndex]->allowedHeaderes[gbccDataEx->bccData[nIndex]->allowedHeaderCount][0] = 0;
                gbccDataEx->bccData[nIndex]->allowedHeaderLens[gbccDataEx->bccData[nIndex]->allowedHeaderCount] = 0;
            }
         else if (!strcmp(elementPath,
                         "CORSConfiguration/CORSRule/ExposeHeader")) {
                gbccDataEx->bccData[nIndex]->exposeHeaderCount++;
                gbccDataEx->bccData[nIndex]->exposeHeaderes[gbccDataEx->bccData[nIndex]->exposeHeaderCount][0] = 0;
                gbccDataEx->bccData[nIndex]->exposeHeaderLens[gbccDataEx->bccData[nIndex]->exposeHeaderCount] = 0;
            }
        }

    /* Avoid compiler error about variable set but not used */
    (void) fit;

    return S3StatusOK;
}

static S3Status GetBucketCorsConfigurationPropertiesCallbackEx
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBucketCorsConfigurationDataEx *gbccDataEx = (GetBucketCorsConfigurationDataEx *) callbackData;
    
    return (*(gbccDataEx->responsePropertiesCallback))
        (responseProperties, gbccDataEx->callbackData);
}


static S3Status GetBucketCorsConfigurationDataCallbackEx(int bufferSize, const char *buffer, void *callbackData)/*lint !e31 */
{
    GetBucketCorsConfigurationDataEx *gbccDataEx = (GetBucketCorsConfigurationDataEx *) callbackData;
    
    return simplexml_add(&(gbccDataEx->simpleXml), buffer, bufferSize);
}


static void GetBucketCorsConfigurationCompleteCallbackEx(S3Status requestStatus, const S3ErrorDetails *s3ErrorDetails, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);
    GetBucketCorsConfigurationDataEx *gbccDataEx = (GetBucketCorsConfigurationDataEx *) callbackData;

    // Make the callback if there is anything
    if (gbccDataEx->bccdNumber) {
        make_get_cors_callbackEx(gbccDataEx);
    }

    (*(gbccDataEx->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gbccDataEx->callbackData);

    simplexml_deinitialize(&(gbccDataEx->simpleXml));

	unsigned int i = 0;
	for (; i<gbccDataEx->bccdNumber; ++i)
	{
		free(gbccDataEx->bccData[i]);
		gbccDataEx->bccData[i] = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	}
    free(gbccDataEx);
	gbccDataEx = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}

void GetBucketCorsConfigurationEx(const S3BucketContext *bucketContext, 
                    S3RequestContext *requestContext,
                    const S3CORSHandlerEx *handlerEx, void *callbackData)
{
       SYSTEMTIME reqTime; 
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBucketCorsConfigurationDataEx *gbccDataEx =
        (GetBucketCorsConfigurationDataEx *) malloc(sizeof(GetBucketCorsConfigurationDataEx));

    if (!gbccDataEx) {
		(void)(*(handlerEx->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBucketCorsConfigurationData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(gbccDataEx, sizeof(GetBucketCorsConfigurationDataEx), 0, sizeof(GetBucketCorsConfigurationDataEx));//lint !e516

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
		(void)(*(handlerEx->responseHandler.completeCallback))(S3StatusInvalidBucketName, 0, callbackData);

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusInvalidBucketName, "");
		//zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		free(gbccDataEx);//lint !e516
		gbccDataEx = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}

    simplexml_initialize(&(gbccDataEx->simpleXml), &GetBucketCorsConfigurationXmlCallbackEx, gbccDataEx);//lint !e119
    
    gbccDataEx->responsePropertiesCallback = 
        handlerEx->responseHandler.propertiesCallback;
    gbccDataEx->getBucketCorsConfigurationCallbackEx = handlerEx->getBucketCorsConfigurationCallbackEx;
    gbccDataEx->responseCompleteCallback = 
        handlerEx->responseHandler.completeCallback;
    gbccDataEx->callbackData = callbackData;

    BucketCorsConfData* bccData = (BucketCorsConfData*) malloc(sizeof(BucketCorsConfData));
	if (!bccData) {
		(void)(*(handlerEx->responseHandler.completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc BucketCorsConfData failed !");

		SYSTEMTIME rspTime; 
		GetLocalTime(&rspTime);
		INTLOG(reqTime, rspTime, S3StatusOutOfMemory, "");

		return;
    }
	memset_s(bccData, sizeof(BucketCorsConfData), 0, sizeof(BucketCorsConfData));//lint !e516
	gbccDataEx->bccData[0] = bccData;
	gbccDataEx->bccdNumber = 1;

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
        0,                                            // key
        0,								              // queryParams
        "cors",                                       // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &GetBucketCorsConfigurationPropertiesCallbackEx,// propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &GetBucketCorsConfigurationDataCallbackEx,      // fromS3Callback
        &GetBucketCorsConfigurationCompleteCallbackEx,  // completeCallback
        gbccDataEx,                                     // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

       SYSTEMTIME rspTime; 
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}
//lint +e26 +e31 +e63 +e64 +e78 +e101 +e119 +e129 +e144 +e156 +e438 +e505 +e516 +e515 +e522 +e529 +e530 +e533 +e534 +e546 +e551 +e578 +e601
