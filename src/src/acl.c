/** **************************************************************************
 * acl.c
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
#include <stdio.h>
#include <string.h>
#include "eSDKOBSS3.h"
#include "request.h"
#include "securec.h"

// Use a rather arbitrary max size for the document of 64K
#define ACL_XML_DOC_MAXSIZE (64 * 1024)

#ifdef WIN32
# pragma warning (disable:4127)
#endif

// get acl -------------------------------------------------------------------
//lint -e551
typedef struct GetAclData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback; //lint !e601
    S3ResponseCompleteCallback *responseCompleteCallback; //lint !e601
    void *callbackData;

    int *aclGrantCountReturn;
    S3AclGrant *aclGrants;//lint !e601
    char *ownerId;
    char *ownerDisplayName;
    string_buffer(aclXmlDocument, ACL_XML_DOC_MAXSIZE);
} GetAclData;

//lint -e551
static S3Status getAclPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetAclData *gaData = (GetAclData *) callbackData;//lint !e78 !e63 !e530
    
    return (*(gaData->responsePropertiesCallback))
        (responseProperties, gaData->callbackData);
}
//lint +e551

static S3Status getAclDataCallback(int bufferSize, const char *buffer,
                                   void *callbackData)
{
    GetAclData *gaData = (GetAclData *) callbackData;

    int fit;

    string_buffer_append(gaData->aclXmlDocument, buffer, bufferSize, fit);
    
    return fit ? S3StatusOK : S3StatusXmlDocumentTooLarge;
}

//lint -e438
static void getAclCompleteCallback(S3Status requestStatus, //lint !e578
                                   const S3ErrorDetails *s3ErrorDetails,
                                   void *callbackData)
{//lint !e101 
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetAclData *gaData = (GetAclData *) callbackData;

    if (requestStatus == S3StatusOK) {
        // Parse the document
        requestStatus = S3_convert_acl
            (gaData->aclXmlDocument, gaData->ownerId, gaData->ownerDisplayName,
             gaData->aclGrantCountReturn, gaData->aclGrants);//lint !e63
    }

    (void)(*(gaData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gaData->callbackData);//lint !e534

    free(gaData);
	gaData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}//lint !e533
//lint +e438

void S3_get_acl(const S3BucketContext *bucketContext, const char *key, 
                const char* versionId,char *ownerId, char *ownerDisplayName,
                int *aclGrantCountReturn, S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_get_acl successfully !");
	string_buffer(queryParams, 4096);
	string_buffer_initialize(queryParams);
	//lint -e438
#define safe_append(name, value)                                        \
	do {																\
		int fit;														\
		if (amp) {														\
			string_buffer_append(queryParams, "&", 1, fit); 			\
			if (!fit) { 												\
				(void)(*(handler->completeCallback))			\
					(S3StatusQueryParamsTooLong, 0, callbackData);		\
				return; 												\
			}															\
		}																\
		string_buffer_append(queryParams, name "=", 					\
							 sizeof(name "=") - 1, fit);				\
		if (!fit) { 													\
			(void)(*(handler->completeCallback))				\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
		amp = 1;														\
		char encoded[3 * 1024]; 										\
		if (!urlEncode(encoded, value, 1024)) { 						\
			(void)(*(handler->completeCallback))				\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
		string_buffer_append(queryParams, encoded, strlen(encoded), 	\
							 fit);										\
		if (!fit) { 													\
			(void)(*(handler->completeCallback))				\
				(S3StatusQueryParamsTooLong, 0, callbackData);			\
			return; 													\
		}																\
	} while (0)

	int amp = 0;
    if (versionId) {
        safe_append("versionId", versionId);//lint !e534
    }
    // Create the callback data
    GetAclData *gaData = (GetAclData *) malloc(sizeof(GetAclData));
    if (!gaData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData); //lint !e534
		COMMLOG(OBS_LOGERROR, "Malloc GetAclData failed!");
        return;
    }
	memset_s(gaData, sizeof(GetAclData), 0 , sizeof(GetAclData));
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);//lint !e534
		free(gaData);    //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		gaData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
		return;
	}
	//lint +e438

    gaData->responsePropertiesCallback = handler->propertiesCallback;//lint !e63
    gaData->responseCompleteCallback = handler->completeCallback;//lint !e63
    gaData->callbackData = callbackData;

    gaData->aclGrantCountReturn = aclGrantCountReturn;
    gaData->aclGrants = aclGrants;//lint !e63
    gaData->ownerId = ownerId;
    gaData->ownerDisplayName = ownerDisplayName;
    string_buffer_initialize(gaData->aclXmlDocument);
    *aclGrantCountReturn = 0;//lint !e63

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypeGET,                           // httpRequestType
        { bucketContext->hostName,     //lint !e63  !e156  // hostName 
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        "acl",                                        // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
        0,											  //corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &getAclPropertiesCallback,                    // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &getAclDataCallback,                          // fromS3Callback
        &getAclCompleteCallback,       //lint !e546 !e64  // completeCallback
        gaData,                                       // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_get_acl successfully !");
}

void GetBucketAcl(const S3BucketContext *bucketContext, 
                char *ownerId, char *ownerDisplayName,
                int *aclGrantCountReturn, S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; //lint !e522
       GetLocalTime(&reqTime);
       
	COMMLOG(OBS_LOGINFO, "Enter GetBucketAcl successfully !");
	S3_get_acl(bucketContext,0,0,ownerId,ownerDisplayName,aclGrantCountReturn,aclGrants,requestContext,handler,callbackData); //lint !e119
	COMMLOG(OBS_LOGINFO, "Leave GetBucketAcl successfully !");

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);

        INTLOG(reqTime, rspTime, S3StatusOK, "");        
    
}

void GetObjectAcl(const S3BucketContext *bucketContext, const char *key, 
                const char* versionId,char *ownerId, char *ownerDisplayName,
                int *aclGrantCountReturn, S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
      SYSTEMTIME reqTime; //lint !e522
      GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetObjectAcl successfully !");
	if(NULL == key || !strlen(key)) //lint !e516
       {
    	    COMMLOG(OBS_LOGERROR, "key is NULL!");
    	    (*(handler->completeCallback))(S3StatusInvalidKey, 0, callbackData); //lint !e534

           SYSTEMTIME rspTime; //lint !e522
           GetLocalTime(&rspTime);
	    INTLOG(reqTime, rspTime, S3StatusInvalidKey, "");            

           return;
	}
    
	S3_get_acl(bucketContext,key,versionId,ownerId,ownerDisplayName,aclGrantCountReturn,aclGrants,requestContext,handler,callbackData); //lint !e119
	COMMLOG(OBS_LOGINFO, "Leave GetObjectAcl successfully !");

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");        
    
}


// set acl -------------------------------------------------------------------

static S3Status generateAclXmlDocument(const char *ownerId, //lint !e31
                                       const char *ownerDisplayName,
                                       int aclGrantCount, 
                                       const S3AclGrant *aclGrants,
                                       int *xmlDocumentLenReturn,
                                       char *xmlDocument,
                                       int xmlDocumentBufferSize)
{
    *xmlDocumentLenReturn = 0; //lint !e63
/* zwx367245 2016.10.08 snprintf_s第二个参数修正*/
#define append(fmt, ...)                                                  \
    do {                                                                 \
        *xmlDocumentLenReturn += snprintf_s                              \
            (&(xmlDocument[*xmlDocumentLenReturn]), xmlDocumentBufferSize - *xmlDocumentLenReturn , \
             xmlDocumentBufferSize - *xmlDocumentLenReturn - 1,           \
             fmt, __VA_ARGS__);                                           \
        if (*xmlDocumentLenReturn >= xmlDocumentBufferSize) {             \
            return S3StatusXmlDocumentTooLarge;                           \
        } \
    } while (0)

    append("<AccessControlPolicy><Owner><ID>%s</ID><DisplayName>%s"
           "</DisplayName></Owner><AccessControlList>", ownerId,
           ownerDisplayName);

    int i;
    for (i = 0; i < aclGrantCount; i++) {
        append("%s", "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/"
               "XMLSchema-instance\" xsi:type=\"");
        const S3AclGrant *grant = &(aclGrants[i]);
        switch (grant->granteeType) {
        case S3GranteeTypeHuaweiCustomerByEmail:
            append("AmazonCustomerByEmail\"><EmailAddress>%s</EmailAddress>",
                   grant->grantee.huaweiCustomerByEmail.emailAddress);
            break;
        case S3GranteeTypeCanonicalUser:
            append("CanonicalUser\"><ID>%s</ID><DisplayName>%s</DisplayName>",
                   grant->grantee.canonicalUser.id, 
                   grant->grantee.canonicalUser.displayName);
            break;
        default: { // case S3GranteeTypeAllAwsUsers/S3GranteeTypeAllUsers:
            const char *grantee;
            switch (grant->granteeType) {
            case S3GranteeTypeAllAwsUsers:
                grantee = ACS_GROUP_AWS_USERS;
                break;
            case S3GranteeTypeAllUsers:
                grantee = ACS_GROUP_ALL_USERS;
                break;
            default:
                grantee = ACS_GROUP_LOG_DELIVERY;
                break;
            }
            append("Group\"><URI>%s</URI>", grantee);
        }
            break;
        }
        append("</Grantee><Permission>%s</Permission></Grant>",
               ((grant->permission == S3PermissionRead) ? "READ" :
                (grant->permission == S3PermissionWrite) ? "WRITE" :
                (grant->permission == S3PermissionReadACP) ? "READ_ACP" :
                (grant->permission == S3PermissionWriteACP) ? "WRITE_ACP" :
				(grant->permission == S3PermissionFullControl) ? "FULL_CONTROL" : "READ"));
    }

    append("%s", "</AccessControlList></AccessControlPolicy>");

    return S3StatusOK;
}


typedef struct SetAclData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int aclXmlDocumentLen;
    char aclXmlDocument[ACL_XML_DOC_MAXSIZE];
    int aclXmlDocumentBytesWritten;

} SetAclData; //lint !e129


static S3Status setAclPropertiesCallback //lint !e31
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    SetAclData *paData = (SetAclData *) callbackData; //lint !e26 !e63 
    
    return (*(paData->responsePropertiesCallback))
        (responseProperties, paData->callbackData);
}


static int setAclDataCallback(int bufferSize, char *buffer, void *callbackData)
{
    SetAclData *paData = (SetAclData *) callbackData;

    int remaining = (paData->aclXmlDocumentLen - 
                     paData->aclXmlDocumentBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, toCopy, &(paData->aclXmlDocument
                     [paData->aclXmlDocumentBytesWritten]), toCopy);  //secure function

    paData->aclXmlDocumentBytesWritten += toCopy;

    return toCopy;
}


static void setAclCompleteCallback(S3Status requestStatus, //lint !e578
                                   const S3ErrorDetails *s3ErrorDetails,
                                   void *callbackData)
{//lint !e101
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetAclData *paData = (SetAclData *) callbackData;//lint !e26 !e63

    (void)(*(paData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, paData->callbackData); //lint !e534

    free(paData); //lint !e516
	paData = NULL;//lint !e63
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}//lint !e533


void S3_set_acl(const S3BucketContext *bucketContext, const char *key, const char *versionId,
                const char *ownerId, const char *ownerDisplayName,
                int aclGrantCount, const S3AclGrant *aclGrants,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_set_acl successfully!");
    if (aclGrantCount > S3_MAX_ACL_GRANT_COUNT) {
        (void)(*(handler->completeCallback))
            (S3StatusTooManyGrants, 0, callbackData);//lint !e534
		COMMLOG(OBS_LOGERROR, "Input param aclGrantCount is greater than S3_MAX_ACL_GRANT_COUNT !");
        return;
    }

    SetAclData *data = (SetAclData *) malloc(sizeof(SetAclData));//lint !e26 !e63
    if (!data) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);//lint !e534
		COMMLOG(OBS_LOGERROR, "Malloc SetAclData failed !");
        return;
    }
	memset_s(data, sizeof(SetAclData), 0 , sizeof(SetAclData));  //lint !e516 //secure function
	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData); //lint !e534
		free(data);  //lint !e516  //zwx367245 2016.09.30 bucketName为空的时候不能直接退出，要先释放内存再return
		data = NULL; //lint !e63
		return;
	}

    string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);
//zwx367245 2016.10.08 宏定义函数里面有return，要先释放内存再return，所以添加了动态分配内存的地址参数
#define safe_append_without_memory_leak(name, value, data)              \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->completeCallback))          \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
				free(data);                                             \
				data=NULL;                                              \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))              \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
				free(data);                                             \
				data=NULL;                                              \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
        char encoded[3 * 1024];                                         \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->completeCallback))              \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
				free(data);                                             \
				data=NULL;                                              \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))              \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
				free(data);                                             \
				data=NULL;                                              \
            return;                                                     \
        }                                                               \
    } while (0)    

	int amp = 0;
    if (versionId) {
        safe_append_without_memory_leak("versionId", versionId, data); //lint !e534 !e516 !e63
    }

    // Convert aclGrants to XML document
    S3Status status = generateAclXmlDocument //lint !e522
        (ownerId, ownerDisplayName, aclGrantCount, aclGrants,
         &(data->aclXmlDocumentLen), data->aclXmlDocument, 
         sizeof(data->aclXmlDocument));
    if (status != S3StatusOK) {
        free(data); //lint !e516
		data = NULL; //lint !e63
        (void)(*(handler->completeCallback))(status, 0, callbackData); //lint !e534
		COMMLOG(OBS_LOGERROR, "generateAclXmlDocument failed");
        return;
    }

    data->responsePropertiesCallback = handler->propertiesCallback;//lint !e63
    data->responseCompleteCallback = handler->completeCallback;//lint !e63
    data->callbackData = callbackData;//lint !e63

    data->aclXmlDocumentBytesWritten = 0;//lint !e63

    // Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { bucketContext->hostName,  //lint !e156      // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        "acl",                                        // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &setAclPropertiesCallback,                    // propertiesCallback
        &setAclDataCallback,                          // toS3Callback
        data->aclXmlDocumentLen,                      // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &setAclCompleteCallback,     //lint !e546  !e64   // completeCallback
        data,                                         // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_set_acl successfully!");
}

void SetBucketAcl(const S3BucketContext *bucketContext,
                const char *ownerId, const char *ownerDisplayName,
                int aclGrantCount, const S3AclGrant *aclGrants,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; //lint !e522
       GetLocalTime(&reqTime);

	COMMLOG(OBS_LOGINFO, "Enter SetBucketAcl successfully!");
	S3_set_acl(bucketContext,0,NULL,ownerId,ownerDisplayName,aclGrantCount,aclGrants,requestContext,handler,callbackData); //lint !e119
	COMMLOG(OBS_LOGINFO, "Leave SetBucketAcl successfully!");

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);
	   
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

void SetObjectAcl(const S3BucketContext *bucketContext, const char *key, const char *versionId,
                const char *ownerId, const char *ownerDisplayName,
                int aclGrantCount, const S3AclGrant *aclGrants,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{

       SYSTEMTIME reqTime; //lint !e522
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetObjectAcl successfully !");
	if(NULL == key || !strlen(key)) //lint !e516
       {
            COMMLOG(OBS_LOGERROR, "key is NULL!");
            (void)(*(handler->completeCallback))(S3StatusInvalidKey, 0, callbackData); //lint !e534

            SYSTEMTIME rspTime; //lint !e522
            GetLocalTime(&rspTime);
	     INTLOG(reqTime, rspTime, S3StatusInvalidKey, "");
    
            return;
       }
    
	S3_set_acl(bucketContext,key,versionId,ownerId,ownerDisplayName,aclGrantCount,aclGrants,requestContext,handler,callbackData); //lint !e119
	COMMLOG(OBS_LOGINFO, "Leave SetObjectAcl successfully !");

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}

void SetAclByHead(const S3BucketContext *bucketContext, const char *key,const char *versionId,S3CannedAcl cannedAcl,S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter SetAclByHead successfully!");

	if(!bucketContext->bucketName){
		COMMLOG(OBS_LOGERROR, "bucketName is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidBucketName, 0, callbackData);//lint !e534
		return;
	}
	string_buffer(queryParams, 4096);
    string_buffer_initialize(queryParams);

#define safe_Append(name, value)                                        \
    do {                                                                \
        int fit;                                                        \
        if (amp) {                                                      \
            string_buffer_append(queryParams, "&", 1, fit);             \
            if (!fit) {                                                 \
                (void)(*(handler->completeCallback))          \
                    (S3StatusQueryParamsTooLong, 0, callbackData);      \
                return;                                                 \
            }                                                           \
        }                                                               \
        string_buffer_append(queryParams, name "=",                     \
                             sizeof(name "=") - 1, fit);                \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))              \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            return;                                                     \
        }                                                               \
        amp = 1;                                                        \
		char encoded[3 * 1024] = {0};                                         \
        if (!urlEncode(encoded, value, 1024)) {                         \
            (void)(*(handler->completeCallback))              \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            return;                                                     \
        }                                                               \
        string_buffer_append(queryParams, encoded, strlen(encoded),     \
                             fit);                                      \
        if (!fit) {                                                     \
            (void)(*(handler->completeCallback))              \
                (S3StatusQueryParamsTooLong, 0, callbackData);          \
            return;                                                     \
        }                                                               \
    } while (0)    

	int amp = 0;
    if (versionId) {
        safe_Append("versionId", versionId);//lint !e534
    }

	//lint -e505
	    // Set up S3PutProperties
    S3PutProperties properties = //lint !e522
    {
        0,                                       // contentType
        0,                                       // md5
        0,                                       // cacheControl
        0,                                       // contentDispositionFilename
        0,                                       // contentEncoding
        0,							 			//storagepolicy
        0,										 //websiteredirectlocation
        0,										 //getConditions
        0,										 //startByte
        0,										 //byteCount
        0,                                       // expires
        cannedAcl,                               // cannedAcl
        0,                                       // metaDataCount
        0,                                       // metaData
        0                                        // useServerSideEncryption
    };//lint !e522
	//lint +e505
	// Set up the RequestParams
    RequestParams params =
    {
        HttpRequestTypePUT,                           // httpRequestType
        { bucketContext->hostName,  //lint !e156                  // hostName
          bucketContext->bucketName,                  // bucketName
          bucketContext->protocol,                    // protocol
          bucketContext->uriStyle,                    // uriStyle
          bucketContext->accessKeyId,                 // accessKeyId
          bucketContext->secretAccessKey,             // secretAccessKey
          bucketContext->certificateInfo },           // certificateInfo
        key,                                          // key
        queryParams[0] ? queryParams : 0,             // queryParams
        "acl",                                        // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  //corsConf
        &properties,                                  // putProperties
		0,                                            // ServerSideEncryptionParams
        handler->propertiesCallback,                  // propertiesCallback
        0,					                          // toS3Callback
        0,						                      // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        handler->completeCallback,                    // completeCallback
        callbackData,                                 // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

	// Perform the request
	 request_perform(&params, requestContext);
	 COMMLOG(OBS_LOGINFO, "Leave SetAclByHead successfully!");


}

void SetBucketAclByHead(const S3BucketContext *bucketContext,S3CannedAcl cannedAcl,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; //lint !e522
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketAclByHead successfully!");
	SetAclByHead(bucketContext,0,NULL,cannedAcl,requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave SetBucketAclByHead successfully!");

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

void SetObjectAclByHead(const S3BucketContext *bucketContext, const char *key, const char *versionId,S3CannedAcl cannedAcl,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData)
{
       SYSTEMTIME reqTime; //lint !e522
       GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetObjectAclByHead successfully !");
	if(NULL == key || !strlen(key)){ //lint !e516
        COMMLOG(OBS_LOGERROR, "key is NULL!");
        (void)(*(handler->completeCallback))(S3StatusInvalidKey, 0, callbackData);//lint !e534

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusInvalidKey, "");
    
        return;
    }
	SetAclByHead(bucketContext,key,versionId,cannedAcl,requestContext,handler,callbackData);//lint !e119
	COMMLOG(OBS_LOGINFO, "Leave SetObjectAclByHead successfully !");

       SYSTEMTIME rspTime; //lint !e522
       GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}
//lint +e551

