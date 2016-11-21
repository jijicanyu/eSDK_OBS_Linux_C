/** **************************************************************************
 * server_access_logging.c
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

#ifdef WIN32
# pragma warning (disable:4127)
#endif
// get server access logging---------------------------------------------------
//lint -e26 -e31 -e63 -e64 -e78 -e101 -e119 -e129 -e144 -e156 -e438 -e505 -e515 -e516 -e522 -e529 -e530 -e533 -e534 -e546 -e551 -e578 -e601
typedef struct ConvertBlsData
{
    char *targetBucketReturn;
    int targetBucketReturnLen;
    char *targetPrefixReturn;
    int targetPrefixReturnLen;
    int *aclGrantCountReturn;
    S3AclGrant *aclGrants; //lint !e601

    string_buffer(emailAddress, S3_MAX_GRANTEE_EMAIL_ADDRESS_SIZE);
    string_buffer(userId, S3_MAX_GRANTEE_USER_ID_SIZE);
    string_buffer(userDisplayName, S3_MAX_GRANTEE_DISPLAY_NAME_SIZE);
    string_buffer(groupUri, 128);
    string_buffer(permission, 32);
} ConvertBlsData;

//lint -e551
static S3Status convertBlsXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    ConvertBlsData *caData = (ConvertBlsData *) callbackData;  //lint !e78 !e63 !e530

    int fit;

    if (data) {
        if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                    "TargetBucket")) {
            caData->targetBucketReturnLen += 
                snprintf_s(&(caData->targetBucketReturn
                           [caData->targetBucketReturnLen]),
						   sizeof(caData->targetBucketReturn[caData->targetBucketReturnLen]),
                         255 - caData->targetBucketReturnLen - 1, 
                         "%.*s", dataLen, data);//secure function
            if (caData->targetBucketReturnLen >= 255) {
                return S3StatusTargetBucketTooLong;
            }
        }
        else if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                    "TargetPrefix")) {
            caData->targetPrefixReturnLen += 
                snprintf_s(&(caData->targetPrefixReturn
                           [caData->targetPrefixReturnLen]),
						   sizeof(caData->targetPrefixReturn[caData->targetPrefixReturnLen]),
                         255 - caData->targetPrefixReturnLen - 1, 
                         "%.*s", dataLen, data);//secure function
            if (caData->targetPrefixReturnLen >= 255) {
                return S3StatusTargetPrefixTooLong;
            }
        }
        else if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                         "TargetGrants/Grant/Grantee/EmailAddress")) {
            // HuaweiCustomerByEmail
            string_buffer_append(caData->emailAddress, data, dataLen, fit);
            if (!fit) {
                return S3StatusEmailAddressTooLong;
            }
        }
        else if (!strcmp(elementPath,
                         "BucketLoggingStatus/LoggingEnabled/TargetGrants/Grant/"
                         "Grantee/ID")) {
            // CanonicalUser
            string_buffer_append(caData->userId, data, dataLen, fit);
            if (!fit) {
                return S3StatusUserIdTooLong;
            }
        }
        else if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                         "TargetGrants/Grant/Grantee/DisplayName")) {
            // CanonicalUser
            string_buffer_append(caData->userDisplayName, data, dataLen, fit);
            if (!fit) {
                return S3StatusUserDisplayNameTooLong;
            }
        }
        else if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                         "TargetGrants/Grant/Grantee/URI")) {
            // Group
            string_buffer_append(caData->groupUri, data, dataLen, fit);
            if (!fit) {
                return S3StatusGroupUriTooLong;
            }
        }
        else if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                         "TargetGrants/Grant/Permission")) {
            // Permission
            string_buffer_append(caData->permission, data, dataLen, fit);
            if (!fit) {
                return S3StatusPermissionTooLong;
            }
        }
    }
    else {
        if (!strcmp(elementPath, "BucketLoggingStatus/LoggingEnabled/"
                    "TargetGrants/Grant")) {
            // A grant has just been completed; so add the next S3AclGrant
            // based on the values read
            if (*(caData->aclGrantCountReturn) == S3_MAX_ACL_GRANT_COUNT) {
                return S3StatusTooManyGrants;
            }

            S3AclGrant *grant = &(caData->aclGrants
                                  [*(caData->aclGrantCountReturn)]);

            if (caData->emailAddress[0]) {
                grant->granteeType = S3GranteeTypeHuaweiCustomerByEmail;
                strcpy_s(grant->grantee.huaweiCustomerByEmail.emailAddress,
						sizeof(grant->grantee.huaweiCustomerByEmail.emailAddress),
                       caData->emailAddress);//secure function
            }
            else if (caData->userId[0] && caData->userDisplayName[0]) {
                grant->granteeType = S3GranteeTypeCanonicalUser;
                strcpy_s(grant->grantee.canonicalUser.id, sizeof(grant->grantee.canonicalUser.id), caData->userId);//secure function
                strcpy_s(grant->grantee.canonicalUser.displayName, 
						sizeof(grant->grantee.canonicalUser.displayName),
                       caData->userDisplayName);//secure function
            }
            else if (caData->groupUri[0]) {
                if (!strcmp(caData->groupUri,
                            ACS_GROUP_AWS_USERS)) {
                    grant->granteeType = S3GranteeTypeAllAwsUsers;
                }
                else if (!strcmp(caData->groupUri,
                                 ACS_GROUP_ALL_USERS)) {
                    grant->granteeType = S3GranteeTypeAllUsers;
                }
                else {
                    return S3StatusBadGrantee;
                }
            }
            else {
                return S3StatusBadGrantee;
            }

            if (!strcmp(caData->permission, "READ")) {
                grant->permission = S3PermissionRead;
            }
            else if (!strcmp(caData->permission, "WRITE")) {
                grant->permission = S3PermissionWrite;
            }
            else if (!strcmp(caData->permission, "READ_ACP")) {
                grant->permission = S3PermissionReadACP;
            }
            else if (!strcmp(caData->permission, "WRITE_ACP")) {
                grant->permission = S3PermissionWriteACP;
            }
            else if (!strcmp(caData->permission, "FULL_CONTROL")) {
                grant->permission = S3PermissionFullControl;
            }
            else {
                return S3StatusBadPermission;
            }

            (*(caData->aclGrantCountReturn))++;

            string_buffer_initialize(caData->emailAddress);
            string_buffer_initialize(caData->userId);
            string_buffer_initialize(caData->userDisplayName);
            string_buffer_initialize(caData->groupUri);
            string_buffer_initialize(caData->permission);
        }
    }

    return S3StatusOK;
}
//lint +e551

static S3Status convert_bls(char *blsXml, char *targetBucketReturn,
                            char *targetPrefixReturn, int *aclGrantCountReturn,
                            S3AclGrant *aclGrants)
{
    ConvertBlsData data;

    data.targetBucketReturn = targetBucketReturn;
    data.targetBucketReturn[0] = 0;
    data.targetBucketReturnLen = 0;
    data.targetPrefixReturn = targetPrefixReturn;
    data.targetPrefixReturn[0] = 0;
    data.targetPrefixReturnLen = 0;
    data.aclGrantCountReturn = aclGrantCountReturn;
    data.aclGrants = aclGrants;
    *aclGrantCountReturn = 0;
    string_buffer_initialize(data.emailAddress);
    string_buffer_initialize(data.userId);
    string_buffer_initialize(data.userDisplayName);
    string_buffer_initialize(data.groupUri);
    string_buffer_initialize(data.permission);

    // Use a simplexml parser
    SimpleXml simpleXml;
    simplexml_initialize(&simpleXml, &convertBlsXmlCallback, &data);

    S3Status status = simplexml_add(&simpleXml, blsXml, strlen(blsXml));

    simplexml_deinitialize(&simpleXml);
                                          
    return status;
}


// Use a rather arbitrary max size for the document of 64K
#define BLS_XML_DOC_MAXSIZE (64 * 1024)


typedef struct GetBlsData
{
    SimpleXml simpleXml;

    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    char *targetBucketReturn;
    char *targetPrefixReturn;
    int *aclGrantCountReturn;
    S3AclGrant *aclGrants;
    string_buffer(blsXmlDocument, BLS_XML_DOC_MAXSIZE);
}GetBlsData;


static S3Status getBlsPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    GetBlsData *gsData = (GetBlsData *) callbackData;
    
    return (*(gsData->responsePropertiesCallback))
        (responseProperties, gsData->callbackData);
}


static S3Status getBlsDataCallback(int bufferSize, const char *buffer,
                                   void *callbackData)
{
    GetBlsData *gsData = (GetBlsData *) callbackData;

    int fit;

    string_buffer_append(gsData->blsXmlDocument, buffer, bufferSize, fit);
    
    return fit ? S3StatusOK : S3StatusXmlDocumentTooLarge;
}


static void getBlsCompleteCallback(S3Status requestStatus, 
                                   const S3ErrorDetails *s3ErrorDetails,
                                   void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    GetBlsData *gsData = (GetBlsData *) callbackData;

    if (requestStatus == S3StatusOK) {
        // Parse the document
        requestStatus = convert_bls
            (gsData->blsXmlDocument, gsData->targetBucketReturn,
             gsData->targetPrefixReturn, gsData->aclGrantCountReturn, 
             gsData->aclGrants);
    }

    (void)(*(gsData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, gsData->callbackData);

    free(gsData);
	gsData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);

}


void S3_get_server_access_logging(const S3BucketContext *bucketContext,
                                  char *targetBucketReturn,
                                  char *targetPrefixReturn,
                                  int *aclGrantCountReturn, 
                                  S3AclGrant *aclGrants,
                                  S3RequestContext *requestContext,
                                  const S3ResponseHandler *handler,
                                  void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_get_server_access_logging successfully !");
    // Create the callback data
    GetBlsData *gsData = (GetBlsData *) malloc(sizeof(GetBlsData));
    if (!gsData) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc GetBlsData failed !");
        return;
    }
	memset_s(gsData, sizeof(GetBlsData), 0, sizeof(GetBlsData));//secure function

    gsData->responsePropertiesCallback = handler->propertiesCallback;
    gsData->responseCompleteCallback = handler->completeCallback;
    gsData->callbackData = callbackData;

    gsData->targetBucketReturn = targetBucketReturn;
    gsData->targetPrefixReturn = targetPrefixReturn;
    gsData->aclGrantCountReturn = aclGrantCountReturn;
    gsData->aclGrants = aclGrants;
    string_buffer_initialize(gsData->blsXmlDocument);//lint !e409
    *aclGrantCountReturn = 0;

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
        "logging",                                    // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &getBlsPropertiesCallback,                    // propertiesCallback
        0,                                            // toS3Callback
        0,                                            // toS3CallbackTotalSize
        &getBlsDataCallback,                          // fromS3Callback
        &getBlsCompleteCallback,                      // completeCallback
        gsData,                                 	  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_get_server_access_logging successfully !");
}

void GetBucketLoggingConfiguration(const S3BucketContext *bucketContext,
                                  char *targetBucketReturn,
                                  char *targetPrefixReturn,
                                  int *aclGrantCountReturn, 
                                  S3AclGrant *aclGrants,
                                  S3RequestContext *requestContext,
                                  const S3ResponseHandler *handler,
                                  void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter GetBucketLoggingConfiguration successfully !");
	S3_get_server_access_logging(bucketContext,targetBucketReturn,targetPrefixReturn,aclGrantCountReturn,aclGrants,requestContext,handler,callbackData);/*lint !e119 */
	COMMLOG(OBS_LOGINFO, "Leave GetBucketLoggingConfiguration successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
}

// set server access logging---------------------------------------------------

static S3Status generateSalXmlDocument(const char *targetBucket,
                                       const char *targetPrefix,
                                       int aclGrantCount, 
                                       const S3AclGrant *aclGrants,
                                       int *xmlDocumentLenReturn,
                                       char *xmlDocument,
                                       int xmlDocumentBufferSize)
{
    *xmlDocumentLenReturn = 0;

#define append(fmt, ...)                                        \
    do {                                                        \
        *xmlDocumentLenReturn += snprintf_s                     \
            (&(xmlDocument[*xmlDocumentLenReturn]),             \
			 strlen(xmlDocument),								\
             xmlDocumentBufferSize - *xmlDocumentLenReturn - 1, \
             fmt, __VA_ARGS__);                                 \
        if (*xmlDocumentLenReturn >= xmlDocumentBufferSize) {   \
            return S3StatusXmlDocumentTooLarge;                 \
        } \
    } while (0)

    append("%s", "<BucketLoggingStatus "
           "xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\">");

    if (targetBucket && targetBucket[0]) {
        append("<LoggingEnabled><TargetBucket>%s</TargetBucket>", targetBucket);
        append("<TargetPrefix>%s</TargetPrefix>", 
               targetPrefix ? targetPrefix : "");

        if (aclGrantCount) {
            append("%s", "<TargetGrants>");
            int i;
            for (i = 0; i < aclGrantCount; i++) {
                append("%s", "<Grant><Grantee "
                       "xmlns:xsi=\"http://www.w3.org/2001/"
                       "XMLSchema-instance\" xsi:type=\"");
                const S3AclGrant *grant = &(aclGrants[i]);
                switch (grant->granteeType) {
                case S3GranteeTypeHuaweiCustomerByEmail:
                    append("AmazonCustomerByEmail\"><EmailAddress>%s"
                           "</EmailAddress>",
                           grant->grantee.huaweiCustomerByEmail.emailAddress);
                    break;
                case S3GranteeTypeCanonicalUser:
                    append("CanonicalUser\"><ID>%s</ID><DisplayName>%s"
                           "</DisplayName>",
                           grant->grantee.canonicalUser.id, 
                           grant->grantee.canonicalUser.displayName);
                    break;
                default: // case S3GranteeTypeAllAwsUsers/S3GranteeTypeAllUsers:
                    append("Group\"><URI>%s</URI>",
                           (grant->granteeType == S3GranteeTypeAllAwsUsers) ?
                           ACS_GROUP_AWS_USERS : ACS_GROUP_ALL_USERS);
                    break;
                }
                append("</Grantee><Permission>%s</Permission></Grant>",
                       ((grant->permission == S3PermissionRead) ? "READ" :
                        (grant->permission == S3PermissionWrite) ? "WRITE" :
                        (grant->permission == S3PermissionReadACP) ? "READ_ACP" :
                        (grant->permission == S3PermissionWriteACP) ? "WRITE_ACP" : 
                        (grant->permission == S3PermissionFullControl) ? "FULL_CONTROL" : "READ"));
            }
            append("%s", "</TargetGrants>");
        }
        append("%s", "</LoggingEnabled>");
    }

    append("%s", "</BucketLoggingStatus>");

    return S3StatusOK;
}


typedef struct SetSalData
{
    S3ResponsePropertiesCallback *responsePropertiesCallback;
    S3ResponseCompleteCallback *responseCompleteCallback;
    void *callbackData;

    int salXmlDocumentLen;
    char salXmlDocument[BLS_XML_DOC_MAXSIZE];
    int salXmlDocumentBytesWritten;

} SetSalData;


static S3Status setSalPropertiesCallback
    (const S3ResponseProperties *responseProperties, void *callbackData)
{
    SetSalData *paData = (SetSalData *) callbackData;
    
    return (*(paData->responsePropertiesCallback))
        (responseProperties, paData->callbackData);
}


static int setSalDataCallback(int bufferSize, char *buffer, void *callbackData)
{
    SetSalData *paData = (SetSalData *) callbackData;

    int remaining = (paData->salXmlDocumentLen - 
                     paData->salXmlDocumentBytesWritten);

    int toCopy = bufferSize > remaining ? remaining : bufferSize;
    
    if (!toCopy) {
        return 0;
    }

    memcpy_s(buffer, strlen(buffer), &(paData->salXmlDocument
                     [paData->salXmlDocumentBytesWritten]), toCopy);//secure function

    paData->salXmlDocumentBytesWritten += toCopy;

    return toCopy;
}


static void setSalCompleteCallback(S3Status requestStatus, 
                                   const S3ErrorDetails *s3ErrorDetails,
                                   void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);

    SetSalData *paData = (SetSalData *) callbackData;

    (void)(*(paData->responseCompleteCallback))
        (requestStatus, s3ErrorDetails, paData->callbackData);

    free(paData);
	paData = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);
}


void S3_set_server_access_logging(const S3BucketContext *bucketContext,
                                  const char *targetBucket, 
                                  const char *targetPrefix, int aclGrantCount, 
                                  const S3AclGrant *aclGrants, 
                                  S3RequestContext *requestContext,
                                  const S3ResponseHandler *handler,
                                  void *callbackData)
{
	COMMLOG(OBS_LOGINFO, "Enter S3_set_server_access_logging successfully !");
    if (aclGrantCount > S3_MAX_ACL_GRANT_COUNT) {
        (void)(*(handler->completeCallback))
            (S3StatusTooManyGrants, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Input param aclGrantCount is greater than S3_MAX_ACL_GRANT_COUNT");
        return;
    }
	int i = 0;
	for(i = 0; i < aclGrantCount;i++)
	{
		const S3AclGrant *grant = &(aclGrants[i]);
		if (grant->permission != S3PermissionRead && grant->permission != S3PermissionWrite &&grant->permission != S3PermissionFullControl) {
			 (void)(*(handler->completeCallback))
				 (S3StatusInvalidParameter, 0, callbackData);
			 COMMLOG(OBS_LOGERROR, "permission is invalid");
			 return;
		}
	}
	if (NULL == targetBucket || NULL == targetPrefix){
		 (void)(*(handler->completeCallback))
			 (S3StatusInvalidParameter, 0, callbackData);
		 COMMLOG(OBS_LOGERROR, "targetBucket or targetPrefix is NULL");
		 return;
	}
    SetSalData *data = (SetSalData *) malloc(sizeof(SetSalData));
    if (!data) {
        (void)(*(handler->completeCallback))(S3StatusOutOfMemory, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "Malloc SetSalData failed !");
        return;
    }
	memset_s(data, sizeof(SetSalData), 0, sizeof(SetSalData));//secure function
    
    // Convert aclGrants to XML document
    S3Status status = generateSalXmlDocument
        (targetBucket, targetPrefix, aclGrantCount, aclGrants,
         &(data->salXmlDocumentLen), data->salXmlDocument, 
         sizeof(data->salXmlDocument));
    if (status != S3StatusOK) {
        free(data);
		data = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
        (void)(*(handler->completeCallback))(status, 0, callbackData);
		COMMLOG(OBS_LOGERROR, "generateSalXmlDocument failed !");
        return;
    }

    data->responsePropertiesCallback = handler->propertiesCallback;
    data->responseCompleteCallback = handler->completeCallback;
    data->callbackData = callbackData;

    data->salXmlDocumentBytesWritten = 0;

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
        0,                                            // key
        0,                                            // queryParams
        "logging",                                    // subResource
        0,                                            // copySourceBucketName
        0,                                            // copySourceKey
        0,                                            // getConditions
        0,                                            // startByte
        0,                                            // byteCount
		0,											  // corsConf
        0,                                            // putProperties
		0,                                            // ServerSideEncryptionParams
        &setSalPropertiesCallback,                    // propertiesCallback
        &setSalDataCallback,                          // toS3Callback
        data->salXmlDocumentLen,                      // toS3CallbackTotalSize
        0,                                            // fromS3Callback
        &setSalCompleteCallback,                      // completeCallback
        data,                                 		  // callbackData
		bucketContext->certificateInfo ? 1 : 0		  // isCheckCA
    };

    // Perform the request
    request_perform(&params, requestContext);
	COMMLOG(OBS_LOGINFO, "Leave S3_set_server_access_logging successfully !");
}

void SetBucketLoggingConfiguration(const S3BucketContext *bucketContext,
                                  const char *targetBucket, 
                                  const char *targetPrefix, int aclGrantCount, 
                                  const S3AclGrant *aclGrants, 
                                  S3RequestContext *requestContext,
                                  const S3ResponseHandler *handler,
                                  void *callbackData)
{
	SYSTEMTIME reqTime; 
	GetLocalTime(&reqTime);
    
	COMMLOG(OBS_LOGINFO, "Enter SetBucketLoggingConfiguration successfully !");
	S3_set_server_access_logging(bucketContext,targetBucket,targetPrefix,aclGrantCount,aclGrants,requestContext,handler,callbackData);
	COMMLOG(OBS_LOGINFO, "Leave SetBucketLoggingConfiguration successfully !");

	SYSTEMTIME rspTime; 
	GetLocalTime(&rspTime);
	INTLOG(reqTime, rspTime, S3StatusOK, "");
    
}
//lint +e26 +e31 +e63 +e64 +e78 +e101 +e119 +e129 +e144 +e156 +e438 +e505 +e516 +e515 +e522 +e529 +e530 +e533 +e534 +e546 +e551 +e578 +e601
