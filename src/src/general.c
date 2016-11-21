/** **************************************************************************
 * general.c
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

#include <ctype.h>
#include <string.h>
#include "request.h"
#include "simplexml.h"
#include "util.h"
#include "log.h"
#include "securec.h"

static int initializeCountG = 0;

S3Status S3_initialize(const char *userAgentInfo, int flags,
                       const char *defaultS3HostName,S3Authorization auth,const char* defaultRegion)//lint !e601
{
    SYSTEMTIME reqTime; //lint !e522
    GetLocalTime(&reqTime);
    
    LOG_INIT();
    if (initializeCountG++) {

      SYSTEMTIME rspTime; //lint !e522
      GetLocalTime(&rspTime);
	   
      INTLOG(reqTime, rspTime, S3StatusOK, "");
	
	return S3StatusOK;
    }

    S3Status ret = request_api_initialize(userAgentInfo, flags, defaultS3HostName,auth,defaultRegion);//lint !e522

    SYSTEMTIME rspTime; //lint !e522
    GetLocalTime(&rspTime);
            
    INTLOG(reqTime, rspTime, ret, "");	

    return ret;
}


void S3_deinitialize()
{
	LOG_EXIT();
    if (--initializeCountG) {
        return;
    }

    request_api_deinitialize();
}

void S3_setTimeout(unsigned int unTimeout)
{
	request_api_setTimeout(unTimeout);
}
//lint -e101
const char *S3_get_status_name(S3Status status)
{
    switch (status) {
#define handlecase(s)                           \
        case S3Status##s:                       \
            return #s
		//lint -e30 -e142
        handlecase(OK);
        handlecase(InternalError);
        handlecase(OutOfMemory);
        handlecase(Interrupted);
        handlecase(InvalidBucketNameTooLong);
        handlecase(InvalidBucketNameFirstCharacter);
        handlecase(InvalidBucketNameCharacter);
        handlecase(InvalidBucketNameCharacterSequence);
        handlecase(InvalidBucketNameTooShort);
        handlecase(InvalidBucketNameDotQuadNotation);
        handlecase(QueryParamsTooLong);
        handlecase(FailedToInitializeRequest);
        handlecase(MetaDataHeadersTooLong);
        handlecase(BadMetaData);
        handlecase(BadContentType);
        handlecase(ContentTypeTooLong);
        handlecase(BadMD5);
        handlecase(MD5TooLong);
        handlecase(BadCacheControl);
        handlecase(CacheControlTooLong);
        handlecase(BadContentDispositionFilename);
        handlecase(ContentDispositionFilenameTooLong);
        handlecase(BadContentEncoding);
        handlecase(ContentEncodingTooLong);
        handlecase(BadIfMatchETag);
        handlecase(IfMatchETagTooLong);
        handlecase(BadIfNotMatchETag);
        handlecase(IfNotMatchETagTooLong);
        handlecase(HeadersTooLong);
        handlecase(KeyTooLong);
        handlecase(UriTooLong);
        handlecase(XmlParseFailure);
        handlecase(EmailAddressTooLong);
        handlecase(UserIdTooLong);
        handlecase(UserDisplayNameTooLong);
        handlecase(GroupUriTooLong);
        handlecase(PermissionTooLong);
        handlecase(TargetBucketTooLong);
        handlecase(TargetPrefixTooLong);
        handlecase(TooManyGrants);
        handlecase(BadGrantee);
        handlecase(BadPermission);
        handlecase(XmlDocumentTooLarge);
        handlecase(NameLookupError);
        handlecase(FailedToConnect);
        handlecase(ServerFailedVerification);
        handlecase(ConnectionFailed);
        handlecase(AbortedByCallback);
        handlecase(AccessDenied);
        handlecase(AccountProblem);
        handlecase(AmbiguousGrantByEmailAddress);
        handlecase(BadDigest);
        handlecase(BucketAlreadyExists);
        handlecase(BucketAlreadyOwnedByYou);
        handlecase(BucketNotEmpty);
        handlecase(CredentialsNotSupported);
        handlecase(CrossLocationLoggingProhibited);
        handlecase(EntityTooSmall);
        handlecase(EntityTooLarge);
        handlecase(ExpiredToken);
        handlecase(IllegalVersioningConfigurationException); 
        handlecase(IncompleteBody);
        handlecase(IncorrectNumberOfFilesInPostRequest);
        handlecase(InlineDataTooLarge);
//        handlecase(InternalError);
        handlecase(InvalidAccessKeyId);
        handlecase(InvalidAddressingHeader);
        handlecase(InvalidArgument);
        handlecase(InvalidBucketName);
        handlecase(InvalidKey);
        handlecase(InvalidBucketState);
        handlecase(InvalidDigest);
        handlecase(InvalidLocationConstraint);
        handlecase(InvalidObjectState); 
        handlecase(InvalidPart);
        handlecase(InvalidPartOrder);
        handlecase(InvalidPayer);
        handlecase(InvalidPolicyDocument);
        handlecase(InvalidRange);
		handlecase(InvalidRedirectLocation);
        handlecase(InvalidRequest);
        handlecase(InvalidSecurity);
        handlecase(InvalidSOAPRequest);
        handlecase(InvalidStorageClass);
        handlecase(InvalidTargetBucketForLogging);
        handlecase(InvalidToken);
        handlecase(InvalidURI);
//        handlecase(KeyTooLong);
        handlecase(MalformedACLError);
	 handlecase(MalformedPolicy);
        handlecase(MalformedPOSTRequest);
        handlecase(MalformedXML);
        handlecase(MaxMessageLengthExceeded);
        handlecase(MaxPostPreDataLengthExceededError);
        handlecase(MetadataTooLarge);
        handlecase(MethodNotAllowed);
        handlecase(MissingAttachment);
        handlecase(MissingContentLength);
        handlecase(MissingRequestBodyError);
        handlecase(MissingSecurityElement);
        handlecase(MissingSecurityHeader);
        handlecase(NoLoggingStatusForKey);
        handlecase(NoSuchBucket);
        handlecase(NoSuchKey);
        handlecase(NoSuchLifecycleConfiguration);
        handlecase(NoSuchUpload); 
        handlecase(NoSuchVersion); 
        handlecase(NotImplemented);
        handlecase(NotSignedUp);
        handlecase(NotSuchBucketPolicy);
        handlecase(OperationAborted);
        handlecase(PermanentRedirect);
        handlecase(PreconditionFailed);
        handlecase(Redirect);
        handlecase(RestoreAlreadyInProgress);
        handlecase(RequestIsNotMultiPartContent);
        handlecase(RequestTimeout);
        handlecase(RequestTimeTooSkewed);
        handlecase(RequestTorrentOfBucketError);
        handlecase(SignatureDoesNotMatch);
        handlecase(ServiceUnavailable);
        handlecase(SlowDown);
        handlecase(TemporaryRedirect);
        handlecase(TokenRefreshRequired);
        handlecase(TooManyBuckets);
        handlecase(UnexpectedContent);
        handlecase(UnresolvableGrantByEmailAddress);
        handlecase(UserKeyMustBeSpecified);
        handlecase(ErrorUnknown);    
        handlecase(HttpErrorMovedTemporarily);
        handlecase(HttpErrorBadRequest);
        handlecase(HttpErrorForbidden);
        handlecase(HttpErrorNotFound);
        handlecase(HttpErrorConflict);
		handlecase(InsufficientStorageSpace);
		handlecase(NoSuchWebsiteConfiguration);
		handlecase(NoSuchBucketPolicy);
		handlecase(NoSuchCORSConfiguration);
		handlecase(HttpErrorUnknown);
        handlecase(InvalidParameter);
		handlecase(PartialFile);
		// Add InArrearOrInsufficientBalance error code by cwx298983 2016.9.18 Start
		handlecase(InArrearOrInsufficientBalance);
		// Add InArrearOrInsufficientBalance error code by cwx298983 2016.9.18 End
		//lint +e30 +e142
    }

    return "Unknown";
}
//lint +e101

S3Status S3_validate_bucket_name(const char *bucketName, S3UriStyle uriStyle)//lint !e601
{
    int virtualHostStyle = (uriStyle == S3UriStyleVirtualHost);
    int len = 0, maxlen = virtualHostStyle ? 63 : 255;
    const char *b = bucketName;

    int hasDot = 0;
    int hasNonDigit = 0;
    
    while (*b) {
        if (len == maxlen) {
                       
            return S3StatusInvalidBucketNameTooLong;
        }
        else if (isalpha(*b)) {
            len++, b++;
            hasNonDigit = 1;
        }
        else if (isdigit(*b)) {
            len++, b++;
        }
        else if (len == 0) {
                        
            return S3StatusInvalidBucketNameFirstCharacter;
        }
        else if (*b == '_') {
            /* Virtual host style bucket names cannot have underscores */
            if (virtualHostStyle) {
                
                return S3StatusInvalidBucketNameCharacter;
            }
            len++, b++;
            hasNonDigit = 1;
        }
        else if (*b == '-') {
            /* Virtual host style bucket names cannot have .- */
            if (virtualHostStyle && (b > bucketName) && (*(b - 1) == '.')) {
                
                return S3StatusInvalidBucketNameCharacterSequence;
            }
            len++, b++;
            hasNonDigit = 1;
        }
        else if (*b == '.') {
            /* Virtual host style bucket names cannot have -. */
            if (virtualHostStyle && (b > bucketName) && (*(b - 1) == '-')) {
                
                return S3StatusInvalidBucketNameCharacterSequence;
            }
            len++, b++;
            hasDot = 1;
        }
        else {
            
            return S3StatusInvalidBucketNameCharacter;
        }
    }

    if (len < 3) {
         
        return S3StatusInvalidBucketNameTooShort;
    }

    /* It's not clear from Huawei's documentation exactly what 'IP address
       style' means.  In its strictest sense, it could mean 'could be a valid
       IP address', which would mean that 255.255.255.255 would be invalid,
       wherase 256.256.256.256 would be valid.  Or it could mean 'has 4 sets
       of digits separated by dots'.  Who knows.  Let's just be really
       conservative here: if it has any dots, and no non-digit characters,
       then we reject it */
    if (hasDot && !hasNonDigit) {
        
        return S3StatusInvalidBucketNameDotQuadNotation;
    }
    
    return S3StatusOK;
}


typedef struct ConvertAclData
{
    char *ownerId;
    int ownerIdLen;
    char *ownerDisplayName;
    int ownerDisplayNameLen;
    int *aclGrantCountReturn;
    S3AclGrant *aclGrants;//lint !e601

    string_buffer(emailAddress, S3_MAX_GRANTEE_EMAIL_ADDRESS_SIZE);
    string_buffer(userId, S3_MAX_GRANTEE_USER_ID_SIZE);
    string_buffer(userDisplayName, S3_MAX_GRANTEE_DISPLAY_NAME_SIZE);
    string_buffer(groupUri, 128);
    string_buffer(permission, 32);
} ConvertAclData;


static S3Status convertAclXmlCallback(const char *elementPath,
                                      const char *data, int dataLen,
                                      void *callbackData)
{
    ConvertAclData *caData = (ConvertAclData *) callbackData;//lint !e78 !e63 !e530

    int fit;

    if (data) {
        if (!strcmp(elementPath, "AccessControlPolicy/Owner/ID")) {
            caData->ownerIdLen += 
                snprintf_s(&(caData->ownerId[caData->ownerIdLen]),
						 S3_MAX_GRANTEE_USER_ID_SIZE + 1 - caData->ownerIdLen,
                         S3_MAX_GRANTEE_USER_ID_SIZE - caData->ownerIdLen - 1,
                         "%.*s", dataLen, data);
            if (caData->ownerIdLen >= S3_MAX_GRANTEE_USER_ID_SIZE) {
                return S3StatusUserIdTooLong;
            }
        }
        else if (!strcmp(elementPath, "AccessControlPolicy/Owner/"
                         "DisplayName")) {
            caData->ownerDisplayNameLen += 
                snprintf_s(&(caData->ownerDisplayName[caData->ownerDisplayNameLen]),
						   S3_MAX_GRANTEE_DISPLAY_NAME_SIZE + 1 - caData->ownerDisplayNameLen,
                         S3_MAX_GRANTEE_DISPLAY_NAME_SIZE - caData->ownerDisplayNameLen - 1, 
                         "%.*s", dataLen, data);
            if (caData->ownerDisplayNameLen >= 
                S3_MAX_GRANTEE_DISPLAY_NAME_SIZE) {
                return S3StatusUserDisplayNameTooLong;
            }
        }
        else if (!strcmp(elementPath, 
                    "AccessControlPolicy/AccessControlList/Grant/"
                    "Grantee/EmailAddress")) {
            // HuaweiCustomerByEmail
            string_buffer_append(caData->emailAddress, data, dataLen, fit);
            if (!fit) {
                return S3StatusEmailAddressTooLong;
            }
        }
        else if (!strcmp(elementPath,
                         "AccessControlPolicy/AccessControlList/Grant/"
                         "Grantee/ID")) {
            // CanonicalUser
            string_buffer_append(caData->userId, data, dataLen, fit);
            if (!fit) {
                return S3StatusUserIdTooLong;
            }
        }
        else if (!strcmp(elementPath,
                         "AccessControlPolicy/AccessControlList/Grant/"
                         "Grantee/DisplayName")) {
            // CanonicalUser
            string_buffer_append(caData->userDisplayName, data, dataLen, fit);
            if (!fit) {
                return S3StatusUserDisplayNameTooLong;
            }
        }
        else if (!strcmp(elementPath,
                         "AccessControlPolicy/AccessControlList/Grant/"
                         "Grantee/URI")) {
            // Group
            string_buffer_append(caData->groupUri, data, dataLen, fit);
            if (!fit) {
                return S3StatusGroupUriTooLong;
            }
        }
        else if (!strcmp(elementPath,
                         "AccessControlPolicy/AccessControlList/Grant/"
                         "Permission")) {
            // Permission
            string_buffer_append(caData->permission, data, dataLen, fit);
            if (!fit) {
                return S3StatusPermissionTooLong;
            }
        }
    }
    else {
        if (!strcmp(elementPath, "AccessControlPolicy/AccessControlList/"
                    "Grant")) {
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
                       caData->emailAddress);
            }
            else if (caData->userId[0] && caData->userDisplayName[0]) {
                grant->granteeType = S3GranteeTypeCanonicalUser;
                strcpy_s(grant->grantee.canonicalUser.id, sizeof(grant->grantee.canonicalUser.id), caData->userId);
                strcpy_s(grant->grantee.canonicalUser.displayName, 
						sizeof(grant->grantee.canonicalUser.displayName),
                       caData->userDisplayName);
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
                else if (!strcmp(caData->groupUri,
                                 ACS_GROUP_LOG_DELIVERY)) {
                    grant->granteeType = S3GranteeTypeLogDelivery;
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


S3Status S3_convert_acl(char *aclXml, char *ownerId, char *ownerDisplayName,
                        int *aclGrantCountReturn, S3AclGrant *aclGrants)
{    
	COMMLOG(OBS_LOGINFO, "Enter %s successfully !", __FUNCTION__);// add log by jwx329074 2016.11.02
    ConvertAclData data;
	memset_s(&data, sizeof(data), 0, sizeof(ConvertAclData));

    data.ownerId = ownerId;
    data.ownerIdLen = 0;
    data.ownerId[0] = 0;
    data.ownerDisplayName = ownerDisplayName;
    data.ownerDisplayNameLen = 0;
    data.ownerDisplayName[0] = 0;
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
	memset_s(&simpleXml,sizeof(simpleXml), 0, sizeof(SimpleXml));
    simplexml_initialize(&simpleXml, &convertAclXmlCallback, &data);

    S3Status status = simplexml_add(&simpleXml, aclXml, strlen(aclXml));

    simplexml_deinitialize(&simpleXml);

	COMMLOG(OBS_LOGINFO, "Leave %s successfully !", __FUNCTION__);
    return status;
}

//lint -e30 -e142 -e101
int S3_status_is_retryable(S3Status status) //lint !e578
{
    switch (status) {
    case S3StatusNameLookupError:
    case S3StatusFailedToConnect:
    case S3StatusConnectionFailed:
    case S3StatusInternalError:
    case S3StatusOperationAborted:
    case S3StatusRequestTimeout:
	// Ôö¼ÓPartial File´íÎó add by cwx298983 2016.11.01
	case S3StatusPartialFile:
        return 1;
    default:
        return 0;
    }
}
//lint +e30 +e142 +e101