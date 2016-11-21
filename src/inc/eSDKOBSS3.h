/** **************************************************************************
 * eSDKOBSS3.h
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

#ifndef ESDKOBSS3_H
#define ESDKOBSS3_H

#include <stdint.h>
#if defined __GNUC__ || defined LINUX
#include <sys/select.h>
#else 
#include <winsock2.h>
#endif 

#ifdef WIN32
	#ifdef OBS_EXPORTS
		#define eSDK_OBS_API __declspec(dllexport)
	#else
		#define eSDK_OBS_API __declspec(dllimport)
	#endif
#else
		#define eSDK_OBS_API __attribute__((__visibility__("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif


/** **************************************************************************
 * Overview
 * --------
 *
 * This library provides an API for using Huawei's S3 service 
 * .  Its design goals are:
 *
 * - To provide a simple and straightforward API for accessing all of S3's
 *   functionality
 * - To not require the developer using libs3 to need to know anything about:
 *     - HTTP
 *     - XML
 *     - SSL
 *   In other words, this API is meant to stand on its own, without requiring
 *   any implicit knowledge of how S3 services are accessed using HTTP
 *   protocols.
 * - To be usable from multithreaded code
 * - To be usable by code which wants to process multiple S3 requests
 *   simultaneously from a single thread
 * - To be usable in the simple, straightforward way using sequentialized
 *   blocking requests
 *
 * The general usage pattern of libs3 is:
 *
 * - Initialize libs3 once per program by calling S3_initialize() at program
 *   start up time
 * - Make any number of requests to S3 for getting, putting, or listing
 *   S3 buckets or objects, or modifying the ACLs associated with buckets
 *   or objects, using one of three general approaches:
 *   1. Simple blocking requests, one at a time
 *   2. Multiple threads each making simple blocking requests
 *   3. From a single thread, managing multiple S3 requests simultaneously
 *      using file descriptors and a select()/poll() loop
 * - Shut down libs3 at program exit time by calling S3_deinitialize()
 *
 * All functions which send requests to S3 return their results via a set of
 * callback functions which must be supplied to libs3 at the time that the
 * request is initiated.  libs3 will call these functions back in the thread
 * calling the libs3 function if blocking requests are made (i.e., if the
 * S3RequestContext for the function invocation is passed in as NULL).
 * If an S3RequestContext is used to drive multiple S3 requests
 * simultaneously, then the callbacks will be made from the thread which
 * calls S3_runall_request_context() or S3_runonce_request_context(), or
 * possibly from the thread which calls S3_destroy_request_context(), if
 * S3 requests are in progress at the time that this function is called.
 *
 * NOTE: Response headers from Huawei S3 are limited to 4K (2K of metas is all
 * that Huawei supports, and libs3 allows Huawei an additional 2K of headers).
 *
 * NOTE: Because HTTP and the S3 REST protocol are highly under-specified,
 * libs3 must make some assumptions about the maximum length of certain HTTP
 * elements (such as headers) that it will accept.  While efforts have been
 * made to enforce maximums which are beyond that expected to be needed by any
 * user of S3, it is always possible that these maximums may be too low in
 * some rare circumstances.  Bug reports should this unlikely situation occur
 * would be most appreciated.
 * 
 * Threading Rules
 * ---------------
 * 
 * 1. All arguments passed to any function must not be modified directly until
 *    the function returns.
 * 2. All S3RequestContext and S3Request arguments passed to all functions may
 *    not be passed to any other libs3 function by any other thread until the
 *    function returns.
 * 3. All functions may be called simultaneously by multiple threads as long
 *    as (1) and (2) are observed, EXCEPT for S3_initialize(), which must be
 *    called from one thread at a time only.
 * 4. All callbacks will be made in the thread of the caller of the function
 *    which invoked them, so the caller of all libs3 functions should not hold
 *    locks that it would try to re-acquire in a callback, as this may
 *    deadlock.
 ************************************************************************** **/


/** **************************************************************************
 * Constants
 ************************************************************************** **/

/**
 * S3_MAX_HOSTNAME_SIZE is the maximum size we allow for a host name
 **/
#define S3_MAX_HOSTNAME_SIZE               255

/**
 * This is the default hostname that is being used for the S3 requests
 **/
#define S3_DEFAULT_HOSTNAME                "obs.huawei.com"


/**
 * S3_MAX_BUCKET_NAME_SIZE is the maximum size of a bucket name.
 **/

#define S3_MAX_BUCKET_NAME_SIZE            255

/**
 * S3_MAX_KEY_SIZE is the maximum size of keys that Huawei S3 supports.
 **/
#define S3_MAX_KEY_SIZE                    1024


/**
 * S3_MAX_METADATA_SIZE is the maximum number of bytes allowed for
 * x-amz-meta header names and values in any request passed to Huawei S3
 **/
#define S3_MAX_METADATA_SIZE               2048


/**
 * S3_METADATA_HEADER_NAME_PREFIX is the prefix of an S3 "meta header"
 **/
#define S3_METADATA_HEADER_NAME_PREFIX     "x-amz-meta-"


/**
 * S3_MAX_METADATA_COUNT is the maximum number of x-amz-meta- headers that
 * could be included in a request to S3.  The smallest meta header is
 * "x-amz-meta-n: v".  Since S3 doesn't count the ": " against the total, the
 * smallest amount of data to count for a header would be the length of
 * "x-amz-meta-nv".
 **/
#define S3_MAX_METADATA_COUNT \
    (S3_MAX_METADATA_SIZE / (sizeof(S3_METADATA_HEADER_NAME_PREFIX "nv") - 1))


/**
 * S3_MAX_ACL_GRANT_COUNT is the maximum number of ACL grants that may be
 * set on a bucket or object at one time.  It is also the maximum number of
 * ACL grants that the XML ACL parsing routine will parse.
 **/
#define S3_MAX_ACL_GRANT_COUNT             100


/**
 * This is the maximum number of characters (including terminating \0) that
 * libs3 supports in an ACL grantee email address.
 **/
#define S3_MAX_GRANTEE_EMAIL_ADDRESS_SIZE  128


/**
 * This is the maximum number of characters (including terminating \0) that
 * libs3 supports in an ACL grantee user id.
 **/
#define S3_MAX_GRANTEE_USER_ID_SIZE        128


/**
 * This is the maximum number of characters (including terminating \0) that
 * libs3 supports in an ACL grantee user display name.
 **/
#define S3_MAX_GRANTEE_DISPLAY_NAME_SIZE   128


/**
 * This is the maximum number of characters that will be stored in the
 * return buffer for the utility function which computes an HTTP authenticated
 * query string
 **/
#define S3_MAX_AUTHENTICATED_QUERY_STRING_SIZE \
    (sizeof("https:///") + S3_MAX_HOSTNAME_SIZE + (S3_MAX_KEY_SIZE * 3) + \
     sizeof("?AWSAccessKeyId=") + 32 + sizeof("&Expires=") + 32 + \
     sizeof("&Signature=") + 28 + 1)


/**
 * This constant is used by the S3_initialize() function, to specify that
 * the winsock library should be initialized by libs3; only relevent on 
 * Microsoft Windows platforms.
 **/
#define S3_INIT_WINSOCK                    1


/**
 * This convenience constant is used by the S3_initialize() function to
 * indicate that all libraries required by libs3 should be initialized.
 **/
#define S3_INIT_ALL                        (S3_INIT_WINSOCK)




/**
 * This is the maximum number of characters (including terminating \0) that
 * libs3 supports in an ACL grantee email address.
 **/
#define S3_MAX_DELETE_OBJECT_NUMBER  100



/**
 * This is the maximum number of objects that
 * libs3 supports batch delete.
 **/
#define S3_MAX_DELETE_OBJECT_NUMBER  100


/** **************************************************************************
 * Enumerations
 ************************************************************************** **/

/**
 * S3Status is a status code as returned by a libs3 function.  The meaning of
 * each status code is defined in the comments for each function which returns
 * that status.
 **/

//lint -strong(AXJ,S3Status) <选项是以注释的形式插入代码中>
typedef enum
{
    S3StatusOK											,
    /*
     * Errors that prevent the S3 request from being issued or response from
     * being read
     */
    S3StatusInternalError									,
    S3StatusOutOfMemory									,
    S3StatusInterrupted									,
    S3StatusInvalidBucketNameTooLong						,
    S3StatusInvalidBucketNameFirstCharacter					,
    S3StatusInvalidBucketNameCharacter						,
    S3StatusInvalidBucketNameCharacterSequence				,
    S3StatusInvalidBucketNameTooShort						,
    S3StatusInvalidBucketNameDotQuadNotation					,
    S3StatusQueryParamsTooLong								,
    S3StatusFailedToInitializeRequest						,
    S3StatusMetaDataHeadersTooLong							,
    S3StatusBadMetaData									,
    S3StatusBadContentType									,
    S3StatusContentTypeTooLong								,
    S3StatusBadMD5										,
    S3StatusMD5TooLong									,
    S3StatusBadCacheControl								,
    S3StatusCacheControlTooLong							,
    S3StatusBadContentDispositionFilename                   ,
    S3StatusContentDispositionFilenameTooLong				,
    S3StatusBadContentEncoding								,
    S3StatusContentEncodingTooLong							,
    S3StatusBadIfMatchETag									,
    S3StatusIfMatchETagTooLong								,
    S3StatusBadIfNotMatchETag								,
    S3StatusIfNotMatchETagTooLong							,
    S3StatusHeadersTooLong									,
    S3StatusKeyTooLong									,
    S3StatusUriTooLong									,
    S3StatusXmlParseFailure								,
    S3StatusEmailAddressTooLong							,
    S3StatusUserIdTooLong									,
    S3StatusUserDisplayNameTooLong							,
    S3StatusGroupUriTooLong								,
    S3StatusPermissionTooLong								,
    S3StatusTargetBucketTooLong							,
    S3StatusTargetPrefixTooLong							,
    S3StatusTooManyGrants									,
    S3StatusBadGrantee									,
    S3StatusBadPermission									,
    S3StatusXmlDocumentTooLarge							,
    S3StatusNameLookupError								,
    S3StatusFailedToConnect								,
    S3StatusServerFailedVerification						,
    S3StatusConnectionFailed								,
    S3StatusAbortedByCallback								,
    S3StatusInvalidParameter								,
    S3StatusPartialFile									,
    
    /**
     * Errors from the S3 service
     **/
	S3StatusAccessDenied									,
	S3StatusAccountProblem									,
	S3StatusAmbiguousGrantByEmailAddress					,
	S3StatusBadDigest										,
	S3StatusBucketAlreadyExists 							,
	S3StatusBucketAlreadyOwnedByYou 						,
	S3StatusBucketNotEmpty									,
	S3StatusCredentialsNotSupported 						,
	S3StatusCrossLocationLoggingProhibited					,
	S3StatusEntityTooSmall									,
	S3StatusEntityTooLarge									,
	S3StatusExpiredToken									,
	S3StatusIllegalVersioningConfigurationException			,
	S3StatusIncompleteBody									,
	S3StatusIncorrectNumberOfFilesInPostRequest				,
	S3StatusInlineDataTooLarge								,
//	S3StatusInternalError									,
	S3StatusInvalidAccessKeyId								,
	S3StatusInvalidAddressingHeader 						,
	S3StatusInvalidArgument 								,
	S3StatusInvalidBucketName								,
    S3StatusInvalidKey									,
	S3StatusInvalidBucketState								,
	S3StatusInvalidDigest									,
	S3StatusInvalidLocationConstraint						,
	S3StatusInvalidObjectState								,
	S3StatusInvalidPart 									,
	S3StatusInvalidPartOrder								,
	S3StatusInvalidPayer									,
	S3StatusInvalidPolicyDocument							,
	S3StatusInvalidRange									,
	S3StatusInvalidRedirectLocation							,
	S3StatusInvalidRequest									,
	S3StatusInvalidSecurity 								,
	S3StatusInvalidSOAPRequest								,
	S3StatusInvalidStorageClass 							,
	S3StatusInvalidTargetBucketForLogging					,
	S3StatusInvalidToken									,
	S3StatusInvalidURI									,
//	S3StatusKeyTooLong										,
	S3StatusMalformedACLError								,
	S3StatusMalformedPolicy								,
	S3StatusMalformedPOSTRequest							,
	S3StatusMalformedXML									,
	S3StatusMaxMessageLengthExceeded						,
	S3StatusMaxPostPreDataLengthExceededError				,
	S3StatusMetadataTooLarge								,
	S3StatusMethodNotAllowed								,
	S3StatusMissingAttachment								,
	S3StatusMissingContentLength							,
	S3StatusMissingRequestBodyError 						,
	S3StatusMissingSecurityElement							,
	S3StatusMissingSecurityHeader							,
	S3StatusNoLoggingStatusForKey							,
	S3StatusNoSuchBucket									,
	S3StatusNoSuchKey										,
	S3StatusNoSuchLifecycleConfiguration					,
	S3StatusNoSuchUpload									,
	S3StatusNoSuchVersion									,
	S3StatusNotImplemented									,
	S3StatusNotSignedUp 									,
	S3StatusNotSuchBucketPolicy 							,
	S3StatusOperationAborted								,
	S3StatusPermanentRedirect								,
	S3StatusPreconditionFailed								,
	S3StatusRedirect										,
	S3StatusRestoreAlreadyInProgress						,
	S3StatusRequestIsNotMultiPartContent					,
	S3StatusRequestTimeout									,
	S3StatusRequestTimeTooSkewed							,
 	S3StatusRequestTorrentOfBucketError                     ,
    S3StatusSignatureDoesNotMatch							,
    S3StatusServiceUnavailable								,
    S3StatusSlowDown										,
    S3StatusTemporaryRedirect								,
    S3StatusTokenRefreshRequired							,
    S3StatusTooManyBuckets									,
    S3StatusUnexpectedContent								,
    S3StatusUnresolvableGrantByEmailAddress					,
    S3StatusUserKeyMustBeSpecified							,
	S3StatusInsufficientStorageSpace						,
	S3StatusNoSuchWebsiteConfiguration						,
	S3StatusNoSuchBucketPolicy								,
	S3StatusNoSuchCORSConfiguration							,
	// Add InArrearOrInsufficientBalance error code by cwx298983 2016.9.18 Start
	S3StatusInArrearOrInsufficientBalance					,
	// Add InArrearOrInsufficientBalance error code by cwx298983 2016.9.18 End
    S3StatusErrorUnknown									,
    /*
     * The following are HTTP errors returned by S3 without enough detail to
     * distinguish any of the above S3StatusError conditions
     */
    S3StatusHttpErrorMovedTemporarily                       ,
    S3StatusHttpErrorBadRequest							,
    S3StatusHttpErrorForbidden								,
    S3StatusHttpErrorNotFound                              ,
    S3StatusHttpErrorConflict                              ,
    S3StatusHttpErrorUnknown
} S3Status;


/**
 * S3Protocol represents a protocol that may be used for communicating a
 * request to the Huawei S3 service.
 *
 * In general, HTTPS is greatly preferred (and should be the default of any
 * application using libs3) because it protects any data being sent to or
 * from S3 using strong encryption.  However, HTTPS is much more CPU intensive
 * than HTTP, and if the caller is absolutely certain that it is OK for the
 * data to be viewable by anyone in transit, then HTTP can be used.
 **/
typedef enum
{
    S3ProtocolHTTPS                     = 0,
    S3ProtocolHTTP                      = 1
} S3Protocol;


typedef enum
{
    AuthorizationV2,
    AuthorizationV4
} S3Authorization;

/**
 * S3UriStyle defines the form that an Huawei S3 URI identifying a bucket or
 * object can take.  They are of these forms:
 *
 * Virtual Host: ${protocol}://${bucket}.obs.huawei.com/[${key}]
 * Path: ${protocol}://obs.huawei.com/${bucket}/[${key}]
 *
 * It is generally better to use the Virual Host URI form, because it ensures
 * that the bucket name used is compatible with normal HTTP GETs and POSTs of
 * data to/from the bucket.  However, if DNS lookups for the bucket are too
 * slow or unreliable for some reason, Path URI form may be used.
 **/
typedef enum
{
    S3UriStyleVirtualHost               = 0,
    S3UriStylePath                      = 1
} S3UriStyle;


/**
 * S3GranteeType defines the type of Grantee used in an S3 ACL Grant.
 * Huawei Customer By Email - identifies the Grantee using their Huawei S3
 *     account email address
 * Canonical User - identifies the Grantee by S3 User ID and Display Name,
 *     which can only be obtained by making requests to S3, for example, by
 *     listing owned buckets
 * All AWS Users - identifies all authenticated AWS users
 * All Users - identifies all users
 * Log Delivery - identifies the Huawei group responsible for writing
 *                server access logs into buckets
 **/
typedef enum
{
    S3GranteeTypeHuaweiCustomerByEmail  = 0,
    S3GranteeTypeCanonicalUser          = 1,
    S3GranteeTypeAllAwsUsers            = 2,
    S3GranteeTypeAllUsers               = 3,
    S3GranteeTypeLogDelivery            = 4
} S3GranteeType;


/**
 * serverside encryption parameters
 **/
typedef struct ServerSideEncryptionParams
{
	char use_kms;
	char use_ssec;
	char *kmsServerSideEncryption;
	char *kmsKeyId;
	char *kmsEncryptionContext;
	char *ssecCustomerAlgorithm;
	char *ssecCustomerKey;
	char *ssecCustomerKeyMD5;
	char *des_ssecCustomerAlgorithm;
	char *des_ssecCustomerKey;
	char *des_ssecCustomerKeyMD5;
}ServerSideEncryptionParams;


/**
 * This is an individual permission granted to a grantee in an S3 ACL Grant.
 * Read permission gives the Grantee the permission to list the bucket, or
 *     read the object or its metadata
 * Write permission gives the Grantee the permission to create, overwrite, or
 *     delete any object in the bucket, and is not supported for objects
 * ReadACP permission gives the Grantee the permission to read the ACP for
 *     the bucket or object; the owner of the bucket or object always has
 *     this permission implicitly
 * WriteACP permission gives the Grantee the permission to overwrite the ACP
 *     for the bucket or object; the owner of the bucket or object always has
 *     this permission implicitly
 * FullControl permission gives the Grantee all permissions specified by the
 *     Read, Write, ReadACP, and WriteACP permissions
 **/
typedef enum
{
    S3PermissionRead                    = 0,
    S3PermissionWrite                   = 1,
    S3PermissionReadACP                 = 2,
    S3PermissionWriteACP                = 3,
    S3PermissionFullControl             = 4
} S3Permission;


/**
 * S3CannedAcl is an ACL that can be specified when an object is created or
 * updated.  Each canned ACL has a predefined value when expanded to a full
 * set of S3 ACL Grants.
 * Private canned ACL gives the owner FULL_CONTROL and no other permissions
 *     are issued
 * Public Read canned ACL gives the owner FULL_CONTROL and all users Read
 *     permission 
 * Public Read Write canned ACL gives the owner FULL_CONTROL and all users
 *     Read and Write permission
 * AuthenticatedRead canned ACL gives the owner FULL_CONTROL and authenticated
 *     S3 users Read permission
 **/
typedef enum
{
    S3CannedAclPrivate                  = 0, /* private */
    S3CannedAclPublicRead               = 1, /* public-read */
    S3CannedAclPublicReadWrite          = 2, /* public-read-write */
    S3CannedAclAuthenticatedRead        = 3, /* authenticated-read */
    S3CannedAclBucketOwnerRead			= 4, /*bucket-owner-read*/
    S3CannedAclBucketOwnerFullControl	= 5, /*bucket-owner-full-control*/
    S3CannedAclLogDeliveryWrite			= 6	 /*log-delivery-write*/
} S3CannedAcl;


/** **************************************************************************
 * Data Types
 ************************************************************************** **/

/**
 * An S3RequestContext manages multiple S3 requests simultaneously; see the
 * S3_XXX_request_context functions below for details
 **/
typedef struct S3RequestContext S3RequestContext;


/**
 * S3NameValue represents a single Name - Value pair, used to represent either
 * S3 metadata associated with a key, or S3 error details.
 **/
typedef struct S3NameValue
{
    /**
     * The name part of the Name - Value pair
     **/
    const char *name;

    /**
     * The value part of the Name - Value pair
     **/
    const char *value;
} S3NameValue;


/**
 * S3ResponseProperties is passed to the properties callback function which is
 * called when the complete response properties have been received.  Some of
 * the fields of this structure are optional and may not be provided in the
 * response, and some will always be provided in the response.
 **/
typedef struct S3ResponseProperties
{
    /**
     * This optional field identifies the request ID and may be used when
     * reporting problems to Huawei.
     **/
    const char *requestId;

    /**
     * This optional field identifies the request ID and may be used when
     * reporting problems to Huawei.
     **/
    const char *requestId2;

    /**
     * This optional field is the content type of the data which is returned
     * by the request.  If not provided, the default can be assumed to be
     * "binary/octet-stream".
     **/
    const char *contentType;

    /**
     * This optional field is the content length of the data which is returned
     * in the response.  A negative value means that this value was not
     * provided in the response.  A value of 0 means that there is no content
     * provided.  A positive value gives the number of bytes in the content of
     * the response.
     **/
    uint64_t contentLength;

    /**
     * This optional field names the server which serviced the request.
     **/
    const char *server;

    /**
     * This optional field provides a string identifying the unique contents
     * of the resource identified by the request, such that the contents can
     * be assumed not to be changed if the same eTag is returned at a later
     * time decribing the same resource.  This is an MD5 sum of the contents.
     **/
	const char *eTag;
	/**
	*It describes the detailed date information objects
	**/
    const char *expiration;
	/**
	*website redirect location
	**/
    const char *websiteRedirectLocation;
	/**
	*version ID
	**/
    const char *versionId;

    /**
     * This optional field provides the last modified time, relative to the
     * Unix epoch, of the contents.  If this value is < 0, then the last
     * modified time was not provided in the response.  If this value is >= 0,
     * then the last modified date of the contents are available as a number
     * of seconds since the UNIX epoch.
     * 
     **/
    int64_t lastModified;

    /**
     * This is the number of user-provided meta data associated with the
     * resource.
     **/
    int metaDataCount;

    /**
     * These are the meta data associated with the resource.  In each case,
     * the name will not include any S3-specific header prefixes
     * (i.e. x-amz-meta- will have been removed from the beginning), and
     * leading and trailing whitespace will have been stripped from the value.
     **/
    const S3NameValue *metaData;

    /**
     * This optional field provides an indication of whether or not
     * server-side encryption was used for the object.  This field is only
     * meaningful if the request was an object put, copy, get, or head
     * request.
     * If this value is 0, then server-side encryption is not in effect for
     * the object (or the request was one for which server-side encryption is
     * not a meaningful value); if this value is non-zero, then server-side
     * encryption is in effect for the object.
     **/
    char usesServerSideEncryption;

	
	/**
	*CorsConf
	*Access-Control-Allow-Origin
	**/
    const char *allowOrigin;
	/**
	*Access-Control-Allow-Headers
	**/
	const char *allowHeaders;
	/**
	*Access-Control-Max-Age
	**/
	const char *maxAge;
	/**
	*Access-Control-Allow-Methods
	**/
	const char *allowMethods;
	/**
	*Access-Control-Expose-Headers
	**/
	const char *exposeHeaders;

	const char *serverSideEncryption;

	const char *kmsKeyId;

	const char *customerAlgorithm;

	const char *customerKeyMD5;
	
} S3ResponseProperties;


/**
 * S3AclGrant identifies a single grant in the ACL for a bucket or object.  An
 * ACL is composed of any number of grants, which specify a grantee and the
 * permissions given to that grantee.  S3 does not normalize ACLs in any way,
 * so a redundant ACL specification will lead to a redundant ACL stored in S3.
 **/
typedef struct S3AclGrant
{
    /**
     * The granteeType gives the type of grantee specified by this grant.
     **/
    S3GranteeType granteeType;
    /**
     * The identifier of the grantee that is set is determined by the
     * granteeType:
     *
     * S3GranteeTypeHuaweiCustomerByEmail - huaweiCustomerByEmail.emailAddress
     * S3GranteeTypeCanonicalUser - canonicalUser.id, canonicalUser.displayName
     * S3GranteeTypeAllAwsUsers - none
     * S3GranteeTypeAllUsers - none
     **/
    union
    {
        /**
         * This structure is used iff the granteeType is 
         * S3GranteeTypeHuaweiCustomerByEmail.
         **/
        struct
        {
            /**
             * This is the email address of the Huawei Customer being granted
             * permissions by this S3AclGrant.
             **/
            char emailAddress[S3_MAX_GRANTEE_EMAIL_ADDRESS_SIZE];
        } huaweiCustomerByEmail;
        /**
         * This structure is used iff the granteeType is
         * S3GranteeTypeCanonicalUser.
         **/
        struct
        {
            /**
             * This is the CanonicalUser ID of the grantee
             **/
            char id[S3_MAX_GRANTEE_USER_ID_SIZE];
            /**
             * This is the display name of the grantee
             **/
            char displayName[S3_MAX_GRANTEE_DISPLAY_NAME_SIZE];
        } canonicalUser;
    } grantee;
    /**
     * This is the S3Permission to be granted to the grantee
     **/
    S3Permission permission;
} S3AclGrant;


/**
 * A context for working with objects within a bucket.  A bucket context holds
 * all information necessary for working with a bucket, and may be used
 * repeatedly over many consecutive (or simultaneous) calls into libs3 bucket
 * operation functions.
 **/
typedef struct S3BucketContext
{
    /**
     * The name of the host to connect to when making S3 requests.  If set to
     * NULL, the default S3 hostname passed in to S3_initialize will be used.
     **/
    const char *hostName;

    /**
     * The name of the bucket to use in the bucket context
     **/
    const char *bucketName;

    /**
     * The protocol to use when accessing the bucket
     **/
    S3Protocol protocol;

    /**
     * The URI style to use for all URIs sent to Huawei S3 while working with
     * this bucket context
     **/
    S3UriStyle uriStyle;

    /**
     * The Huawei Access Key ID to use for access to the bucket
     **/
    const char *accessKeyId;

    /**
     *  The Huawei Secret Access Key to use for access to the bucket
     **/
    const char *secretAccessKey;
	
	/**
     *  The information of the certificate that used by Https
     **/
    const char *certificateInfo;
} S3BucketContext;

/**
 *批量删除对象中传入
 **/

typedef struct S3DelBucketInfo
{
	/**
	*bucket object key
	**/
	const char* key;
	/**
	*version ID
	**/
	const char* versionId;
}S3DelBucketInfo;

/**
 *合并段中传入
 **/

typedef struct S3UploadInfo
{
	/**
	 *段号
	 **/
	
	const char* partNumber;
	/**
	 *对应段的ETag值
	 **/
	const char* eTag;
}S3UploadInfo;

/**
 * This is a single entry supplied to the list bucket callback by a call to
 * S3_list_bucket.  It identifies a single matching key from the list
 * operation.
 **/
typedef struct S3ListBucketContent
{
    /**
     * This is the next key in the list bucket results.
     **/
    const char *key;

    /**
     * This is the number of seconds since UNIX epoch of the last modified
     * date of the object identified by the key. 
     **/
    int64_t lastModified;

    /**
     * This gives a tag which gives a signature of the contents of the object,
     * which is the MD5 of the contents of the object.
     **/
    const char *eTag;

    /**
     * This is the size of the object in bytes.
     **/
    uint64_t size;

    /**
     * This is the ID of the owner of the key; it is present only if access
     * permissions allow it to be viewed.
     **/
    const char *ownerId;

    /**
     * This is the display name of the owner of the key; it is present only if
     * access permissions allow it to be viewed.
     **/
    const char *ownerDisplayName;
} S3ListBucketContent;

/**
 *列出多段上传任务中回调函数使用
 **/
typedef struct S3ListMultipartUpload
{
	/**
	 *初始化Multipart Upload任务的Object名字
	 **/
    const char *key;
	/**
	 *Multipart Upload任务的ID
	 **/
    const char *uploadId;
	/**
	 *创建者的CanonicalUserId
	 **/
    const char *initiatorId;
	/**
	 *创建者的名字
	 **/
    const char *initiatorDisplayName;
	/**
	 *创建者的CanonicalUserId
	 **/
    const char *ownerId;
	/**
	 *创建者的名字
	 **/
    const char *ownerDisplayName;
	/**
	 *表明待多段上传的对象存储类型
	 **/
    const char *storageClass;
	/**
	 *Multipart Upload任务的初始化时间
	 **/
    int64_t		initiated;
} S3ListMultipartUpload;

/**
 *批量删除对象中回调函数使用
 **/
typedef struct S3DeleteObjects
{
	/**
	 *每个删除结果的对象名
	 **/
    const char *key;
	/**
	 *删除失败结果的错误码
	 **/
    const char *code;
	/**
	 *删除失败结果的错误消息
	 **/
    const char *message;
	/**
	 *当批量删除请求访问的桶是多版本桶时，如果创建或删除一个删除标记，返回消息中该元素的值为true
	 **/
    const char *deleteMarker;
	/**
	 *请求创建或删除的删除标记版本号
	 **/
    const char *deleteMarkerVersionId;
} S3DeleteObjects;


/**
 * This is a single entry supplied to the list versions callback by a call to
 * ListVersions.  It identifies a single matching key from the list
 * operation.
 **/
typedef struct S3Version
{
	/**
     * This is the next key in the list bucket results.
     **/
    const char *key;

	/**
     * This is the version id .
     **/
	const char *versionId;

    /**
     * This indicates whether the object is th latest or not.True means the latest.
     **/
	const char *isLatest;

    /**
     * This is the number of seconds since UNIX epoch of the last modified
     * date of the object identified by the key. 
     **/
    int64_t lastModified;

    /**
     * This gives a tag which gives a signature of the versions of the object,
     * which is the MD5 of the versions of the object.
     **/
    const char *eTag;

    /**
     * This is the size of the object in bytes.
     **/
    uint64_t size;

    /**
     * This is the ID of the owner of the key; it is present only if access
     * permissions allow it to be viewed.
     **/
    const char *ownerId;

    /**
     * This is the display name of the owner of the key; it is present only if
     * access permissions allow it to be viewed.
     **/
    const char *ownerDisplayName;
	
	/**
     * This is the display name of the owner of the key; it is present only if
     * access permissions allow it to be viewed.
     **/
	const char *storageClass;
} S3Version;

typedef struct S3ListVersions
{
	/**
     * 桶名。
     **/
	const char* bucketName;
	
	/**
     * 对象名的前缀，表示本次请求只列举对象名能匹配该前缀的所有对象。
     **/
	const char* prefix;
	 
	/**
     * 列举对象时的起始位置。
     **/
	const char* keyMarker;
	 
	/**
     * 请求中带的Delimiter。
     **/
	const char* delimiter;
	
	/**
     * 列举时最多返回的对象个数。
     **/
	const char* maxKeys;
	
	/**
     * 保存版本信息的容器。
     **/
	S3Version* versions;
	
	/**
     * 容器的个数。
     **/
	int versionsCount;
	
	/**
     * 请求中带delimiter参数时，返回消息带CommonPrefixes分组信息。
     **/
	const char** commonPrefixes;
	
	/**
     * commonPrefixes的数目
     **/
	int commonPrefixesCount;
} S3ListVersions;

typedef struct S3ListParts
{
    /**
     * The uploaded part's number.
     **/
	const char *partNumber;
    /**
     * This is the number of seconds since UNIX epoch of the last modified
     * date of the object identified by the key. 
     **/
   	int64_t lastModified;
    /**
     * This gives a tag which gives a signature of the parts of the object,
     * which is the MD5 of the parts of the object.
     **/
    const char *eTag;
    /**
     * This is the size of the object in bytes.
     **/
    uint64_t size;
}S3ListParts;

/**
 * S3GetConditions is used for the get_object operation, and specifies
 * conditions which the object must meet in order to be successfully returned.
 **/
typedef struct S3GetConditions
{
    /**
     * The request will be processed if the Last-Modification header of the
     * object is greater than or equal to this value, specified as a number of
     * seconds since Unix epoch.  If this value is less than zero, it will not
     * be used in the conditional.
     **/
    int64_t ifModifiedSince;

    /**
     * The request will be processed if the Last-Modification header of the
     * object is less than this value, specified as a number of seconds since
     * Unix epoch.  If this value is less than zero, it will not be used in
     * the conditional.
     **/
    int64_t ifNotModifiedSince;

    /**
     * If non-NULL, this gives an eTag header value which the object must
     * match in order to be returned.  Note that altough the eTag is simply an
     * MD5, this must be presented in the S3 eTag form, which typically
     * includes double-quotes.
     **/
    const char *ifMatchETag;

    /**
     * If non-NULL, this gives an eTag header value which the object must not
     * match in order to be returned.  Note that altough the eTag is simply an
     * MD5, this must be presented in the S3 eTag form, which typically
     * includes double-quotes.
     **/
    const char *ifNotMatchETag;
} S3GetConditions;


/**
 * S3PutProperties is the set of properties that may optionally be set by the
 * user when putting objects to S3.  Each field of this structure is optional
 * and may or may not be present.
 **/
typedef struct S3PutProperties
{
    /**
     * If present, this is the Content-Type that should be associated with the
     * object.  If not provided, S3 defaults to "binary/octet-stream".
     **/
    const char *contentType;

    /**
     * If present, this provides the MD5 signature of the contents, and is
     * used to validate the contents.  This is highly recommended by Huawei
     * but not required.  Its format is as a base64-encoded MD5 sum.
     **/
    const char *md5;

    /**
     * If present, this gives a Cache-Control header string to be supplied to
     * HTTP clients which download this
     **/
    const char *cacheControl;

    /**
     * If present, this gives the filename to save the downloaded file to,
     * whenever the object is downloaded via a web browser.  This is only
     * relevent for objects which are intended to be shared to users via web
     * browsers and which is additionally intended to be downloaded rather
     * than viewed.
     **/
    const char *contentDispositionFilename;

    /**
     * If present, this identifies the content encoding of the object.  This
     * is only applicable to encoded (usually, compressed) content, and only
     * relevent if the object is intended to be downloaded via a browser.
     **/
    const char *contentEncoding;

	const char *storagepolicy;
	const char *websiteredirectlocation;
	// Get conditions
    const S3GetConditions *getConditions;
		
	// Start byte
    uint64_t startByte;

    // Byte count
    uint64_t byteCount;

    /**
     * If >= 0, this gives an expiration date for the content.  This
     * information is typically only delivered to users who download the
     * content via a web browser.
     **/
    int64_t expires;

    /**
     * This identifies the "canned ACL" that should be used for this object.
     * The default (0) gives only the owner of the object access to it.
     **/
    S3CannedAcl cannedAcl;

    /**
     * This is the number of values in the metaData field.
     **/
    int metaDataCount;

    /**
     * These are the meta data to pass to S3.  In each case, the name part of
     * the Name - Value pair should not include any special S3 HTTP header
     * prefix (i.e., should be of the form 'foo', NOT 'x-amz-meta-foo').
     **/
    const S3NameValue *metaData;

    /**
     * This a boolean value indicating whether or not the object should be
     * stored by Huawei S3 using server-side encryption, wherein the data is
     * encrypted by Huawei before being stored on permanent medium.
     * Server-side encryption does not affect the data as it is sent to or
     * received by Huawei, the encryption is applied by Huawei when objects
     * are put and then de-encryption is applied when the objects are read by
     * clients.
     * If this value is 0, then server-side encryption is not used; if this
     * value is non-zero, then server-side encryption is used.  Note that the
     * encryption status of the object can be checked by ensuring that the put
     * response has the usesServerSideEncryption flag set.
     **/
    char useServerSideEncryption;
} S3PutProperties;


/**
 * S3ErrorDetails provides detailed information describing an S3 error.  This
 * is only presented when the error is an S3-generated error (i.e. one of the
 * S3StatusErrorXXX values).
 **/

//lint -strong(AXJ,S3ErrorDetails) <选项是以注释的形式插入代码中>
typedef struct S3ErrorDetails
{
    /**
     * This is the human-readable message that Huawei supplied describing the
     * error
     **/
    const char *message;

    /**
     * This identifies the resource for which the error occurred
     **/
    const char *resource;

    /**
     * This gives human-readable further details describing the specifics of
     * this error
     **/
    const char *furtherDetails;

    /**
     * This gives the number of S3NameValue pairs present in the extraDetails
     * array
     **/
    int extraDetailsCount;

    /**
     * S3 can provide extra details in a freeform Name - Value pair format.
     * Each error can have any number of these, and this array provides these
     * additional extra details.
     **/
    S3NameValue *extraDetails;
} S3ErrorDetails;

/**
 *设置桶的Website配置中传入
 **/
typedef struct S3SetBucketRedirectAllConf
{
	/**
	 * 描述重定向的站点名
	 **/
	const char *hostName;
	/**
	 * 描述重定向请求时使用的协议（http，https），默认使用http协议
	 **/
	const char *protocol;
}S3SetBucketRedirectAllConf;


/**
 * 设置桶的Website配置中传入
 **/
typedef struct S3SetBucketWebsiteConfIn
{
	/**
	 * 描述当重定向生效时对象名的前缀
	 **/
	const char *keyPrefixEquals;
	/**
	 * 描述Redirect生效时的HTTP错误码
	 **/
	const char *httpErrorCodeReturnedEquals;

	/**
	 * 描述重定向请求时使用的协议
	 **/
	const char *protocol;
	/**
	 *描述重定向的站点名
	 **/
	const char *hostName;
	/**
	 *描述重定向请求时使用的对象名前缀
	 **/
	const char *replaceKeyPrefixWith;
	/**
	 * 描述重定向请求时使用的对象名
	 **/
	const char *replaceKeyWith;
	/**
	 *描述响应中的HTTP状态码
	 **/
	const char *httpRedirectCode;

}S3SetBucketWebsiteConfIn;


/**
 * 设置桶的Website配置中传入
 **/
typedef struct S3SetBucketWebsiteConf
{
	/**
	 * Suffix 元素被追加在对文件夹的请求的末尾
	 **/
	const char *suffix;
	/**
	 * 指定了当错误出现时返回的页面
	 **/
	const char *key;

	/**
	 * 重定向结构体
	 **/
	S3SetBucketWebsiteConfIn* stIn;
	/**
	 * 重定向结构体个数
	 **/
	int stCount;
}S3SetBucketWebsiteConf;


/**
*桶的CORS配置参数
**/
typedef struct S3BucketCorsConf
{
	/**
	 * 一条Rule的标识，由不超过255个字符的字符串组成
	 **/
	const char *id;

	/**
	 * CORS规则允许的Method
	 **/
	const char **allowedMethod;

	/**
	 * Method 的数目
	 **/
	unsigned int amNumber;

	/**
	 * CORS规则允许的Origin
	 **/
	const char **allowedOrigin;

	/**
	 * Origin 的数目
	 **/
	unsigned int aoNumber;

	/**
	 * 配置CORS请求中允许携带的“Access-Control-Request-Headers”头域
	 **/
	const char **allowedHeader;

	/**
	 *  Access-Control-Request-Headers的数目
	 **/
	unsigned int ahNumber;

	/**
	 * 客户端可以缓存的CORS响应时间，以秒为单位
	 **/
	const char *maxAgeSeconds;

	/**
	 * CORS响应中带的附加头域
	 **/
	const char **exposeHeader;

	/**
	 * 附加头域的数目
	 **/
	unsigned int ehNumber;
}S3BucketCorsConf;

/**
*桶的生命周期配置参数
**/
typedef struct S3BucketLifeCycleConf
{
	/**
	 * 表示规则生效的时间
	 **/
	const char *date;

	/**
	 * 表示在对象创建时间后第几天时规则生效
	 **/
	const char *days;

	/**
	 * 一条Rule的标识，由不超过255个字符的字符串组成
	 **/
	const char *id;

	/**
	 * 对象名前缀，用以标识哪些对象可以匹配到当前这条Rule
	 **/
	const char *prefix;

	/**
	 * 标识当前这条Rule是否启用
	 **/
	const char *status;

	
}S3BucketLifeCycleConf;

/** **************************************************************************
 * Callback Signatures
 ************************************************************************** **/

/**
 * This callback is made whenever the response properties become available for
 * any request.
 *
 * @param properties are the properties that are available from the response
 * @param callbackData is the callback data as specified when the request
 *        was issued.
 * @return S3StatusOK to continue processing the request, anything else to
 *         immediately abort the request with a status which will be
 *         passed to the S3ResponseCompleteCallback for this request.
 *         Typically, this will return either S3StatusOK or
 *         S3StatusAbortedByCallback.
 **/
typedef S3Status (S3ResponsePropertiesCallback)
    (const S3ResponseProperties *properties, void *callbackData);


/**
 * This callback is made when the response has been completely received, or an
 * error has occurred which has prematurely aborted the request, or one of the
 * other user-supplied callbacks returned a value intended to abort the
 * request.  This callback is always made for every request, as the very last
 * callback made for that request.
 *
 * @param status gives the overall status of the response, indicating success
 *        or failure; use S3_status_is_retryable() as a simple way to detect
 *        whether or not the status indicates that the request failed but may
 *        be retried.
 * @param errorDetails if non-NULL, gives details as returned by the S3
 *        service, describing the error
 * @param callbackData is the callback data as specified when the request
 *        was issued.
 **/
typedef void (S3ResponseCompleteCallback)(S3Status status,
                                          const S3ErrorDetails *errorDetails,
                                          void *callbackData);

                                    
/**
 * This callback is made for each bucket resulting from a list service
 * operation.
 *
 * @param ownerId is the ID of the owner of the bucket
 * @param ownerDisplayName is the owner display name of the owner of the bucket
 * @param bucketName is the name of the bucket
 * @param creationDateSeconds if < 0 indicates that no creation date was
 *        supplied for the bucket; if >= 0 indicates the number of seconds
 *        since UNIX Epoch of the creation date of the bucket
 * @param callbackData is the callback data as specified when the request
 *        was issued.
 * @return S3StatusOK to continue processing the request, anything else to
 *         immediately abort the request with a status which will be
 *         passed to the S3ResponseCompleteCallback for this request.
 *         Typically, this will return either S3StatusOK or
 *         S3StatusAbortedByCallback.
 **/
typedef S3Status (S3ListServiceCallback)(const char *ownerId, 
                                         const char *ownerDisplayName,
                                         const char *bucketName,
                                         int64_t creationDateSeconds,
                                         void *callbackData);
/**
 * 合并段中回调
 *
 * @参数 location 合并后得到的对象的url
 * @参数 bucket 合并段所在的桶
 * @参数 key 合并得到对象的key
 * @参数 eTag 根据各个段的ETag计算得出的结果
 * @参数 callbackData 回调数据
 * @返回 S3Status 返回执行结果
 **/
typedef S3Status (S3CompleteMultipartUploadCallback)(const char *location, 
                                         const char *bucket,
                                         const char *key,
                                         const char* eTag,
                                         void *callbackData);

/**
 * This callback is made repeatedly as a list bucket operation progresses.
 * The contents reported via this callback are only reported once per list
 * bucket operation, but multiple calls to this callback may be necessary to
 * report all items resulting from the list bucket operation.
 *
 * @param isTruncated is true if the list bucket request was truncated by the
 *        S3 service, in which case the remainder of the list may be obtained
 *        by querying again using the Marker parameter to start the query
 *        after this set of results
 * @param nextMarker if present, gives the largest (alphabetically) key
 *        returned in the response, which, if isTruncated is true, may be used
 *        as the marker in a subsequent list buckets operation to continue
 *        listing
 * @param contentsCount is the number of ListBucketContent structures in the
 *        contents parameter
 * @param contents is an array of ListBucketContent structures, each one
 *        describing an object in the bucket
 * @param commonPrefixesCount is the number of common prefixes strings in the
 *        commonPrefixes parameter
 * @param commonPrefixes is an array of strings, each specifing one of the
 *        common prefixes as returned by S3
 * @param callbackData is the callback data as specified when the request
 *        was issued.
 * @return S3StatusOK to continue processing the request, anything else to
 *         immediately abort the request with a status which will be
 *         passed to the S3ResponseCompleteCallback for this request.
 *         Typically, this will return either S3StatusOK or
 *         S3StatusAbortedByCallback.
 **/
typedef S3Status (S3ListBucketCallback)(int isTruncated,
											const char *nextMarker,
											int contentsCount, 
											const S3ListBucketContent *contents,
											int commonPrefixesCount,
											const char **commonPrefixes,
											void *callbackData);
/**
 * 列出多段上传任务中回调
 *
 * @参数 isTruncated 表明是否本次返回的Multipart Upload结果列表被截断。"true"表示本次没有返回全部结果；"false"表示本次已经返回了全部结果.
 * @参数 nextMarker 如果本次没有返回全部结果，响应请求中将包含NextKeyMarker字段，用于标明接下来请求的KeyMarker值
 * @参数 nextUploadIdMarker 如果本次没有返回全部结果，响应请求中将包含NextUploadMarker字段，用于标明接下来请求的UploadMarker值。
 * @参数 uploadsCount 返回多段上传任务条数
 * @参数 uploads 返回多段上传任务明细
 * @参数 commonPrefixesCount 是参数commonPrefixes中common prefixes字符串的数目
 * @参数 commonPrefixes 是一个字符串数组，其中每个成员是S3返回的common prefix
 * @参数 callbackData 回调数据
 * @返回 S3Status 返回执行结果
 **/										   
typedef S3Status (S3ListMultipartUploadsCallback)(int isTruncated,
      								    const char *nextMarker,
      								    const char*nextUploadIdMarker,
									    int uploadsCount, 
										const S3ListMultipartUpload *uploads,
										int commonPrefixesCount,
										const char **commonPrefixes,
										void *callbackData);
																				  

/**
 * 列举桶内对象（含多版本）中回调
 *
 * @参数 isTruncated 表明是否本次返回的ListVersionsResult结果列表被截断。"true"表示本次没有返回全部结果；"false"表示本次已经返回了全部结果
 * @参数 nextKeyMarker 如果本次没有返回全部结果，响应请求中将包含该元素，用于标明接下来请求的KeyMarker值
 * @参数 nextVersionIdMarker 如果本次没有返回全部结果，响应请求中将包含该元素，用于标明接下来请求的VersionIdMarker值
 * @参数 versions 对象明细
 * @参数 callbackData 回调数据
 * @返回 S3Status 返回执行结果
 **/		
typedef S3Status (S3ListVersionsCallback)(int isTruncated,
	const char *nextKeyMarker,
	const char *nextVersionIdMarker,
	const S3ListVersions *listVersions,
	void *callbackData);

/**
 * This callback is made during a put object operation, to obtain the next
 * chunk of data to put to the S3 service as the contents of the object.  This
 * callback is made repeatedly, each time acquiring the next chunk of data to
 * write to the service, until a negative or 0 value is returned.
 *
 * @param bufferSize gives the maximum number of bytes that may be written
 *        into the buffer parameter by this callback
 * @param buffer gives the buffer to fill with at most bufferSize bytes of
 *        data as the next chunk of data to send to S3 as the contents of this
 *        object
 * @param callbackData is the callback data as specified when the request
 *        was issued.
 * @return < 0 to abort the request with the S3StatusAbortedByCallback, which
 *        will be pased to the response complete callback for this request, or
 *        0 to indicate the end of data, or > 0 to identify the number of
 *        bytes that were written into the buffer by this callback
 **/
typedef int (S3PutObjectDataCallback)(int bufferSize, char *buffer,
                                      void *callbackData);

/**
 *上传段的回调函数
 *
 * @参数 bufferSize 缓存字符串长度
 * @参数 buffer 缓存字符串
 * @参数 callbackData 回调数据
 * @返回 S3Status 返回执行结果
 **/		
 typedef int (S3UploadDataCallback)(int bufferSize, char *buffer,
                                      void *callbackData);
/**
 * This callback is made during a get object operation, to provide the next
 * chunk of data available from the S3 service constituting the contents of
 * the object being fetched.  This callback is made repeatedly, each time
 * providing the next chunk of data read, until the complete object contents
 * have been passed through the callback in this way, or the callback
 * returns an error status.
 *
 * @param bufferSize gives the number of bytes in buffer
 * @param buffer is the data being passed into the callback
 * @param callbackData is the callback data as specified when the request
 *        was issued.
 * @return S3StatusOK to continue processing the request, anything else to
 *         immediately abort the request with a status which will be
 *         passed to the S3ResponseCompleteCallback for this request.
 *         Typically, this will return either S3StatusOK or
 *         S3StatusAbortedByCallback.
 **/
typedef S3Status (S3GetObjectDataCallback)(int bufferSize, const char *buffer,
                                           void *callbackData);



typedef S3Status (S3DeleteObjectDataCallback)(int contentsCount, 
                                         S3DeleteObjects *contents,
                                         void *callbackData);                                       

/**
 *  列出已上传的段中回调
 *
 * @参数 isTruncated 表明是否本次返回的ListVersionsResult结果列表被截断。"true"表示本次没有返回全部结果；"false"表示本次已经返回了全部结果
 * @参数 nextPartNumberMarker 如果本次没有返回全部结果，响应请求中将包含NextPartNumberMarker元素，用于标明接下来请求的PartNumberMarker值
 * @参数 initiatorId Upload任务的创建者的CanonicalUserId
 * @参数 initiatorDisplayName Upload任务的创建者的名字
 * @参数 ownerId Upload任务的创建者的CanonicalUserId
 * @参数 ownerDisplayName Upload任务的创建者的名字
 * @参数 partsCount 上传段的个数
 * @参数 parts 上传段明细
 * @参数 callbackData 回调数据
 * @返回 S3Status 返回执行结果
 **/		
 typedef S3Status (S3ListPartsCallback)(int isTruncated,
                               const char *nextPartNumberMarker,
                               const char *initiatorId,
                               const char *initiatorDisplayName,
                               const char *ownerId,
                               const char *ownerDisplayName,
                               int partsCount, 
                               const S3ListParts *parts,
						       void *callbackData);

/**
 *  获取桶的Website配置中回调函数
 *
 * @参数 hostname 描述重定向的站点名
 * @参数 protocol 描述重定向请求时使用的协议（http，https )
 * @参数 suffix Suffix 元素被追加在对文件夹的请求的末尾
 * @参数 key 指定了当错误出现时返回的页面
 * @参数 websiteconf 重定向内容结构体
 * @参数 webdatacount 结构体个数
 * @参数 callbackData 回调数据
 * @返回 S3Status 返回执行结果
 **/		                                 
typedef S3Status (S3GetBucketWebsiteConfigurationCallback) (const char *hostname,
								const char *protocol,
								const char *suffix,
								const char *key,
								const S3SetBucketWebsiteConfIn *websiteconf,
								int webdatacount,
								void *callbackData);


/**
 *  获取桶的CORS 配置中回调函数
 *
 * @参数 id: 一条Rule的标识，由不超过255个字符的字符串组成
 * @参数 maxAgeSeconds:  客户端可以缓存的CORS响应时间，以秒为单位。 每个CORSRule可以包含至多一个MaxAgeSeconds，可以设 置为负值
 * @参数 allowedMethodCount : Methodd 的个数
 * @参数 allowedMethodes: CORS规则允许的Method
 * @参数 allowedOriginCount: Origin的个数
 * @参数 allowedOrigines: CORS规则允许的Origin
 * @参数 allowedHeaderCount: allowedHeaderes的个数
 * @参数 allowedHeaderes:  配置CORS请求中允许携带的"Access-Control-Request- Headers"头域 
 * @参数 exposeHeaderCount: exposeHeaderes的个数
 * @参数 exposeHeaderes:  CORS响应中带的附加头域，给客户端提供额外的信息，不 可出现空格 
 * @参数 callbackData: 回调数据
 * @返回 S3Status: 返回执行结果
 **/		                                 
typedef S3Status (S3GetBucketCorsConfigurationCallback) (const char *id,
								const char *maxAgeSeconds,
								int allowedMethodCount,
								const char** allowedMethodes,
								int allowedOriginCount,
								const char** allowedOrigines,
								int allowedHeaderCount,
								const char**allowedHeaderes,
								int exposeHeaderCount,
								const char**exposeHeaderes,
								void *callbackData);

/**
 *  获取桶的CORS 配置中回调函数(存在多条rule)
 *
 * @参数 bucketCorsConf: 一条Rule所包含的信息
 * @参数 bccNumber:  Rule的数目
 * @参数 callbackData: 回调数据
 * @返回 S3Status: 返回执行结果
  **/	
 typedef S3Status (S3GetBucketCorsConfigurationCallbackEx) (S3BucketCorsConf* bucketCorsConf,
 								unsigned int bccNumber,
								void *callbackData);

/**
 *  获取桶的生命周期 配置中回调函数(存在多条rule)
 *
 * @参数 bucketLifeCycleConf: 一条Rule所包含的信息
 * @参数 blccNumber:  Rule的数目
 * @参数 callbackData: 回调数据
 * @返回 S3Status: 返回执行结果
  **/	
 typedef S3Status (GetBucketLifecycleConfigurationCallbackEx) (S3BucketLifeCycleConf* bucketLifeCycleConf,
 								unsigned int blccNumber,
								void *callbackData);

/** **************************************************************************
 * Callback Structures
 ************************************************************************** **/


/**
 * An S3ResponseHandler defines the callbacks which are made for any
 * request.
 **/
typedef struct S3ResponseHandler
{
    /**
     * The propertiesCallback is made when the response properties have
     * successfully been returned from S3.  This function may not be called
     * if the response properties were not successfully returned from S3.
     **/
    S3ResponsePropertiesCallback *propertiesCallback;
    
    /**
     * The completeCallback is always called for every request made to S3,
     * regardless of the outcome of the request.  It provides the status of
     * the request upon its completion, as well as extra error details in the
     * event of an S3 error.
     **/
    S3ResponseCompleteCallback *completeCallback;
} S3ResponseHandler;


/**
 * An S3ListServiceHandler defines the callbacks which are made for
 * list_service requests.
 **/
typedef struct S3ListServiceHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The listServiceCallback is called as items are reported back from S3 as
     * responses to the request
     **/
    S3ListServiceCallback *listServiceCallback;
} S3ListServiceHandler;


/**
 * An S3ListBucketHandler defines the callbacks which are made for
 * list_bucket requests.
 **/
typedef struct S3ListBucketHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The listBucketCallback is called as items are reported back from S3 as
     * responses to the request.  This may be called more than one time per
     * list bucket request, each time providing more items from the list
     * operation.
     **/
    S3ListBucketCallback *listBucketCallback;
} S3ListBucketHandler;

typedef struct S3ListMultipartUploadsHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The listBucketCallback is called as items are reported back from S3 as
     * responses to the request.  This may be called more than one time per
     * list bucket request, each time providing more items from the list
     * operation.
     **/
    S3ListMultipartUploadsCallback *listMultipartUploadsCallback;
} S3ListMultipartUploadsHandler;


/**
 * An S3PutObjectHandler defines the callbacks which are made for
 * put_object requests.
 **/
typedef struct S3PutObjectHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The putObjectDataCallback is called to acquire data to send to S3 as
     * the contents of the put_object request.  It is made repeatedly until it
     * returns a negative number (indicating that the request should be
     * aborted), or 0 (indicating that all data has been supplied).
     **/
    S3PutObjectDataCallback *putObjectDataCallback;
} S3PutObjectHandler;


/**
 * An S3GetObjectHandler defines the callbacks which are made for
 * get_object requests.
 **/
typedef struct S3GetObjectHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The getObjectDataCallback is called as data is read from S3 as the
     * contents of the object being read in the get_object request.  It is
     * called repeatedly until there is no more data provided in the request,
     * or until the callback returns an error status indicating that the
     * request should be aborted.
     **/
    S3GetObjectDataCallback *getObjectDataCallback;
} S3GetObjectHandler;



/**
 * An S3PutObjectHandler defines the callbacks which are made for
 * put_object requests.
 **/
typedef struct S3DeleteObjectHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The putObjectDataCallback is called to acquire data to send to S3 as
     * the contents of the put_object request.  It is made repeatedly until it
     * returns a negative number (indicating that the request should be
     * aborted), or 0 (indicating that all data has been supplied).
     **/
    S3DeleteObjectDataCallback *deleteObjectDataCallback;
} S3DeleteObjectHandler;

/**
*合并段的回调函数结构体
**/
typedef struct S3CompleteMultipartUploadHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

	/**
	*合并段的回调函数
	**/
    S3CompleteMultipartUploadCallback *completeMultipartUploadCallback;
} S3CompleteMultipartUploadHandler;

/**
*上传段的回调函数结构体
**/
typedef struct S3UploadHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

	/**
	*上传段的回调函数
	**/
    S3UploadDataCallback *uploadDataCallback;
} S3UploadHandler;

/**
*获取桶的CORS 配置的回调函数结构体
**/
typedef struct S3CORSHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

	/**
	*获取桶的CORS 配置的回调函数
	**/
    S3GetBucketCorsConfigurationCallback *getBucketCorsConfigurationCallback;
} S3CORSHandler;

/**
*获取桶的CORS 配置的回调函数结构体(存在多个rule)
**/
typedef struct S3CORSHandlerEx
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

	/**
	*获取桶的CORS 配置的回调函数(存在多个rule)
	**/
    S3GetBucketCorsConfigurationCallbackEx *getBucketCorsConfigurationCallbackEx;
} S3CORSHandlerEx;

/**
 * An S3ListVersionsHandler defines the callbacks which are made for
 * list_versions requests.
 **/
typedef struct S3ListVersionsHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The listBucketCallback is called as items are reported back from S3 as
     * responses to the request.  This may be called more than one time per
     * list bucket request, each time providing more items from the list
     * operation.
     **/
    S3ListVersionsCallback *listVersionsCallback;
} S3ListVersionsHandler;

/**
 * An S3ListPartsHandler defines the callbacks which are made for
 * list_partns requests.
 **/
typedef struct S3ListPartsHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The listPartsCallback is called as items are reported back from S3 as
     * responses to the request.  This may be called more than one time per
     * list part request, each time providing more items from the list
     * operation.
     **/
    S3ListPartsCallback *listPartsCallback;
} S3ListPartsHandler;

/**
*获取桶的Website配置的回调函数结构体
**/
typedef struct S3GetBucketWebsiteConfHandler
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

    /**
     * The getBucketWebsiteConfigurationCallback is called as items are reported back from S3 as
     * responses to the request.  This may be called more than one time per
     * list part request, each time providing more items from the list
     * operation.
     **/
    S3GetBucketWebsiteConfigurationCallback *getBucketWebsiteConfigurationCallback;
} S3GetBucketWebsiteConfHandler;

/**
*获取桶的生命周期配置的回调函数结构体(存在多个rule)
**/
typedef struct S3LifeCycleHandlerEx
{
    /**
     * responseHandler provides the properties and complete callback
     **/
    S3ResponseHandler responseHandler;

	/**
	*获取桶的生命周期 配置的回调函数(存在多个rule)
	**/
    GetBucketLifecycleConfigurationCallbackEx *getBucketLifecycleConfigurationCallbackEx;
} S3LifeCycleHandlerEx;


/** **************************************************************************
 * General Library Functions
 ************************************************************************** **/

/**
 * Initializes libs3 for use.  This function must be called before any other
 * libs3 function is called.  It may be called multiple times, with the same
 * effect as calling it once, as long as S3_deinitialize() is called an
 * equal number of times when the program has finished.  This function is NOT
 * thread-safe and must only be called by one thread at a time.
 *
 * @param userAgentInfo is a string that will be included in the User-Agent
 *        header of every request made to the S3 service.  You may provide
 *        NULL or the empty string if you don't care about this.  The value
 *        will not be copied by this function and must remain unaltered by the
 *        caller until S3_deinitialize() is called.
 * @param flags is a bitmask of some combination of S3_INIT_XXX flag, or
 *        S3_INIT_ALL, indicating which of the libraries that libs3 depends
 *        upon should be initialized by S3_initialize().  Only if your program
 *        initializes one of these dependency libraries itself should anything
 *        other than S3_INIT_ALL be passed in for this bitmask.
 *
 *        You should pass S3_INIT_WINSOCK if and only if your application does
 *        not initialize winsock elsewhere.  On non-Microsoft Windows
 *        platforms it has no effect.
 *
 *        As a convenience, the macro S3_INIT_ALL is provided, which will do
 *        all necessary initialization; however, be warned that things may
 *        break if your application re-initializes the dependent libraries
 *        later.
 * @param defaultS3Hostname is a string the specifies the default S3 server
 *        hostname to use when making S3 requests; this value is used
 *        whenever the hostName of an S3BucketContext is NULL.  If NULL is
 *        passed here then the default of S3_DEFAULT_HOSTNAME will be used.
 * @param auth  AuthorizationV2 or AuthorizationV4 
 * @return One of:
 *         S3StatusOK on success
 *         S3StatusUriTooLong if the defaultS3HostName is longer than
 *             S3_MAX_HOSTNAME_SIZE
 *         S3StatusInternalError if dependent libraries could not be
 *             initialized
 *         S3StatusOutOfMemory on failure due to out of memory
 **/
eSDK_OBS_API S3Status S3_initialize(const char *userAgentInfo, int flags,
                       const char *defaultS3HostName,S3Authorization auth,const char* defaultRegion);


/**
 * Must be called once per program for each call to libs3_initialize().  After
 * this call is complete, no libs3 function may be called except
 * S3_initialize().
 **/
eSDK_OBS_API void S3_deinitialize();


/**
 * Set the timeout of low speed limit
 *
 * param unTimeout is the value of timeout. Unit : second
 **/
 eSDK_OBS_API void S3_setTimeout(unsigned int unTimeout);

/**
 * Returns a string with the textual name of an S3Status code
 *
 * @param status is S3Status code for which the textual name will be returned
 * @return a string with the textual name of an S3Status code
 **/
eSDK_OBS_API const char *S3_get_status_name(S3Status status);


/**
 * This function may be used to validate an S3 bucket name as being in the
 * correct form for use with the S3 service.  Huawei S3 limits the allowed
 * characters in S3 bucket names, as well as imposing some additional rules on
 * the length of bucket names and their structure.  There are actually two
 * limits; one for bucket names used only in path-style URIs, and a more
 * strict limit used for bucket names used in virtual-host-style URIs.  It is
 * advisable to use only bucket names which meet the more strict requirements
 * regardless of how the bucket expected to be used.
 *
 * This method does NOT validate that the bucket is available for use in the
 * S3 service, so the return value of this function cannot be used to decide
 * whether or not a bucket with the give name already exists in Huawei S3 or
 * is accessible by the caller.  It merely validates that the bucket name is
 * valid for use with S3.
 *
 * @param bucketName is the bucket name to validate
 * @param uriStyle gives the URI style to validate the bucket name against.
 *        It is advisable to always use S3UriStyleVirtuallHost.
 * @return One of:
 *         S3StatusOK if the bucket name was validates successfully
 *         S3StatusInvalidBucketNameTooLong if the bucket name exceeded the
 *             length limitation for the URI style, which is 255 bytes for
 *             path style URIs and 63 bytes for virtual host type URIs
 *         S3StatusInvalidBucketNameTooShort if the bucket name is less than
 *             3 characters
 *         S3StatusInvalidBucketNameFirstCharacter if the bucket name as an
 *             invalid first character, which is anything other than
 *             an alphanumeric character
 *         S3StatusInvalidBucketNameCharacterSequence if the bucket name
 *             includes an invalid character sequence, which for virtual host
 *             style buckets is ".-" or "-."
 *         S3StatusInvalidBucketNameCharacter if the bucket name includes an
 *             invalid character, which is anything other than alphanumeric,
 *             '-', '.', or for path style URIs only, '_'.
 *         S3StatusInvalidBucketNameDotQuadNotation if the bucket name is in
 *             dot-quad notation, i.e. the form of an IP address, which is
 *             not allowed by Huawei S3.
 **/
eSDK_OBS_API S3Status S3_validate_bucket_name(const char *bucketName, S3UriStyle uriStyle);


/**
 * Converts an XML representation of an ACL to a libs3 structured
 * representation.  This method is not strictly necessary for working with
 * ACLs using libs3, but may be convenient for users of the library who read
 * ACLs from elsewhere in XML format and need to use these ACLs with libs3.
 *
 * @param aclXml is the XML representation of the ACL.  This must be a
 *        zero-terminated character string.
 * @param ownerId will be filled in with the Owner ID specified in the XML.
 *        At most MAX_GRANTEE_USER_ID_SIZE bytes will be stored at this
 *        location.
 * @param ownerDisplayName will be filled in with the Owner Display Name
 *        specified in the XML.  At most MAX_GRANTEE_DISPLAY_NAME_SIZE bytes
 *        will be stored at this location.
 * @param aclGrantCountReturn returns the number of S3AclGrant structures
 *        returned in the aclGrantsReturned array
 * @param aclGrants must be passed in as an array of at least S3_ACL_MAXCOUNT
 *        structures, and on return from this function, the first
 *        aclGrantCountReturn structures will be filled in with the ACLs
 *        represented by the input XML.
 * @return One of:
 *         S3StatusOK on successful conversion of the ACL
 *         S3StatusInternalError on internal error representing a bug in the
 *             libs3 library
 *         S3StatusXmlParseFailure if the XML document was malformed
 **/
eSDK_OBS_API S3Status S3_convert_acl(char *aclXml, char *ownerId, char *ownerDisplayName,
                        int *aclGrantCountReturn, S3AclGrant *aclGrants);
                        

/**
 * Returns nonzero if the status indicates that the request should be
 * immediately retried, because the status indicates an error of a nature that
 * is likely due to transient conditions on the local system or S3, such as
 * network failures, or internal retryable errors reported by S3.  Returns
 * zero otherwise.
 *
 * @param status is the status to evaluate
 * @return nonzero if the status indicates a retryable error, 0 otherwise
 **/
eSDK_OBS_API int S3_status_is_retryable(S3Status status);


/** **************************************************************************
 * Request Context Management Functions
 ************************************************************************** **/

/**
 * An S3RequestContext allows muliple requests to be serviced by the same
 * thread simultaneously.  It is an optional parameter to all libs3 request
 * functions, and if provided, the request is managed by the S3RequestContext;
 * if not, the request is handled synchronously and is complete when the libs3
 * request function has returned.
 *
 * @param requestContextReturn returns the newly-created S3RequestContext
 *        structure, which if successfully returned, must be destroyed via a
 *        call to S3_destroy_request_context when it is no longer needed.  If
 *        an error status is returned from this function, then
 *        requestContextReturn will not have been filled in, and
 *        S3_destroy_request_context should not be called on it
 * @return One of:
 *         S3StatusOK if the request context was successfully created
 *         S3StatusOutOfMemory if the request context could not be created due
 *             to an out of memory error
 **/
eSDK_OBS_API S3Status S3_create_request_context(S3RequestContext **requestContextReturn);


/**
 * Destroys an S3RequestContext which was created with
 * S3_create_request_context.  Any requests which are currently being
 * processed by the S3RequestContext will immediately be aborted and their
 * request completed callbacks made with the status S3StatusInterrupted.
 *
 * @param requestContext is the S3RequestContext to destroy
 **/
eSDK_OBS_API void S3_destroy_request_context(S3RequestContext *requestContext);


/**
 * Runs the S3RequestContext until all requests within it have completed,
 * or until an error occurs.
 *
 * @param requestContext is the S3RequestContext to run until all requests
 *            within it have completed or until an error occurs
 * @return One of:
 *         S3Status if all requests were successfully run to completion
 *         S3StatusInternalError if an internal error prevented the
 *             S3RequestContext from running one or more requests
 *         S3StatusOutOfMemory if requests could not be run to completion
 *             due to an out of memory error
 **/
eSDK_OBS_API S3Status S3_runall_request_context(S3RequestContext *requestContext);


/**
 * Does some processing of requests within the S3RequestContext.  One or more
 * requests may have callbacks made on them and may complete.  This function
 * processes any requests which have immediately available I/O, and will not
 * block waiting for I/O on any request.  This function would normally be used
 * with S3_get_request_context_fdsets.
 *
 * @param requestContext is the S3RequestContext to process
 * @param requestsRemainingReturn returns the number of requests remaining
 *            and not yet completed within the S3RequestContext after this
 *            function returns.
 * @return One of:
 *         S3StatusOK if request processing proceeded without error
 *         S3StatusInternalError if an internal error prevented the
 *             S3RequestContext from running one or more requests
 *         S3StatusOutOfMemory if requests could not be processed due to
 *             an out of memory error
 **/
eSDK_OBS_API S3Status S3_runonce_request_context(S3RequestContext *requestContext, 
                                    int *requestsRemainingReturn);


/**
 * This function, in conjunction allows callers to manually manage a set of
 * requests using an S3RequestContext.  This function returns the set of file
 * descriptors which the caller can watch (typically using select()), along
 * with any other file descriptors of interest to the caller, and using
 * whatever timeout (if any) the caller wishes, until one or more file
 * descriptors in the returned sets become ready for I/O, at which point
 * S3_runonce_request_context can be called to process requests with available
 * I/O.
 *
 * @param requestContext is the S3RequestContext to get fd_sets from
 * @param readFdSet is a pointer to an fd_set which will have all file
 *        descriptors to watch for read events for the requests in the
 *        S3RequestContext set into it upon return.  Should be zero'd out
 *        (using FD_ZERO) before being passed into this function.
 * @param writeFdSet is a pointer to an fd_set which will have all file
 *        descriptors to watch for write events for the requests in the
 *        S3RequestContext set into it upon return.  Should be zero'd out
 *        (using FD_ZERO) before being passed into this function.
 * @param exceptFdSet is a pointer to an fd_set which will have all file
 *        descriptors to watch for exception events for the requests in the
 *        S3RequestContext set into it upon return.  Should be zero'd out
 *        (using FD_ZERO) before being passed into this function.
 * @param maxFd returns the highest file descriptor set into any of the
 *        fd_sets, or -1 if no file descriptors were set
 * @return One of:
 *         S3StatusOK if all fd_sets were successfully set
 *         S3StatusInternalError if an internal error prevented this function
 *             from completing successfully
 **/
eSDK_OBS_API S3Status S3_get_request_context_fdsets(S3RequestContext *requestContext,
                                       fd_set *readFdSet, fd_set *writeFdSet,
                                       fd_set *exceptFdSet, int *maxFd);


/**
 * This function returns the maximum number of milliseconds that the caller of
 * S3_runonce_request_context should wait on the fdsets obtained via a call to
 * S3_get_request_context_fdsets.  In other words, this is essentially the
 * select() timeout that needs to be used (shorter values are OK, but no
 * longer than this) to ensure that internal timeout code of libs3 can work
 * properly.  This function should be called right before select() each time
 * select() on the request_context fdsets are to be performed by the libs3
 * user.
 *
 * @param requestContext is the S3RequestContext to get the timeout from
 * @return the maximum number of milliseconds to select() on fdsets.  Callers
 *         could wait a shorter time if they wish, but not longer.
 **/
eSDK_OBS_API int64_t S3_get_request_context_timeout(S3RequestContext *requestContext);


/** **************************************************************************
 * S3 Utility Functions
 ************************************************************************** **/

/**
 * Generates an HTTP authenticated query string, which may then be used by
 * a browser (or other web client) to issue the request.  The request is
 * implicitly a GET request; Huawei S3 is documented to only support this type
 * of authenticated query string request.
 *
 * @param buffer is the output buffer for the authenticated query string.
 *        It must be at least S3_MAX_AUTHENTICATED_QUERY_STRING_SIZE bytes in 
 *        length.
 * @param bucketContext gives the bucket and associated parameters for the
 *        request to generate.
 * @param key gives the key which the authenticated request will GET.
 * @param expires gives the number of seconds since Unix epoch for the
 *        expiration date of the request; after this time, the request will
 *        no longer be valid.  If this value is negative, the largest
 *        expiration date possible is used (currently, Jan 19, 2038).
 * @param resource gives a sub-resource to be fetched for the request, or NULL
 *        for none.  This should be of the form "?<resource>", i.e. 
 *        "?torrent".
 * @return One of:
 *         S3StatusUriTooLong if, due to an internal error, the generated URI
 *             is longer than S3_MAX_AUTHENTICATED_QUERY_STRING_SIZE bytes in
 *             length and thus will not fit into the supplied buffer
 *         S3StatusOK on success
 **/
eSDK_OBS_API S3Status S3_generate_authenticated_query_string
    (char *buffer, const S3BucketContext *bucketContext,
     const char *key, int64_t expires, const char *resource);


/** **************************************************************************
 * Service Functions
 ************************************************************************** **/

/**
 * Lists all S3 buckets belonging to the access key id.
 *
 * @param protocol gives the protocol to use for this request
 * @param accessKeyId gives the Huawei Access Key ID for which to list owned
 *        buckets
 * @param secretAccessKey gives the Huawei Secret Access Key for which to list
 *        owned buckets
 * @param hostName is the S3 host name to use; if NULL is passed in, the
 *        default S3 host as provided to S3_initialize() will be used.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

 **/
eSDK_OBS_API void ListBuckets(S3Protocol protocol, const char *accessKeyId,
                     const char *secretAccessKey, const char *hostName,
                     S3RequestContext *requestContext,
                     const S3ListServiceHandler *handler,
                     void *callbackData);

                         

/**
 * Lists all S3 buckets belonging to the access key id.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

 **/
eSDK_OBS_API void ListBucketsCA(const S3BucketContext *bucketContext,
                     S3RequestContext *requestContext,
                     const S3ListServiceHandler *handler,
                     void *callbackData);
					 
						 
						 
/** **************************************************************************
 * Bucket Functions
 ************************************************************************** **/

/**
 * Tests the existence of an S3 bucket, additionally returning the bucket's
 * location if it exists and is accessible.
 *
 * @param protocol gives the protocol to use for this request
 * @param uriStyle gives the URI style to use for this request
 * @param accessKeyId gives the Huawei Access Key ID for which to list owned
 *        buckets
 * @param secretAccessKey gives the Huawei Secret Access Key for which to list
 *        owned buckets
 * @param hostName is the S3 host name to use; if NULL is passed in, the
 *        default S3 host as provided to S3_initialize() will be used.
 * @param bucketName is the bucket name to test
 * @param locationConstraintReturnSize gives the number of bytes in the
 *        locationConstraintReturn parameter
 * @param locationConstraintReturn provides the location into which to write
 *        the name of the location constraint naming the geographic location
 *        of the S3 bucket.  This must have at least as many characters in it
 *        as specified by locationConstraintReturn, and should start out
 *        NULL-terminated.  On successful completion of this request, this
 *        will be set to the name of the geographic location of S3 bucket, or
 *        will be left as a zero-length string if no location was available.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

 **/
eSDK_OBS_API void GetBucketLocation(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int locationConstraintReturnSize,
                    char *locationConstraintReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);



/**
 * Tests the existence of an S3 bucket, additionally returning the bucket's
 * location if it exists and is accessible.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param locationConstraintReturnSize gives the number of bytes in the
 *        locationConstraintReturn parameter
 * @param locationConstraintReturn provides the location into which to write
 *        the name of the location constraint naming the geographic location
 *        of the S3 bucket.  This must have at least as many characters in it
 *        as specified by locationConstraintReturn, and should start out
 *        NULL-terminated.  On successful completion of this request, this
 *        will be set to the name of the geographic location of S3 bucket, or
 *        will be left as a zero-length string if no location was available.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

 **/
eSDK_OBS_API void GetBucketLocationCA(const S3BucketContext *bucketContext,
                    int locationConstraintReturnSize,
                    char *locationConstraintReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);


					
/**
 * Creates a new bucket.
 *
 * @param protocol gives the protocol to use for this request
 * @param accessKeyId gives the Huawei Access Key ID for which to list owned
 *        buckets
 * @param secretAccessKey gives the Huawei Secret Access Key for which to list
 *        owned buckets
 * @param hostName is the S3 host name to use; if NULL is passed in, the
 *        default S3 host as provided to S3_initialize() will be used.
 * @param bucketName is the name of the bucket to be created
 * @param cannedAcl gives the "REST canned ACL" to use for the created bucket
 * @param locationConstraint if non-NULL, gives the geographic location for
 *        the bucket to create.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

 **/
eSDK_OBS_API void CreateBucket(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName, S3CannedAcl cannedAcl,const char*storagepolicy,
                      const char *locationConstraint,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);


/**
 * Creates a new bucket.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param cannedAcl gives the "REST canned ACL" to use for the created bucket
 * @param locationConstraint if non-NULL, gives the geographic location for
 *        the bucket to create.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

 **/
eSDK_OBS_API void CreateBucketCA(const S3BucketContext *bucketContext, 
					  S3CannedAcl cannedAcl,const char*storagepolicy,
                      const char *locationConstraint,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData); 
					  
					  
/**
 * Deletes a bucket.  The bucket must be empty, or the status
 * S3StatusErrorBucketNotEmpty will result.
 *
 * @param protocol gives the protocol to use for this request
 * @param uriStyle gives the URI style to use for this request
 * @param accessKeyId gives the Huawei Access Key ID for which to list owned
 *        buckets
 * @param secretAccessKey gives the Huawei Secret Access Key for which to list
 *        owned buckets
 * @param hostName is the S3 host name to use; if NULL is passed in, the
 *        default S3 host as provided to S3_initialize() will be used.
 * @param bucketName is the name of the bucket to be deleted
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void DeleteBucket(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);


/**
 * Deletes a bucket.  The bucket must be empty, or the status
 * S3StatusErrorBucketNotEmpty will result.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void DeleteBucketCA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  
					  
/**
 * Lists keys within a bucket.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param prefix if present, gives a prefix for matching keys
 * @param marker if present, only keys occuring after this value will be
 *        listed
 * @param delimiter if present, causes keys that contain the same string
 *        between the prefix and the first occurrence of the delimiter to be
 *        rolled up into a single result element
 * @param maxkeys is the maximum number of keys to return
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request


**/

eSDK_OBS_API void ListObjects(const S3BucketContext *bucketContext,
                    const char *prefix, const char *marker, 
                    const char *delimiter, int maxkeys,
                    S3RequestContext *requestContext,
                    const S3ListBucketHandler *handler, void *callbackData);



/** **************************************************************************
 * Object Functions
 ************************************************************************** **/

/**
 * Puts object data to S3.  This overwrites any existing object at that key;
 * note that S3 currently only supports full-object upload.  The data to
 * upload will be acquired by calling the handler's putObjectDataCallback.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to put to
 * @param contentLength is required and gives the total number of bytes that
 *        will be put
 * @param putProperties optionally provides additional properties to apply to
 *        the object that is being put to
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void PutObject(const S3BucketContext *bucketContext, const char *key,
                   uint64_t contentLength,
                   const S3PutProperties *putProperties,
                   S3RequestContext *requestContext,
                   const S3PutObjectHandler *handler, void *callbackData);

eSDK_OBS_API void PutObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	uint64_t contentLength,
	const S3PutProperties *putProperties,ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3PutObjectHandler *handler, void *callbackData);
/**
 * Copies an object from one location to another.  The object may be copied
 * back to itself, which is useful for replacing metadata without changing
 * the object.
 *
 * @param bucketContext gives the source bucket and associated parameters for
 *        this request
 * @param key is the source key
 * @param destinationBucket gives the destination bucket into which to copy
 *        the object.  If NULL, the source bucket will be used.
 * @param destinationKey gives the destination key into which to copy the
 *        object.  If NULL, the source key will be used.
 * @param putProperties optionally provides properties to apply to the object
 *        that is being put to.  If not supplied (i.e. NULL is passed in),
 *        then the copied object will retain the metadata of the copied
 *        object.
 * @param lastModifiedReturn returns the last modified date of the copied
 *        object
 * @param eTagReturnSize specifies the number of bytes provided in the
 *        eTagReturn buffer
 * @param eTagReturn is a buffer into which the resulting eTag of the copied
 *        object will be written
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request
**/

eSDK_OBS_API void CopyObject(const S3BucketContext *bucketContext,
                    const char *key, const char *destinationBucket,
                    const char *destinationKey,const char *versionId, unsigned int nIsCopy,
                    S3PutProperties *putProperties,
                    int64_t *lastModifiedReturn, int eTagReturnSize,
                    char *eTagReturn, S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);

eSDK_OBS_API void CopyObjectWithServerSideEncryption(const S3BucketContext *bucketContext,
	const char *key, const char *destinationBucket,
	const char *destinationKey,const char *versionId, unsigned int nIsCopy,
	S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams,
	int64_t *lastModifiedReturn, int eTagReturnSize,
	char *eTagReturn, S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData);

/**
 * Gets an object from S3.  The contents of the object are returned in the
 * handler's getObjectDataCallback.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to get
 * @param versionId is the version Id of the object to get
 * @param getConditions if non-NULL, gives a set of conditions which must be
 *        met in order for the request to succeed
 * @param startByte gives the start byte for the byte range of the contents
 *        to be returned
 * @param byteCount gives the number of bytes to return; a value of 0
 *        indicates that the contents up to the end should be returned
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

#if defined __GNUC__ || defined LINUX
void GetObject(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData);
void getObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount,ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData);
#else
eSDK_OBS_API void getObject(const S3BucketContext *bucketContext, const char *key,const char* versionId,
                   const S3GetConditions *getConditions,
                   uint64_t startByte, uint64_t byteCount,
                   S3RequestContext *requestContext,
                   const S3GetObjectHandler *handler, void *callbackData);

eSDK_OBS_API void getObjectWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,const char* versionId,
	const S3GetConditions *getConditions,
	uint64_t startByte, uint64_t byteCount,ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3GetObjectHandler *handler, void *callbackData);
#endif
/**
 * Gets the response properties for the object, but not the object contents.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to get the properties of
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void HeadBucket(const S3BucketContext *bucketContext,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);
                         
/**
 * Deletes an object from S3.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to delete
 * @param versionId is the version Id of the object to delete
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

#if defined __GNUC__ || defined LINUX
eSDK_OBS_API void DeleteObject(const S3BucketContext *bucketContext, const char *key,
                      const char* versionId,S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
#else
eSDK_OBS_API void deleteObject(const S3BucketContext *bucketContext, const char *key,
	const char* versionId,S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData);
#endif

/** **************************************************************************
 * Access Control List Functions
 ************************************************************************** **/
/**
 * Gets the ACL for the given bucket or object.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to get the ACL of; or NULL to get the
 *        ACL of the bucket
 * @param ownerId must be supplied as a buffer of at least
 *        S3_MAX_GRANTEE_USER_ID_SIZE bytes, and will be filled in with the
 *        owner ID of the object/bucket
 * @param ownerDisplayName must be supplied as a buffer of at least
 *        S3_MAX_GRANTEE_DISPLAY_NAME_SIZE bytes, and will be filled in with
 *        the display name of the object/bucket
 * @param aclGrantCountReturn returns the number of S3AclGrant structures
 *        returned in the aclGrants parameter
 * @param aclGrants must be passed in as an array of at least
 *        S3_MAX_ACL_GRANT_COUNT S3AclGrant structures, which will be filled
 *        in with the grant information for the ACL
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void GetBucketAcl(const S3BucketContext *bucketContext,
                char *ownerId, char *ownerDisplayName,
                int *aclGrantCountReturn, S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData);
/**
 * Gets the ACL for the given bucket or object.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to get the ACL of; or NULL to get the
 *        ACL of the bucket
 * @param ownerId must be supplied as a buffer of at least
 *        S3_MAX_GRANTEE_USER_ID_SIZE bytes, and will be filled in with the
 *        owner ID of the object/bucket
 * @param ownerDisplayName must be supplied as a buffer of at least
 *        S3_MAX_GRANTEE_DISPLAY_NAME_SIZE bytes, and will be filled in with
 *        the display name of the object/bucket
 * @param aclGrantCountReturn returns the number of S3AclGrant structures
 *        returned in the aclGrants parameter
 * @param aclGrants must be passed in as an array of at least
 *        S3_MAX_ACL_GRANT_COUNT S3AclGrant structures, which will be filled
 *        in with the grant information for the ACL
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void GetObjectAcl(const S3BucketContext *bucketContext, const char *key, 
                const char* versionId,char *ownerId, char *ownerDisplayName,
                int *aclGrantCountReturn, S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData);



/**
 * Sets the ACL for the given bucket or object.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to set the ACL for; or NULL to set the
 *        ACL for the bucket
 * @param ownerId is the owner ID of the object/bucket.  Unfortunately, S3
 *        requires this to be valid and thus it must have been fetched by a
 *        previous S3 request, such as a list_buckets request.
 * @param ownerDisplayName is the owner display name of the object/bucket.
 *        Unfortunately, S3 requires this to be valid and thus it must have
 *        been fetched by a previous S3 request, such as a list_buckets
 *        request.
 * @param aclGrantCount is the number of ACL grants to set for the
 *        object/bucket
 * @param aclGrants are the ACL grants to set for the object/bucket
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request
**/

eSDK_OBS_API void SetBucketAcl(const S3BucketContext *bucketContext,
                const char *ownerId, const char *ownerDisplayName,
                int aclGrantCount, const S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData);
/**
 * Sets the ACL for the given bucket or object.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request
 * @param key is the key of the object to set the ACL for; or NULL to set the
 *        ACL for the bucket
 * @param versionId is the version ID of the Object
 * @param ownerId is the owner ID of the object/bucket.  Unfortunately, S3
 *        requires this to be valid and thus it must have been fetched by a
 *        previous S3 request, such as a list_buckets request.
 * @param ownerDisplayName is the owner display name of the object/bucket.
 *        Unfortunately, S3 requires this to be valid and thus it must have
 *        been fetched by a previous S3 request, such as a list_buckets
 *        request.
 * @param aclGrantCount is the number of ACL grants to set for the
 *        object/bucket
 * @param aclGrants are the ACL grants to set for the object/bucket
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request
**/

eSDK_OBS_API void SetObjectAcl(const S3BucketContext *bucketContext, const char *key, const char *versionId, 
                const char *ownerId, const char *ownerDisplayName,
                int aclGrantCount, const S3AclGrant *aclGrants, 
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData);


/** **************************************************************************
 * Server Access Log Functions
 ************************************************************************** **/

/**
 * Gets the service access logging settings for a bucket.  The service access
 * logging settings specify whether or not the S3 service will write service
 * access logs for requests made for the given bucket, and if so, several
 * settings controlling how these logs will be written.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request; this is the bucket for which service access logging is
 *        being requested
 * @param targetBucketReturn must be passed in as a buffer of at least
 *        (S3_MAX_BUCKET_NAME_SIZE + 1) bytes in length, and will be filled
 *        in with the target bucket name for access logging for the given
 *        bucket, which is the bucket into which access logs for the specified
 *        bucket will be written.  This is returned as an empty string if
 *        service access logging is not enabled for the given bucket.
 * @param targetPrefixReturn must be passed in as a buffer of at least
 *        (S3_MAX_KEY_SIZE + 1) bytes in length, and will be filled in
 *        with the key prefix for server access logs for the given bucket,
 *        or the empty string if no such prefix is specified.
 * @param aclGrantCountReturn returns the number of ACL grants that are
 *        associated with the server access logging for the given bucket.
 * @param aclGrants must be passed in as an array of at least
 *        S3_MAX_ACL_GRANT_COUNT S3AclGrant structures, and these will be
 *        filled in with the target grants associated with the server access
 *        logging for the given bucket, whose number is returned in the
 *        aclGrantCountReturn parameter.  These grants will be applied to the
 *        ACL of any server access logging log files generated by the S3
 *        service for the given bucket.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request

**/

eSDK_OBS_API void GetBucketLoggingConfiguration(const S3BucketContext *bucketContext,
                                  char *targetBucketReturn,
                                  char *targetPrefixReturn,
                                  int *aclGrantCountReturn, 
                                  S3AclGrant *aclGrants,
                                  S3RequestContext *requestContext,
                                  const S3ResponseHandler *handler,
                                  void *callbackData);                                 

/**
 * Sets the service access logging settings for a bucket.  The service access
 * logging settings specify whether or not the S3 service will write service
 * access logs for requests made for the given bucket, and if so, several
 * settings controlling how these logs will be written.
 *
 * @param bucketContext gives the bucket and associated parameters for this
 *        request; this is the bucket for which service access logging is
 *        being set
 * @param targetBucket gives the target bucket name for access logging for the
 *        given bucket, which is the bucket into which access logs for the
 *        specified bucket will be written.
 * @param targetPrefix is an option parameter which specifies the key prefix
 *        for server access logs for the given bucket, or NULL if no such
 *        prefix is to be used.
 * @param aclGrantCount specifies the number of ACL grants that are to be
 *        associated with the server access logging for the given bucket.
 * @param aclGrants is as an array of S3AclGrant structures, whose number is
 *        given by the aclGrantCount parameter.  These grants will be applied
 *        to the ACL of any server access logging log files generated by the
 *        S3 service for the given bucket.
 * @param requestContext if non-NULL, gives the S3RequestContext to add this
 *        request to, and does not perform the request immediately.  If NULL,
 *        performs the request immediately and synchronously.
 * @param handler gives the callbacks to call as the request is processed and
 *        completed 
 * @param callbackData will be passed in as the callbackData parameter to
 *        all callbacks for this request
 

**/

eSDK_OBS_API void SetBucketLoggingConfiguration(const S3BucketContext *bucketContext,
                                  const char *targetBucket, 
                                  const char *targetPrefix, int aclGrantCount, 
                                  const S3AclGrant *aclGrants, 
                                  S3RequestContext *requestContext,
                                  const S3ResponseHandler *handler,
                                  void *callbackData);

/**
 * 获取桶配额
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 uriStyle :URI样式
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 storagequotaReturnSize :返回配额长度
 * @参数 storagequotaReturn :返回配额
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void GetBucketQuota(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int storagequotaReturnSize,
                    char *storagequotaReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);


/**
 * 获取桶配额(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 storagequotaReturnSize :返回配额长度
 * @参数 storagequotaReturn :返回配额
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void GetBucketQuotaCA(const S3BucketContext *bucketContext,
                    int storagequotaReturnSize,
                    char *storagequotaReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);					
					
					
/**
 * 设置桶配额
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 storagequota :设置配额
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void SetBucketQuota(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName,
                      const char *storagequota,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  
					  
/**
 * 设置桶配额(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 storagequota :设置配额
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void SetBucketQuotaCA(const S3BucketContext *bucketContext,
                      const char *storagequota,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  

/**
 * 获取桶存量信息
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 uriStyle :URI样式
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 sizeReturnSize :桶空间大小长度
 * @参数 sizeReturn :桶空间大小
 * @参数 objectnumberReturnSize :桶对象个数长度
 * @参数 objectnumberReturn :桶对象个数
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void GetBucketStorageInfo(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int sizeReturnSize,
                    char *sizeReturn,
                    int objectnumberReturnSize,
                    char *objectnumberReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);
					

/**
 * 获取桶存量信息(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 sizeReturnSize :桶空间大小长度
 * @参数 sizeReturn :桶空间大小
 * @参数 objectnumberReturnSize :桶对象个数长度
 * @参数 objectnumberReturn :桶对象个数
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void GetBucketStorageInfoCA(const S3BucketContext *bucketContext,
                    int sizeReturnSize,
                    char *sizeReturn,
                    int objectnumberReturnSize,
                    char *objectnumberReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);
					

/**
 * 列出多段上传任务
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 prefix :如果请求中指定了prefix，则响应中仅包含对象名以prefix开始的任务信息
 * @参数 marker :列举时返回指定的key-marker之后的多段任务
 * @参数 delimiter :对于名字中包含delimiter的对象的任务，其对象名
 *	（如果请求中指定了prefix，则此处的对象名需要去掉prefix）中从首字符至
 *	第一个delimiter之间的字符串将作为CommonPrefix在响应中返回。对象名包含
 *	CommonPrefix的任务被视为一个分组，作为一条记录在响应中返回，该记录不包含任务
 *	的信息，仅用于提示用户该分组下存在多段上传任务
 * @参数 uploadidmarke :只有和key-marker一起使用才有意义， 列举时返回指定的key-marker的upload-id-marker之后的多段任务
 * @参数 maxuploads :列举的多段任务的最大条目，取值范围为[1,1000]，当超出范围时，按照默认的1000进行处理。
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void ListMultipartUploads(const S3BucketContext *bucketContext, const char *prefix,
                    const char *marker, const char *delimiter,const char* uploadidmarke, int maxuploads,
                    S3RequestContext *requestContext,
                    const S3ListMultipartUploadsHandler *handler, void *callbackData);

/**
 *  设置桶的生命周期配置
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 id :一条Rule的标识，由不超过255个字符的字符串组成
 * @参数 prefix :对象名前缀，用以标识哪些对象可以匹配到当前这条Rule
 * @参数 status :标识当前这条Rule是否启用
 * @参数 days :表示在对象创建时间后第几天时规则生效
 * @参数 date :表示规则生效的时间
 * @参数 putProperties :表示一种发送请求的时候，可以被用户选择性添加的属性设置
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void SetBucketLifecycleConfiguration(const S3BucketContext *bucketContext,const char *id,
                      const char *prefix, const char *status,
                      const char *days,const char *date,const S3PutProperties *putProperties,S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);

/**
 *  设置桶的生命周期配置(设置多条rule)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 bucketLifeCycleConf :一条Rule所包含的信息
 * @参数 blccNumber :rule的数目
 * @参数 putProperties :表示一种发送请求的时候，可以被用户选择性添加的属性设置
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void SetBucketLifecycleConfigurationEx(const S3BucketContext *bucketContext, 
			S3BucketLifeCycleConf* bucketLifeCycleConf, unsigned int blccNumber, const S3PutProperties *putProperties,
			S3RequestContext *requestContext, const S3ResponseHandler *handler, void *callbackData);

/**
 *  获取桶的生命周期配置
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 date :表示规则生效的时间
 * @参数 days :表示在对象创建时间后第几天时规则生效
 * @参数 id :一条Rule的标识，由不超过255个字符的字符串组成
 * @参数 prefix :对象名前缀，用以标识哪些对象可以匹配到当前这条Rule
 * @参数 status :标识当前这条Rule是否启用
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/

eSDK_OBS_API void GetBucketLifecycleConfiguration(const S3BucketContext *bucketContext,
                    char*date,char*days,char*id,char*prefix,char*status,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);

/**
 *  获取桶的生命周期配置(存在多条rule)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/

eSDK_OBS_API void GetBucketLifecycleConfigurationEx(const S3BucketContext *bucketContext,
                    S3RequestContext *requestContext,
                    const S3LifeCycleHandlerEx *handler, void *callbackData);


/**
 * 删除桶的生命周期配置
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 uriStyle :URI样式
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void DeleteBucketLifecycleConfiguration(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  
					  
/**
 * 删除桶的生命周期配置(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void DeleteBucketLifecycleConfigurationCA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  
					  
/**
 * 获取桶策略
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 uriStyle :URI样式
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 policyReturnSize :桶策略字符串长度
 * @参数 policyReturn :桶策略字符串
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void GetBucketPolicy(S3Protocol protocol, S3UriStyle uriStyle,
                    const char *accessKeyId, const char *secretAccessKey,
                    const char *hostName, const char *bucketName,
                    int policyReturnSize,
                    char *policyReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);
					
					
/**
 * 获取桶策略(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 policyReturnSize :桶策略字符串长度
 * @参数 policyReturn :桶策略字符串
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void GetBucketPolicyCA(const S3BucketContext *bucketContext,
                    int policyReturnSize,
                    char *policyReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);					
					
					
/**
 * 上传桶策略
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 uriStyle :URI样式
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 policy :桶策略字符串
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void SetBucketPolicy(S3Protocol protocol, const char *accessKeyId,
                      const char *secretAccessKey, const char *hostName,
                      const char *bucketName,
                      const char *policy,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  
					  
/**
 * 上传桶策略(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 policy :桶策略字符串
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void SetBucketPolicyCA(const S3BucketContext *bucketContext,
                      const char *policy,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
					  
					  
/**
 * 删除桶策略
 *
 * @参数 protocol :请求使用的协议类型
 * @参数 uriStyle :URI样式
 * @参数 accessKeyId :授权者的AK信息。
 * @参数 secretAccessKey :授权者的SK信息。
 * @参数 hostName :请求使用的主机名
 * @参数 bucketName :桶名
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void DeleteBucketPolicy(S3Protocol protocol, S3UriStyle uriStyle,
                      const char *accessKeyId, const char *secretAccessKey,
                      const char *hostName, const char *bucketName,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);


/**
 * 删除桶策略(带证书)
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
 eSDK_OBS_API void DeleteBucketPolicyCA(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);					  
					  

/**
 *  上传段
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 key :对象名称
 * @参数 partNumber :上传段的段号。取值为从1到10000的整数
 * @参数 uploadId :多段上传任务Id
 * @参数 contentLength :上传内容长度
 * @参数 putProperties :表示一种发送请求的时候，可以被用户选择性添加的属性设置
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void UploadPart(const S3BucketContext *bucketContext, const char *key,
                      const char *partNumber,const char *uploadId,uint64_t contentLength,const S3PutProperties *putProperties,
                      S3RequestContext *requestContext,
                      const S3UploadHandler *handler, void *callbackData);

eSDK_OBS_API void UploadPartWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *partNumber,const char *uploadId,uint64_t contentLength,const S3PutProperties *putProperties,ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3UploadHandler *handler, void *callbackData);


/**
 *  拷贝段
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息 
 * @参数 key :对象名称
 * @参数 destinationBucket:拷贝的目标对象所在桶
 * @参数 destinationKey :拷贝的目标对象的名称
 * @参数 startByte :起始字节
 * @参数 byteCount :拷贝长度
 * @参数 partNumber :上传段的段号
 * @参数 uploadId :多段上传任务Id
 * @参数 lastModifiedReturn :对象上次修改时间
 * @参数 eTagReturnSize :源段的ETage值的字符串长度
 * @参数 eTagReturn :源段的ETage值
 * @参数 putProperties :表示一种发送请求的时候，可以被用户选择性添加的属性设置
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 	并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求
 * @参数 callbackData 回调函数中传递的数据
 **/
eSDK_OBS_API void CopyPart(const S3BucketContext *bucketContext, const char *key,
                    const char *destinationBucket, const char *destinationKey,
                    uint64_t startByte,uint64_t byteCount,
                    const char *partNumber,const char *uploadId,int64_t *lastModifiedReturn, int eTagReturnSize,
                    char *eTagReturn, S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);

eSDK_OBS_API void CopyPartWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *destinationBucket, const char *destinationKey,
	uint64_t startByte,uint64_t byteCount,
	const char *partNumber,const char *uploadId,int64_t *lastModifiedReturn, int eTagReturnSize,
	char *eTagReturn, ServerSideEncryptionParams *serverSideEncryptionParams,S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData);


/**
 *  取消多段上传任务
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key : 桶内对象名称；
 * @参数 uploadId: 多段上传任务的 ID ；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *                并且不会立即执行这个请求；如果为空，立即同步执行这个请求。
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void AbortMultipartUpload(const S3BucketContext *bucketContext,const char *key,const char *uploadId,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);

/**
 *  批量删除对象
 *
 * @参数 bucketContext : 表示桶和相关联参数的信息；
 * @参数 delBucketinfo : 删除对象的信息；
 * @参数 keysNumber:  delBucketinfo 的条数；
 * @参数 quiet: 用于指定使用quiet模式，只返回删除失败的对象结果；
                  如果有此字段，则必被置为True，如果为False则被系统忽略掉；
 * @参数 putProperties: 表示一种发送请求的时候，可以被用户选择性添加的属性设置；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *                并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void DeleteObjects(const S3BucketContext *bucketContext, const S3DelBucketInfo *delBucketinfo,
                      const unsigned int keysNumber, int quiet, 
                      const S3PutProperties *putProperties,                      
                      S3RequestContext *requestContext,
                      const S3DeleteObjectHandler *handler, void *callbackData);

/**
 *  初始化上传段任务
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key : 桶内对象名；
 * @参数 putProperties: 表示一种发送请求的时候，可以被用户选择性添加的属性设置；
 * @参数 uploadIdReturnSize: uploadId 字符串大小 ；
 * @参数 uploadIdReturn: 输出参数，上传段 ID；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *                并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void InitiateMultipartUpload(const S3BucketContext *bucketContext,const char* key,const S3PutProperties *putProperties,
                    int uploadIdReturnSize,
                    char *uploadIdReturn,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);

eSDK_OBS_API void InitiateMultipartUploadWithServerSideEncryption(const S3BucketContext *bucketContext,const char* key,const S3PutProperties *putProperties,
	int uploadIdReturnSize,
	char *uploadIdReturn,ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData);


/**
 *  合并段
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key : 桶内对象名称；
 * @参数 uploadId: 多段上传任务的 ID ；
 * @参数 uploadInfo:  上传段信息；
 * @参数 Number:  uploadInfo 的数目；
 * @参数 putProperties: 表示一种发送请求的时候，可以被用户选择性添加的属性设置；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *                并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void CompleteMultipartUpload(const S3BucketContext *bucketContext,const char*key,const char*uploadId,const S3UploadInfo *uploadInfo,
                      const unsigned int Number,const S3PutProperties *putProperties, S3RequestContext *requestContext,
                      const S3CompleteMultipartUploadHandler *handler, void *callbackData);

eSDK_OBS_API void CompleteMultipartUploadWithServerSideEncryption(const S3BucketContext *bucketContext,const char*key,const char*uploadId,const S3UploadInfo *uploadInfo,
	const unsigned int Number,const S3PutProperties *putProperties, ServerSideEncryptionParams *serverSideEncryptionParams,S3RequestContext *requestContext,
	const S3CompleteMultipartUploadHandler *handler, void *callbackData);


/**
 * 设置桶的Website 设置
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 setBucketRedirectAll :重定向所有请求。 与setBucketWebisteConf 不能同时存在；
 * @参数 setBucketWebisteConf: 设定重定向规则。与setBucketRedirectAll 不能同时存在；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *                并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void SetBucketWebsiteConfiguration(const S3BucketContext *bucketContext,
				const S3SetBucketRedirectAllConf *setBucketRedirectAll, const S3SetBucketWebsiteConf *setBucketWebisteConf,
				S3RequestContext *requestContext,
				const S3ResponseHandler *handler, void *callbackData);

	
/**
 * 获取桶的Website 配置
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *		    并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void GetBucketWebsiteConfiguration(const S3BucketContext *bucketContext,
        	                S3RequestContext *requestContext,
                    		const S3GetBucketWebsiteConfHandler *handler, void *callbackData);

eSDK_OBS_API void GetObjectMetadataWithServerSideEncryption(const S3BucketContext *bucketContext, const char *key,
	const char *versionId, ServerSideEncryptionParams *serverSideEncryptionParams,
	S3RequestContext *requestContext,
	const S3ResponseHandler *handler, void *callbackData);


/**
 * 删除桶的多版本状态
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *		     并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void DeleteBucketWebsiteConfiguration(const S3BucketContext *bucketContext,
	                      S3RequestContext *requestContext,
        	              const S3ResponseHandler *handler, void *callbackData);


/**
 * 设置桶的多版本状态
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 statusReturn: 输入参数，设置桶的多版本状态；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *		    并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void SetBucketVersioningConfiguration(const S3BucketContext *bucketContext,
				const char *status,
				S3RequestContext *requestContext,
				const S3ResponseHandler *handler, void *callbackData);


/**
 * 获取桶的多版本状态
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 statusReturnSize :  表示桶的状态字符串的大小；
 * @参数 statusReturn: 输出参数，输出桶的多版本状态；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/

eSDK_OBS_API void GetBucketVersioningConfiguration(const S3BucketContext *bucketContext,
				int statusReturnSize, char *statusReturn,
	                        S3RequestContext *requestContext,
            		        const S3ResponseHandler *handler, void *callbackData);

/**
 * 列举桶内含多版本的对象
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 prefix :列举以指定的字符串prefix开头的对象；
 * @参数 keymarker:列举桶内对象列表时，指定一个标识符， 
 *                返回的对象列表将是按照字典顺序排序后在这个标识符以后的所有对象；
 * @参数 delimiter: 字符串delimiter的第一个字符和字符串prefix之间的字符序列如果相同，
                  则这部分字符序列合并在一起，在返回信息的CommonPrefixes节点显示；
 * @参数 maxkeys: 指定返回的最大对象数，返回的对象列表将是按照字典顺序的最多前max-keys个对象， 
                  范围是[1，1000]，超出范围时，按照默认的1000进行处理；
 * @参数 version_id_marker:  与key-marker配合使用，返回的对象列表将是按照字典顺序排序后
                  在该标识符以后的所有对象。 如果version-id-marker不是key-marker的一个版本号，则该参数无效；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void ListVersions(const S3BucketContext *bucketContext, const char *prefix, const char *keymarker,
					const char *delimiter, int maxkeys, const char *version_id_marker,
                    S3RequestContext *requestContext,
                    const S3ListVersionsHandler *handler, void *callbackData);

/**
 * 列举已经上传的段
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key :桶内对象名；
 * @参数 uploadId: 多段上传任务的 ID ；
 * @参数 max_parts: 规定在列举已上传段响应中的最大Part数目；默认值为1000；
 * @参数 part_number_marker: 指定List的起始位置，只有Part Number数目大于该参数的Part会被列出；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void ListParts(const S3BucketContext *bucketContext, const char *key,
					const char *uploadId,
					const char *max_parts,
					const char *part_number_marker,
                    S3RequestContext *requestContext,
                    const S3ListPartsHandler *handler, void *callbackData);

/**
 * 获取桶对象的元数据
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key :桶内对象名；
 * @参数 versionId: 桶内对象的版本 ID；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void GetObjectMetadata(const S3BucketContext *bucketContext, const char *key,
     				const char *versionId,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);
/**
 * 获取桶的元数据
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void GetBucketMetadata(const S3BucketContext *bucketContext,
                    S3RequestContext *requestContext,
                    const S3ResponseHandler *handler, void *callbackData);

/**
 * 设置桶的CORS 配置
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 id :一条Rule的标识，由不超过255个字符的字符串组成；
 * @参数 allowedMethod: CORS规则允许的Method；
 * @参数 amNumber:Method条数；
 * @参数 allowedOrigin: CORS规则允许的Origin（表示域名的字符串），可以带一个匹配符”*”。
 *	  每一个AllowedOrigin可以带最多一个“*”通配符。
 * @参数 aoNumber: Origin 条数
 * @参数 allowedHeader: 配置CORS请求中允许携带的“Access-Control-Request-Headers”头域。如果一个请求带了“Access-
 *	 Control-Request-Headers”头域，则只有匹配上AllowedHeader中的配置才认为是一个合法的CORS请求。
 *	 每一个AllowedHeader可以带最多一个“*”通配符，不可出现空格。
 * @参数 ahNumber: allowedHeader条数；
 * @参数 maxAgeSeconds: 客户端可以缓存的CORS响应时间，以秒为单位。每个CORSRule可以包含至
 *	  多一个MaxAgeSeconds，可以设置为负值。
 * @参数 exposeHeader: CORS响应中带的附加头域，给客户端提供额外的信息，不可出现空格。
 * @参数 ehNumber: exposeHeader条数；
 * @参数 md5:对象的128位MD5摘要，以Base64编码的方式表示；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/

eSDK_OBS_API void SetBucketCorsConfiguration(const S3BucketContext *bucketContext, const char* id,const char (*allowedMethod)[10],const unsigned int amNumber,
                      const char (*allowedOrigin)[256],const unsigned int aoNumber,const char (*allowedHeader)[256],const unsigned int ahNumber,
                      const char *maxAgeSeconds,const char (*exposeHeader)[256],const unsigned int ehNumber,const char* md5,
                      S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData);


/**
 * 设置桶的CORS 配置(设置多条rule)
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 bucketCorsConf :一条Rule所包含的所有信息；
 * @参数 bccNumber: Rule条数；
 * @参数 md5:对象的128位MD5摘要，以Base64编码的方式表示；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
**/
eSDK_OBS_API void SetBucketCorsConfigurationEx(const S3BucketContext *bucketC, S3BucketCorsConf* bucketCorsConf, const unsigned int bccNumber, const char* md5,
                      S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData);

/**
 * 获取桶的CORS 配置
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/

eSDK_OBS_API void GetBucketCorsConfiguration(const S3BucketContext *bucketContext, 
                    S3RequestContext *requestContext,
                    const S3CORSHandler *handler, void *callbackData);

/**
 * 获取桶的CORS 配置(存在多条rule)
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/

eSDK_OBS_API void GetBucketCorsConfigurationEx(const S3BucketContext *bucketContext, 
                    S3RequestContext *requestContext,
                    const S3CORSHandlerEx *handlerEx, void *callbackData);

/**
 * 删除桶的CORS 配置
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/
eSDK_OBS_API void DeleteBucketCorsConfiguration(const S3BucketContext *bucketContext,
                      S3RequestContext *requestContext,
                      const S3ResponseHandler *handler, void *callbackData);
/**
 * OPTIONS 桶
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key :桶内对象名；
 * @参数 origin :预请求指定的跨域请求Origin（通常为域名）。
 * @参数 requestMethod :实际请求可以带的HTTP方法，可以带多个方法头域。
 * @参数 rmNumber :requestMethod条数；
 * @参数 requestHeader :实际请求可以带的HTTP头域，可以带多个头域。
 * @参数 rhNumber :requestHeader条数；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/
eSDK_OBS_API void OptionsObject(const S3BucketContext *bucketContext,const char* key, const char* origin,
					  const char (*requestMethod)[256],const unsigned int rmNumber,
					  const char (*requestHeader)[256],const unsigned int rhNumber,
					  S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData);

/**
 * OPTIONS 桶
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 origin :预请求指定的跨域请求Origin（通常为域名）。
 * @参数 requestMethod :实际请求可以带的HTTP方法，可以带多个方法头域。
 * @参数 rmNumber :requestMethod条数；
 * @参数 requestHeader :实际请求可以带的HTTP头域，可以带多个头域。
 * @参数 rhNumber :requestHeader条数；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/
eSDK_OBS_API void OptionsBucket(const S3BucketContext *bucketContext,const char* origin,
					  const char (*requestMethod)[256],const unsigned int rmNumber,
					  const char (*requestHeader)[256],const unsigned int rhNumber,
					  S3RequestContext *requestContext,const S3ResponseHandler *handler, void *callbackData);

/**
 * SetBucketAclByHead 
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 cannedAcl :桶权限；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/

eSDK_OBS_API void SetBucketAclByHead(const S3BucketContext *bucketContext,S3CannedAcl cannedAcl,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData);


/**
 *SetObjectAclByHead 
 *
 * @参数 bucketContext :表示桶和相关联参数的信息；
 * @参数 key :桶内对象名；
 * @参数 versionId : 桶内对象的版本 ID；
 * @参数 cannedAcl :桶权限；
 * @参数 requestContext:如果非空，把响应赋值给requestContext，
 *	           并且不会立即执行这个请求；如果为空，立即同步执行这个请求；
 * @参数 handler :回调函数请求；
 * @参数 callbackData 回调函数中传递的数据。
 **/

eSDK_OBS_API void SetObjectAclByHead(const S3BucketContext *bucketContext, const char *key, const char *versionId,S3CannedAcl cannedAcl,
                S3RequestContext *requestContext,
                const S3ResponseHandler *handler, void *callbackData);

#ifdef __cplusplus
}
#endif

#endif /* LIBS3_H */
