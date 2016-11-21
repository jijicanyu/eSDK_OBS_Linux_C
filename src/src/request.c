/** **************************************************************************
 * request.c
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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include "request.h"
#include "request_context.h"
#include "response_headers_handler.h"
#include "util.h"
#include "pcre.h"
#include <openssl/ssl.h>


#define USER_AGENT_SIZE 256
#define REQUEST_STACK_SIZE 32
#define REGION_SIZE 256
//lint -e26 -e31 -e63 -e64 -e78 -e101 -e119 -e129 -e144 -e156 -e438 -e505 -e515 -e516 -e522 -e529 -e530 -e533 -e534 -e546 -e551 -e578 -e601
#define countof(array) (sizeof(array)/sizeof(array[0]))

static char userAgentG[USER_AGENT_SIZE];

#if defined __GNUC__ || defined LINUX
static pthread_mutex_t requestStackMutexG;
#else
static HANDLE hmutex;
#endif

#if defined __GNUC__ || defined LINUX
static pthread_mutex_t setTimeoutMutexG;
#else
static HANDLE setTimeoutMutexG;
#endif

static unsigned int g_unTimeout = 0;

static Request *requestStackG[REQUEST_STACK_SIZE] = {0};

static int requestStackCountG = 0;

char defaultHostNameG[S3_MAX_HOSTNAME_SIZE] = {0};
char defaultRegionG[REGION_SIZE] = {0};
S3Authorization authG = AuthorizationV2;

// Openssl lock add by cwx298983 2016.07.29 Start
#if defined __GNUC__ || defined LINUX
static pthread_mutex_t* lockarray;
#else
static HANDLE* lockarray;
#endif

static void lock_callback(int mode, int type, char *file, int line)  
{
	(void)file;
	(void)line;
	if (mode & CRYPTO_LOCK) {
#if defined __GNUC__ || defined LINUX
		pthread_mutex_lock(&(lockarray[type]));
#else
		WaitForSingleObject(lockarray[type], INFINITE);//lint !e409
#endif		
	}
	else
	{
#if defined __GNUC__ || defined LINUX
		pthread_mutex_unlock(&(lockarray[type]));
#else
		ReleaseMutex(lockarray[type]);//lint !e409
#endif
	}  
}  

static unsigned long thread_id(void)  
{
	unsigned long ret;  

#if defined __GNUC__ || defined LINUX
	ret = (unsigned long)pthread_self();
#else
	ret = (unsigned long)GetCurrentThreadId();
#endif

	return(ret);
}  

static void init_locks(void)
{  
	int i;  

#if defined __GNUC__ || defined LINUX
	lockarray = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i=0; i<CRYPTO_num_locks(); i++)
	{
		pthread_mutex_init(&(lockarray[i]), NULL);
	}
#else
	lockarray = (HANDLE *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
	for (i=0; i<CRYPTO_num_locks(); i++)
	{
		lockarray[i] = CreateMutexA(NULL, false, "");//lint !e409
	}
#endif	 

	CRYPTO_set_id_callback((unsigned long (*)())thread_id);  
	CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))lock_callback);
}  

static void kill_locks(void)  
{  
	int i;  

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++)
	{
#if defined __GNUC__ || defined LINUX
		pthread_mutex_destroy(&(lockarray[i]));
#else
		CloseHandle(lockarray[i]);//lint !e409
#endif
	}

	OPENSSL_free(lockarray);
}  
// Openssl lock add by cwx298983 2016.07.29 End

typedef struct RequestComputedValues
{
    // All x-amz- headers, in normalized form (i.e. NAME: VALUE, no other ws)
    char *amzHeaders[S3_MAX_METADATA_COUNT + 2]; // + 2 for acl and date

    // The number of x-amz- headers
    int amzHeadersCount;

    // Storage for amzHeaders (the +256 is for x-amz-acl and x-amz-date)
    char amzHeadersRaw[COMPACTED_METADATA_BUFFER_SIZE + 256 + 1];

    // Canonicalized x-amz- headers
    string_multibuffer(canonicalizedAmzHeaders,
                       COMPACTED_METADATA_BUFFER_SIZE + 256 + 1);

    // URL-Encoded key
    char urlEncodedKey[MAX_URLENCODED_KEY_SIZE + 1];

    // Canonicalized resource
    char canonicalizedResource[MAX_CANONICALIZED_RESOURCE_SIZE + 1];

    // Cache-Control header (or empty)
    char cacheControlHeader[128];

    // Content-Type header (or empty)
    char contentTypeHeader[128];

    // Content-MD5 header (or empty)
    char md5Header[128];

    // Content-Disposition header (or empty)
    char contentDispositionHeader[128];

    // Content-Encoding header (or empty)
    char contentEncodingHeader[128];

    // x-hws-mdc-storage-policy header (or empty)
    char storagepolicyHeader[128];

    // x-amz-website-redirect-location header (or empty)
    // the length of websiteredirectlocationHeader can reach 2048, so modify it from 128 to 2200 by cwx298983 201608011417
    char websiteredirectlocationHeader[2200];

    // Expires header (or empty)
    char expiresHeader[128];

    // If-Modified-Since header
    char ifModifiedSinceHeader[128];

    // If-Unmodified-Since header
    char ifUnmodifiedSinceHeader[128];

    // If-Match header
    char ifMatchHeader[128];

    // If-None-Match header
    char ifNoneMatchHeader[128];

    // Range header
    char rangeHeader[128];

    // Authorization header
    char authorizationHeader[512];
} RequestComputedValues;



// Called whenever we detect that the request headers have been completely
// processed; which happens either when we get our first read/write callback,
// or the request is finished being procesed.  Returns nonzero on success,
// zero on failure.
static void request_headers_done(Request *request)
{
    if (request->propertiesCallbackMade) {
        return;
    }

    request->propertiesCallbackMade = 1;

    // Get the http response code
    long httpResponseCode = 0;
    request->httpResponseCode = 0;
    if (curl_easy_getinfo(request->curl, CURLINFO_RESPONSE_CODE, 
                          &httpResponseCode) != CURLE_OK) {
        // Not able to get the HTTP response code - error
        request->status = S3StatusInternalError;
        return;
    }
    else {
        request->httpResponseCode = httpResponseCode;
    }

    response_headers_handler_done(&(request->responseHeadersHandler), 
                                  request->curl);

    // Make the callback to return the requestId
    if (request->propertiesCallback) {
        request->status = (*(request->propertiesCallback))
            (&(request->responseHeadersHandler.responseProperties), 
             request->callbackData);
    }
}


static size_t curl_header_func(void *ptr, size_t size, size_t nmemb,
                               void *data)
{
    Request *request = (Request *) data;

    size_t len = size * nmemb;   //zwx367245 2016.10.08 修复了不必要的从unsigned int到int的类型转换

    response_headers_handler_add
        (&(request->responseHeadersHandler), (char *) ptr, len);

    return len;
}


static size_t curl_read_func(void *ptr, size_t size, size_t nmemb, void *data)
{
    Request *request = (Request *) data;


    size_t len = size * nmemb;  //zwx367245 2016.10.08 修复了不必要的从unsigned int到int64_t的类型转换

    // CURL may call this function before response headers are available,
    // so don't assume response headers are available and attempt to parse
    // them.  Leave that to curl_write_func, which is guaranteed to be called
    // only after headers are available.

    if (request->status != S3StatusOK) {
        return CURL_READFUNC_ABORT;
    }

    // If there is no data callback, or the data callback has already returned
    // contentLength bytes, return 0;
    if (!request->toS3Callback || !request->toS3CallbackBytesRemaining) {
        return 0;
    }
    
    // Don't tell the callback that we are willing to accept more data than we
    // really are
    if (len > (unsigned int)request->toS3CallbackBytesRemaining) { //zwx367245 2016.10.21   avoid signed and unsigned mixture
        len = (unsigned int)request->toS3CallbackBytesRemaining;
    }

    // Otherwise, make the data callback
    int64_t ret = (*(request->toS3Callback))
        ((int)len, (char *) ptr, request->callbackData);
    if (ret < 0) {
        request->status = S3StatusAbortedByCallback;
        return CURL_READFUNC_ABORT;
    }
    else {
        if (ret > request->toS3CallbackBytesRemaining) {
            ret = request->toS3CallbackBytesRemaining;
        }
        request->toS3CallbackBytesRemaining -= ret;
        return (size_t)ret;
    }
}


static size_t curl_write_func(void *ptr, size_t size, size_t nmemb,
                              void *data)
{
    Request *request = (Request *) data;

    size_t len = size * nmemb;   //zwx367245 2016.10.08 修复了不必要的从unsigned int到int的类型转换

    request_headers_done(request);

    if (request->status != S3StatusOK) {
        return 0;
    }

    // On HTTP error, we expect to parse an HTTP error response
    if ((request->httpResponseCode < 200) || 
        (request->httpResponseCode > 299)) {
        request->status = error_parser_add
            (&(request->errorParser), (char *) ptr, len);
    }
    // If there was a callback registered, make it
    else if (request->fromS3Callback) {
        request->status = (*(request->fromS3Callback))
            (len, (char *) ptr, request->callbackData);
    }
    // Else, consider this an error - S3 has sent back data when it was not
    // expected
    else {
        request->status = S3StatusInternalError;
    }

    return ((request->status == S3StatusOK) ? len : 0);
}


// This function 'normalizes' all x-amz-meta headers provided in
// params->requestHeaders, which means it removes all whitespace from
// them such that they all look exactly like this:
// x-amz-meta-${NAME}: ${VALUE}
// It also adds the x-amz-acl, x-amz-copy-source, x-amz-metadata-directive,
// and x-amz-server-side-encryption headers if necessary, and always adds the
// x-amz-date header.  It copies the raw string values into
// params->amzHeadersRaw, and creates an array of string pointers representing
// these headers in params->amzHeaders (and also sets params->amzHeadersCount
// to be the count of the total number of x-amz- headers thus created).
static S3Status compose_amz_headers(const RequestParams *params,
                                    RequestComputedValues *values)
{
    const S3PutProperties *properties = params->putProperties;
    const S3CorsConf *corsConf = params->corsConf;
	ServerSideEncryptionParams *serverSideEncryptionParams = params->serverSideEncryptionParams;

    values->amzHeadersCount = 0;
    values->amzHeadersRaw[0] = 0;
    int len = 0;

    // Append a header to amzHeaders, trimming whitespace from the end.
    // Does NOT trim whitespace from the beginning.
    // cheack array index by jwx329074 2016.11.17
#define headers_append(isNewHeader, format, ...)                        \
    do {                                                                \
        if (isNewHeader) {                                              \
            values->amzHeaders[values->amzHeadersCount++] =             \
                &(values->amzHeadersRaw[len]);                          \
        }                                                               \
		if (snprintf_s(&(values->amzHeadersRaw[len]), sizeof(values->amzHeadersRaw) - len,_TRUNCATE, format, __VA_ARGS__) > 0)\
		{																\
			len += snprintf_s(&(values->amzHeadersRaw[len]),                  \
				sizeof(values->amzHeadersRaw) - len,_TRUNCATE,             \
				format, __VA_ARGS__);                           \
		}													\
        if (len >= (int) sizeof(values->amzHeadersRaw)) {               \
            return S3StatusMetaDataHeadersTooLong;                      \
        }                                                               \
        while ((len > 0) && (values->amzHeadersRaw[len - 1] == ' ')) {  \
            len--;                                                      \
        }                                                               \
        values->amzHeadersRaw[len++] = 0;                               \
    } while (0)

#define header_name_tolower_copy(str, l)                                \
    do {                                                                \
        values->amzHeaders[values->amzHeadersCount++] =                 \
            &(values->amzHeadersRaw[len]);                              \
        if ((len + l) >= (int) sizeof(values->amzHeadersRaw)) {         \
            return S3StatusMetaDataHeadersTooLong;                      \
        }                                                               \
        int todo = l;                                                   \
        while (todo--) {                                                \
            if ((*(str) >= 'A') && (*(str) <= 'Z')) {                   \
                values->amzHeadersRaw[len++] = 'a' + (*(str) - 'A');    \
            }                                                           \
            else {                                                      \
                values->amzHeadersRaw[len++] = *(str);                  \
            }                                                           \
            (str)++;                                                    \
        }                                                               \
    } while (0)

    // Check and copy in the x-amz-meta headers
    if (properties) {
        int i;
        for (i = 0; i < properties->metaDataCount; i++) {
            const S3NameValue *property = &(properties->metaData[i]);
            char headerName[S3_MAX_METADATA_SIZE - sizeof(": v")];
            int l = snprintf_s(headerName, sizeof(headerName),_TRUNCATE, 
                             S3_METADATA_HEADER_NAME_PREFIX "%s",
                             property->name);
            char *hn = headerName;
            header_name_tolower_copy(hn, l);
            // Copy in the value
            headers_append(0, ": %s", property->value);
        }

        // Add the x-amz-acl header, if necessary
        const char *cannedAclString;
        switch (properties->cannedAcl) {
        case S3CannedAclPrivate:
            cannedAclString = "private";
            break;
        case S3CannedAclPublicRead:
            cannedAclString = "public-read";
            break;
        case S3CannedAclPublicReadWrite:
            cannedAclString = "public-read-write";
            break;
		case S3CannedAclAuthenticatedRead:
			cannedAclString = "authenticated-read";
			break;
		case S3CannedAclBucketOwnerRead:
			cannedAclString = "bucket-owner-read";
			break;
		case S3CannedAclBucketOwnerFullControl:
			cannedAclString = "bucket-owner-full-control";
			break;
		case S3CannedAclLogDeliveryWrite:
			cannedAclString = "log-delivery-write";
			break;
        default: // S3CannedAclAuthenticatedRead
            cannedAclString = "authenticated-read";
            break;
        }
        if (cannedAclString) {
            headers_append(1, "x-amz-acl: %s", cannedAclString);
        }

        // Add the x-amz-server-side-encryption header, if necessary
        /*if (properties->useServerSideEncryption) {
            headers_append(1, "x-amz-server-side-encryption: %s", "AES256");
        }*/
    }
	if(serverSideEncryptionParams){
		if(serverSideEncryptionParams->use_kms){
			if(serverSideEncryptionParams->kmsServerSideEncryption)
				headers_append(1, "x-amz-server-side-encryption: %s", serverSideEncryptionParams->kmsServerSideEncryption);
			if(serverSideEncryptionParams->kmsKeyId)
				headers_append(1, "x-amz-server-side-encryption-aws-kms-key-id: %s", serverSideEncryptionParams->kmsKeyId);
			if(serverSideEncryptionParams->kmsEncryptionContext)
				headers_append(1, "x-amz-server-side-encryption-context: %s", serverSideEncryptionParams->kmsEncryptionContext);
		}else if(serverSideEncryptionParams->use_ssec){
			if(serverSideEncryptionParams->ssecCustomerAlgorithm)
				headers_append(1, "x-amz-server-side-encryption-customer-algorithm: %s", serverSideEncryptionParams->ssecCustomerAlgorithm);
			if(serverSideEncryptionParams->ssecCustomerKey)
				headers_append(1, "x-amz-server-side-encryption-customer-key: %s", serverSideEncryptionParams->ssecCustomerKey);
			if(serverSideEncryptionParams->ssecCustomerKeyMD5)
				headers_append(1, "x-amz-server-side-encryption-customer-key-MD5: %s", serverSideEncryptionParams->ssecCustomerKeyMD5);
			if(serverSideEncryptionParams->des_ssecCustomerAlgorithm)
				headers_append(1, "x-amz-copy-source-server-side-encryption-customer-algorithm: %s", serverSideEncryptionParams->des_ssecCustomerAlgorithm);
			if(serverSideEncryptionParams->des_ssecCustomerKey)
				headers_append(1, "x-amz-copy-source-server-side-encryption-customer-key: %s", serverSideEncryptionParams->des_ssecCustomerKey);
			if(serverSideEncryptionParams->des_ssecCustomerKeyMD5)
				headers_append(1, "x-amz-copy-source-server-side-encryption-customer-key-MD5: %s", serverSideEncryptionParams->des_ssecCustomerKeyMD5);
		}
    }
	if(corsConf)
	{
		if(corsConf->origin){
			headers_append(1,"Origin: %s",corsConf->origin);
		}
		unsigned int i;
		for(i = 0; i < corsConf->rmNumber; i++)
		{
			headers_append(1,"Access-Control-Request-Method: %s",corsConf->requestMethod[i]);
		}
		for(i = 0; i < corsConf->rhNumber; i++)
		{
			headers_append(1,"Access-Control-Request-Headers: %s",corsConf->requestHeader[i]);
		}
	}
	if(authG){
		headers_append(1,"x-amz-content-sha256: %s","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		headers_append(1,"host: %s",params->bucketContext.hostName ? params->bucketContext.hostName : defaultHostNameG);
//		headers_append(1,"x-amz-content-sha256: %s","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	}
    // Add the x-amz-date header
    time_t now = time(NULL);
	char date[64] = {0};
 	if(authG)
	{
		struct tm *flag = gmtime(&now);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){  //zwx367245 2016.10.08 增加对gmtime(&now)返回值是否为NULL的判断，保证strftime函数正确使用
			strftime(date, sizeof(date), "%Y%m%dT%H%M%SZ", flag);
		}
		headers_append(1, "x-amz-date: %s", date);//x-amz-date
  	}
	else
	{
		struct tm *flag = gmtime(&now);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){  //zwx367245 2016.10.08 增加对gmtime(&now)返回值是否为NULL的判断，保证strftime函数正确使用
			strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", flag);
		}
		headers_append(1, "x-amz-date: %s", date);//x-amz-date
	}
    if (params->httpRequestType == HttpRequestTypeCOPY) {
        // Add the x-amz-copy-source header
        if (params->copySourceBucketName && params->copySourceBucketName[0] &&
            params->copySourceKey && params->copySourceKey[0]) {
            headers_append(1, "x-amz-copy-source: /%s/%s",
                           params->copySourceBucketName,
                           params->copySourceKey);
        }
        // And the x-amz-metadata-directive header
        if (properties && 0 != properties->metaDataCount) {
            headers_append(1, "%s", "x-amz-metadata-directive: REPLACE");
        }
    }

    return S3StatusOK;
}


// Composes the other headers
static S3Status compose_standard_headers(const RequestParams *params,
                                         RequestComputedValues *values)
{
	//Negative array index write 
#define do_put_header(fmt, sourceField, destField, badError, tooLongError)  \
    do {                                                                    \
        if (params->putProperties &&                                        \
            params->putProperties->sourceField &&                          \
            params->putProperties->sourceField[0]) {                       \
            /* Skip whitespace at beginning of val */                       \
            const char *val = params->putProperties-> sourceField;          \
            while (*val && is_blank(*val)) {                                \
                val++;                                                      \
            }                                                               \
            if (!*val) {                                                    \
                return badError;                                            \
            }                                                               \
            /* Compose header, make sure it all fit */                      \
            int len = snprintf_s(values->destField,                          \
                               sizeof(values->destField),_TRUNCATE,  fmt, val);       \
            if (len >= (int) sizeof(values->destField) || len < 0) {                  \
                return tooLongError;                                        \
            }                                                               \
            /* Now remove the whitespace at the end */                      \
            while (is_blank(values-> destField[len])) {                     \
				if (len > 0)												\
				{														\
					len--;                                               \
				}														\
            }                                                               \
            values-> destField[len] = 0;                                    \
        }                                                                   \
        else {                                                              \
            values-> destField[0] = 0;                                      \
        }                                                                   \
    } while (0)

#define do_get_header(fmt, sourceField, destField, badError, tooLongError)  \
    do {                                                                    \
        if (params->getConditions &&                                        \
            params->getConditions-> sourceField &&                          \
            params->getConditions-> sourceField[0]) {                       \
            /* Skip whitespace at beginning of val */                       \
            const char *val = params->getConditions-> sourceField;          \
            while (*val && is_blank(*val)) {                                \
                val++;                                                      \
            }                                                               \
            if (!*val) {                                                    \
                return badError;                                            \
            }                                                               \
            /* Compose header, make sure it all fit */                      \
            int len = snprintf_s(values-> destField,                          \
                               sizeof(values-> destField),_TRUNCATE,  fmt, val);       \
            if (len >= (int) sizeof(values-> destField) || len < 0) {                  \
                return tooLongError;                                        \
            }                                                               \
            /* Now remove the whitespace at the end */                      \
            while ((len > 0) && is_blank(values-> destField[len])) {                     \
                len--;                                                      \
            }                                                               \
            values-> destField[len] = 0;                                    \
        }                                                                   \
        else {                                                              \
            values-> destField[0] = 0;                                      \
        }                                                                   \
    } while (0)
//Negative array index read by jwx329074 2016.11.17
#define do_gp_header(fmt, sourceField, destField, badError, tooLongError)  \
			do {																	\
				if (params->putProperties && params->putProperties->getConditions &&										\
					params->putProperties->getConditions-> sourceField &&							\
					params->putProperties->getConditions-> sourceField[0]) {						\
					/* Skip whitespace at beginning of val */						\
					const char *val = params->putProperties->getConditions-> sourceField;			\
					while (*val && is_blank(*val)) {								\
						val++;														\
					}																\
					if (!*val) {													\
						return badError;											\
					}																\
					/* Compose header, make sure it all fit */						\
					int len = snprintf_s(values-> destField,							\
									   sizeof(values-> destField),_TRUNCATE,  fmt, val);		\
					if (len >= (int) sizeof(values-> destField) || len < 0) {					\
						return tooLongError;										\
					}																\
					/* Now remove the whitespace at the end */						\
					while ((len > 0) && is_blank(values-> destField[len])) { 					\
							len--;													\
					}																\
					values-> destField[len] = 0;									\
				}																	\
				else {																\
					values-> destField[0] = 0;										\
				}																	\
			} while (0)


    // Cache-Control
    do_put_header("Cache-Control: %s", cacheControl, cacheControlHeader,
                  S3StatusBadCacheControl, S3StatusCacheControlTooLong);
    
    // ContentType
    do_put_header("Content-Type: %s", contentType, contentTypeHeader,
                  S3StatusBadContentType, S3StatusContentTypeTooLong);

    // MD5
    do_put_header("Content-MD5: %s", md5, md5Header, S3StatusBadMD5,
                  S3StatusMD5TooLong);

    // Content-Disposition
    do_put_header("Content-Disposition: attachment; filename=\"%s\"",
                  contentDispositionFilename, contentDispositionHeader,
                  S3StatusBadContentDispositionFilename,
                  S3StatusContentDispositionFilenameTooLong);
    
    // ContentEncoding
    do_put_header("Content-Encoding: %s", contentEncoding, 
                  contentEncodingHeader, S3StatusBadContentEncoding,
                  S3StatusContentEncodingTooLong);
    
    // Expires
    if (params->putProperties && (params->putProperties->expires >= 0)) {
        time_t t = (time_t) params->putProperties->expires;

		struct tm *flag = gmtime(&t);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){   //zwx367245 2016.10.08 函数gmtime(&t))返回值的NULL检查
			strftime(values->expiresHeader, sizeof(values->expiresHeader),
				"Expires: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
    }
    else {
        values->expiresHeader[0] = 0;
    }

    // storagepolicy
    do_put_header("x-hws-mdc-storage-policy: %s", storagepolicy, 
                  storagepolicyHeader, S3StatusBadContentEncoding,
                  S3StatusContentEncodingTooLong);
    // websiteredirectlocation
    do_put_header("x-amz-website-redirect-location: %s", websiteredirectlocation, 
                  websiteredirectlocationHeader, S3StatusBadContentEncoding,
                  S3StatusContentEncodingTooLong);
    // If-Modified-Since
    if (params->getConditions &&
        (params->getConditions->ifModifiedSince >= 0)) {
        time_t t = (time_t) params->getConditions->ifModifiedSince;

		struct tm *flag = gmtime(&t);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){   //zwx367245 2016.10.08 函数gmtime(&t))返回值的NULL检查
			strftime(values->ifModifiedSinceHeader,
				sizeof(values->ifModifiedSinceHeader),
				"If-Modified-Since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
    }
    else if (params->putProperties&&params->putProperties->getConditions&&
        (params->putProperties->getConditions->ifModifiedSince >= 0)) {
        time_t t = (time_t) params->putProperties->getConditions->ifModifiedSince;

		struct tm *flag = gmtime(&t);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){   //zwx367245 2016.10.08 函数gmtime(&t))返回值的NULL检查
			strftime(values->ifModifiedSinceHeader,
				sizeof(values->ifModifiedSinceHeader),
				"x-amz-copy-source-if-modified-since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
    }
    else {
        values->ifModifiedSinceHeader[0] = 0;
    }
    // If-Unmodified-Since header
    if (params->getConditions &&
        (params->getConditions->ifNotModifiedSince >= 0)) {
        time_t t = (time_t) params->getConditions->ifNotModifiedSince;
		
		struct tm *flag = gmtime(&t);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){   //zwx367245 2016.10.08 函数gmtime(&t))返回值的NULL检查
			strftime(values->ifUnmodifiedSinceHeader,
				sizeof(values->ifUnmodifiedSinceHeader),
				"If-Unmodified-Since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
    }
    else if (params->putProperties&&params->putProperties->getConditions &&
        (params->putProperties->getConditions->ifNotModifiedSince >= 0)) {
        time_t t = (time_t) params->putProperties->getConditions->ifNotModifiedSince;
		
		struct tm *flag = gmtime(&t);//jwx329074 2016.10.09 增加判断标志位
		if(flag != NULL){   //zwx367245 2016.10.08 函数gmtime(&t))返回值的NULL检查
			strftime(values->ifUnmodifiedSinceHeader,
				sizeof(values->ifUnmodifiedSinceHeader),
				"x-amz-copy-source-if-unmodified-since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
    }
    else {
        values->ifUnmodifiedSinceHeader[0] = 0;
    }
    
    // If-Match header
    do_get_header("If-Match: %s", ifMatchETag, ifMatchHeader,
                  S3StatusBadIfMatchETag, S3StatusIfMatchETagTooLong);
	if(!values->ifMatchHeader[0])
	{
    	do_gp_header("x-amz-copy-source-if-match: %s", ifMatchETag, ifMatchHeader,
                  S3StatusBadIfMatchETag, S3StatusIfMatchETagTooLong);
	}
    
    // If-None-Match header
    do_get_header("If-None-Match: %s", ifNotMatchETag, ifNoneMatchHeader,
                  S3StatusBadIfNotMatchETag, 
                  S3StatusIfNotMatchETagTooLong);
	if(!values->ifNoneMatchHeader[0])
	{
	    do_gp_header("x-amz-copy-source-if-none-match: %s", ifNotMatchETag, ifNoneMatchHeader,
                  S3StatusBadIfNotMatchETag, 
                  S3StatusIfNotMatchETagTooLong);
	}
    
    // Range header
    if (params->startByte || params->byteCount) {
        if (params->byteCount) {
            snprintf_s(values->rangeHeader, sizeof(values->rangeHeader),_TRUNCATE, 
                     "Range: bytes=%llu-%llu", 
                     (unsigned long long) params->startByte,
                     (unsigned long long) (params->startByte + 
                                           params->byteCount - 1));
        }
        else {
            snprintf_s(values->rangeHeader, sizeof(values->rangeHeader),_TRUNCATE, 
                     "Range: bytes=%llu-", 
                     (unsigned long long) params->startByte);
        }
    }
    else  if (params->putProperties&&( params->putProperties->startByte || params->putProperties->byteCount)) {
				if (params->putProperties->byteCount) {
				 snprintf_s(values->rangeHeader, sizeof(values->rangeHeader),_TRUNCATE, 
					  "x-amz-copy-source-range: bytes=%llu-%llu", 
					  (unsigned long long) params->putProperties->startByte,
					  (unsigned long long) (params->putProperties->startByte + 
											params->putProperties->byteCount - 1));
		 }
		 else {
			 snprintf_s(values->rangeHeader, sizeof(values->rangeHeader),_TRUNCATE, 
					  "x-amz-copy-source-range: bytes=%llu-", 
					  (unsigned long long) params->putProperties->startByte);
		 }
	 }
	 else {
		 values->rangeHeader[0] = 0;
	 }

    return S3StatusOK;
}


// URL encodes the params->key value into params->urlEncodedKey
static S3Status encode_key(const RequestParams *params,
                           RequestComputedValues *values)
{
	if (NULL != params->key)
	{
		char *pStrKeyUTF8 = string_To_UTF8(params->key);
		int nRet = urlEncode(values->urlEncodedKey, pStrKeyUTF8, S3_MAX_KEY_SIZE);
		CHECK_NULL_FREE(pStrKeyUTF8);
		return (nRet ? S3StatusOK : S3StatusUriTooLong);
	}
	else
	{
		return (urlEncode(values->urlEncodedKey, params->key, S3_MAX_KEY_SIZE) ?
			S3StatusOK : S3StatusUriTooLong);
	}
}


// Simple comparison function for comparing two HTTP header names that are
// embedded within an HTTP header line, returning true if header1 comes
// before header2 alphabetically, false if not
static int headerle(const char *header1, const char *header2)
{
    while (1) {
        if (*header1 == ':') {
            return (*header2 != ':');
        }
        else if (*header2 == ':') {
            return 0;
        }
        else if (*header2 < *header1) {
            return 0;
        }
        else if (*header2 > *header1) {
            return 1;
        }
        header1++, header2++;
    }
}


// Replace this with merge sort eventually, it's the best stable sort.  But
// since typically the number of elements being sorted is small, it doesn't
// matter that much which sort is used, and gnome sort is the world's simplest
// stable sort.  Added a slight twist to the standard gnome_sort - don't go
// forward +1, go forward to the last highest index considered.  This saves
// all the string comparisons that would be done "going forward", and thus
// only does the necessary string comparisons to move values back into their
// sorted position.
static void header_gnome_sort(const char **headers, int size)
{
    int i = 0, last_highest = 0;

    while (i < size) {
        if ((i == 0) || headerle(headers[i - 1], headers[i])) {
            i = ++last_highest;
        }
        else {
            const char *tmp = headers[i];
            headers[i] = headers[i - 1];
            headers[--i] = tmp;
        }
    }
}


// Canonicalizes the x-amz- headers into the canonicalizedAmzHeaders buffer
static void canonicalize_amz_headers(RequestComputedValues *values)
{
    // Make a copy of the headers that will be sorted
	const char *sortedHeaders[S3_MAX_METADATA_COUNT] = {0};

    memcpy_s(sortedHeaders, S3_MAX_METADATA_COUNT, values->amzHeaders,
           (values->amzHeadersCount * sizeof(sortedHeaders[0])));//zwx367245 2016.11.3 secure function
	
	// add rangeHeader information to headers by cwx298983 2015.11.24 Start
	int nCount = values->amzHeadersCount;
	
	if (0 != values->rangeHeader[0])
	{
		sortedHeaders[nCount] = values->rangeHeader;
		nCount++;
	}

	// ifModifiedSinceHeader
	if (0 != values->ifModifiedSinceHeader[0])
	{
		sortedHeaders[nCount] = values->ifModifiedSinceHeader;
		nCount++;
	}
	
	// ifUnmodifiedSinceHeader
	if (0 != values->ifUnmodifiedSinceHeader[0])
	{
		sortedHeaders[nCount] = values->ifUnmodifiedSinceHeader;
		nCount++;
	}
	
	// ifMatchHeader
	if (0 != values->ifMatchHeader[0])
	{
		sortedHeaders[nCount] = values->ifMatchHeader;
		nCount++;
	}
	
	// ifNoneMatchHeader
	if (0 != values->ifNoneMatchHeader[0])
	{
		sortedHeaders[nCount] = values->ifNoneMatchHeader;
		nCount++;
	}
	
	// websiteredirectlocationHeader
	if (0 != values->websiteredirectlocationHeader[0])
	{
		sortedHeaders[nCount] = values->websiteredirectlocationHeader;
		nCount++;
	}
	
    // Now sort these
    header_gnome_sort(sortedHeaders, nCount);

    // Now copy this sorted list into the buffer, all the while:
    // - folding repeated headers into single lines, and
    // - folding multiple lines
    // - removing the space after the colon
    int lastHeaderLen = 0, i;
    char *buffer = values->canonicalizedAmzHeaders;
    for (i = 0; i < nCount; i++) {
        const char *header = sortedHeaders[i];
        const char *c = header;
        // If the header names are the same, append the next value
        if ((i > 0) && 
            !strncmp(header, sortedHeaders[i - 1], lastHeaderLen)) {
            // Replacing the previous newline with a comma
            *(buffer - 1) = ',';
            // Skip the header name and space
            c += (lastHeaderLen + 1);
        }
        // Else this is a new header
        else {
            // Copy in everything up to the space in the ": "
            while (*c != ' ') {
                *buffer++ = *c++;
            }
            // Save the header len since it's a new header
            lastHeaderLen = c - header;
            // Skip the space
            c++;
        }
	// add rangeHeader information to headers by cwx298983 2015.11.24 End	
	
        // Now copy in the value, folding the lines
        while (*c) {
            // If c points to a \r\n[whitespace] sequence, then fold
            // this newline out
            if ((*c == '\r') && (*(c + 1) == '\n') && is_blank(*(c + 2))) {
                c += 3;
                while (is_blank(*c)) {
                    c++;
                }
                // Also, what has most recently been copied into buffer amy
                // have been whitespace, and since we're folding whitespace
                // out around this newline sequence, back buffer up over
                // any whitespace it contains
                while (is_blank(*(buffer - 1))) {
                    buffer--;
                }
                continue;
            }
            *buffer++ = *c++;
        }
        // Finally, add the newline
        *buffer++ = '\n';
    }

    // Terminate the buffer
    *buffer = 0;
}


// Canonicalizes the resource into params->canonicalizedResource
static void canonicalize_resource(const char *bucketName,
                                  const char *subResource,
                                  const char *urlEncodedKey,
                                  char *buffer ,int bufferSize)
{
    int len = 0;

    *buffer = 0;

#define append(str) len += sprintf_s(&(buffer[len]), bufferSize-len, "%s", str)

    if (bucketName && bucketName[0]) {
        buffer[len++] = '/';
        append(bucketName);
    }

    append("/");

    if (urlEncodedKey && urlEncodedKey[0]) {
        append(urlEncodedKey);
    }

    if (subResource && subResource[0]) {
        append("?");
        append(subResource);
    }
}


// Convert an HttpRequestType to an HTTP Verb string
static const char *http_request_type_to_verb(HttpRequestType requestType)
{
    switch (requestType) {
    case HttpRequestTypeGET:
        return "GET";
    case HttpRequestTypeHEAD:
        return "HEAD";
    case HttpRequestTypePUT:
    case HttpRequestTypeCOPY:
        return "PUT";
    case HttpRequestTypePOST:
        return "POST";
	case HttpRequestTypeOPTIONS:
		return "OPTIONS";
    default: // HttpRequestTypeDELETE
        return "DELETE";
    }
}
int  A2a(char * strInput,char *strOutput)
{
	int i = 0;
	char ch;
	if(!strInput || !strOutput)return 0;
	if(!(strlen(strInput)))return 0;
	while((ch = *strInput) != '\0')
	{
		if( !((ch <= 'Z' && ch >= 'A') || (ch <= 'z' && ch >= 'a')) )
		{
			if(ch == ':')return 0;
			*strOutput++ = *strInput++;
			continue;
		}
		*strOutput++ = (*strInput++) | 32;
		++i;
	}
	*strOutput = '\0';
	if(!i)return -1;
	return 0;
}
void mkCanonicalQueryString(const RequestParams *params,char*canonicalQueryString)
{
	char tempheaders[1024] = {0};
	if(params->queryParams)
	{
		char query[10][256] = {""};
		char header[10][50] = {""};
		int count = 0;
		const char* pos = 0;
		int offset = 0;
		int len = strlen(params->queryParams);
		while((pos = strstr(params->queryParams + offset,"&")) != NULL)
		{
			int poslen = pos - params->queryParams - offset;
			strncpy_s(query[count], sizeof(query[count]), params->queryParams + offset,poslen);//zwx367245 2016.11.4
			offset += poslen + 1;
			count++;			
		}
		strncpy_s(query[count], sizeof(query[count]), params->queryParams + offset,len - offset);
		count++;
		if(params->subResource)
		{
			strcpy_s(query[count], sizeof(query[count]), params->subResource);
			strcat_s(query[count], sizeof(query[count]), "=");
			count++;
		}
		int i = 0;
		for(i = 0; i < count; i++)
		{
			pos = strstr(query[i],"=");
			if(pos){    //zwx367245 2016.10.08 strstr返回值的pos做NULL检查
				int poslen = pos - query[i];
				strncpy_s(header[i], sizeof(header[i]), query[i],poslen);	//ok	
			}	
		}
		int j;
		for(i = 0; i < count - 1; i++)
	    {
	        for(j = 0; j < count -i -1; j++)
	        {
	            if(strcmp(header[j],header[j+1]) > 0)
	            {
	                char temp[256] = {0}; //ok
					strcpy_s(temp, sizeof(temp), header[j]);
	                strcpy_s(header[j] , sizeof(header[j]), header[j+1]);
	                strcpy_s(header[j+1] , sizeof(header[j+1]), temp);
					memset_s(temp, sizeof(temp),0,sizeof(temp));

					strcpy_s(temp, sizeof(temp), query[j]);
					strcpy_s(query[j],  sizeof(query[j]), query[j+1]);
					strcpy_s(query[j+1], sizeof(query[j+1]), temp);
				}
	        }
   		 }
		for(i = 0; i < count; i++)
		{
			strcpy_s(tempheaders+strlen(tempheaders), sizeof(tempheaders)-strlen(tempheaders), query[i]); //ok
	      if(i != count - 1)
	      {
	          strcat_s(tempheaders,sizeof(tempheaders), "&"); //ok
	      }
		}

	}
	else if(params->subResource)
	{
		strcpy_s(tempheaders, sizeof(tempheaders), params->subResource);//ok
		strcat_s(tempheaders, sizeof(tempheaders),"=");//ok
	
	}
	 strcpy_s(canonicalQueryString, 4096, tempheaders);//lint !e539
}
// Composes the V4 Authorization header for the request
static S3Status compose_authV4_header(const RequestParams *params,
                                    RequestComputedValues *values)
{

	char canonicalRequest[4096] = {0};
	char canonicalQueryString[4096] = {0};

	int len = 0;
	#define canonicalRequest_append(format, ...)                             \
		len += snprintf_s(&(canonicalRequest[len]), sizeof(canonicalRequest) - len, _TRUNCATE,  	\
						format, __VA_ARGS__)
	
	canonicalRequest_append
		("%s\n", http_request_type_to_verb(params->httpRequestType));
	if(params->bucketContext.bucketName)
	{
		canonicalRequest_append("/%s/%s\n",params->bucketContext.bucketName,values->urlEncodedKey);
	}
	else
	{
		canonicalRequest_append("/%s\n","");
	}
/*	if(params->subResource || params->queryParams)
	{
		if(!params->subResource&&params->queryParams)
		{
			canonicalRequest_append("%s\n",params->queryParams);		
		}
		else if(params->subResource&&!params->queryParams)
		{
			canonicalRequest_append("%s=\n",params->subResource);		
		}
		else if(!strcmp(params->subResource,"acl")&&params->queryParams)
		{
			canonicalRequest_append("%s=%s\n",params->subResource,params->queryParams);
		}
		else if(params->subResource&&params->queryParams)
		{
			canonicalRequest_append("%s%s=\n",params->queryParams,params->subResource);
		}
	}
	else
	{
		canonicalRequest_append("%s\n","");
	}
*/	
	mkCanonicalQueryString(params,canonicalQueryString);
	canonicalRequest_append("%s\n",canonicalQueryString);
	char headers[30][256]={""};
	int i;
	for(i = 0; i < values->amzHeadersCount; i++)
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->amzHeaders[i]);//zwx367245 2016.11.4
	}
	if(values->cacheControlHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->cacheControlHeader);//ok
		i++;
	}
	if(values->contentTypeHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->contentTypeHeader);//ok
		i++;
	}
	if(values->md5Header[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->md5Header);//ok
		i++;
	}
	if(values->contentDispositionHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->contentDispositionHeader);
		i++;
	}
	if(values->contentEncodingHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->contentEncodingHeader);//ok
		i++;
	}
	if(values->expiresHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->expiresHeader);//ok
		i++;
	}
	if(values->ifModifiedSinceHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->ifModifiedSinceHeader);//ok
		i++;
	}

	if(values->ifUnmodifiedSinceHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->ifUnmodifiedSinceHeader);
		i++;
	}
	if(values->ifMatchHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->ifMatchHeader);//ok
		i++;
	}
	if(values->ifNoneMatchHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->ifNoneMatchHeader);//ok
		i++;
	}
	if(values->rangeHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->rangeHeader);//ok
		i++;
	}
	if(values->storagepolicyHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->storagepolicyHeader);//ok
		i++;
	}
	if(values->websiteredirectlocationHeader[0])
	{
		strcpy_s(headers[i] , sizeof(headers[i]), values->websiteredirectlocationHeader); //ok
		i++;
	}
	int headerscount = i;

	char signedHeaders[30][128] = {""};
	for(i = 0; i < headerscount ; i++)
	{
		A2a(headers[i],headers[i]);			
		const char* pos = strstr(headers[i],":");
		int ilen = strlen(headers[i]);
		if(pos){   //zwx367245 2016.10.08 函数返回的pos的NULL检查
			int poslen = pos-headers[i];
			strncpy_s(signedHeaders[i], sizeof(signedHeaders[i]), headers[i],poslen);//ok
			//strncpy(headers[i]+poslen+1,headers[i]+poslen+2,ilen-poslen);
			memmove_s(headers[i]+poslen+1, sizeof(headers[i]) - (poslen+1), headers[i]+poslen+2,ilen-poslen);// 安全函数替换 jwx329074 2016.11.18
		}
	}
	int j;
	for(i = 0; i < headerscount - 1; i++)
    {
        for(j = 0; j < headerscount -i -1; j++)
        {
            if(strcmp(signedHeaders[j],signedHeaders[j+1]) > 0)
            {
				char temp[256] = {0};
				strcpy_s(temp, sizeof(temp), headers[j]);
				strcpy_s(headers[j], sizeof(headers[j]), headers[j+1]);
				strcpy_s(headers[j+1], sizeof(headers[j+1]), temp);

				char temp1[256] = {0};
				strcpy_s(temp1, sizeof(temp1), signedHeaders[j]);
				strcpy_s(signedHeaders[j], sizeof(signedHeaders[j]), signedHeaders[j+1]);
				strcpy_s(signedHeaders[j+1], sizeof(signedHeaders[j+1]), temp1);
			}
        }
    }
    char tempheaders[1024]={0};
	for(i = 0; i < headerscount; i++)
	{
		strcpy_s(tempheaders+strlen(tempheaders), sizeof(tempheaders)-strlen(tempheaders), signedHeaders[i]);//ok
      if(i != headerscount - 1)
      {
          strcat_s(tempheaders,sizeof(tempheaders), ";");//ok
      }
	} 
//	for(i = 0; i < headerscount ; i++)printf("header[%d] = %s\n",i,headers[i]);
   	for(i = 0; i < headerscount ; i++)canonicalRequest_append("%s\n", headers[i]);
    canonicalRequest_append("%s\n", "");
 	canonicalRequest_append("%s\n", tempheaders);
//	printf("signedbuf = %s\n",canonicalRequest);
	char hashedPayload[65] = {0};
	char temp[32] = {0};
	char* empt="";
	SHA256Hash((unsigned char*)temp,(unsigned char *) empt,strlen(empt));
	ustr_to_hexes((unsigned char*)temp,sizeof(temp),(unsigned char*)hashedPayload);
//	printf("\nhashedPayload=%s\n",hashedPayload);
	canonicalRequest_append("%s", hashedPayload);
	
//	printf("canonicalRequest=%s\n",canonicalRequest);
	//COMMLOG(OBS_LOGDEBUG, "canonicalRequest = %s", canonicalRequest);

	SHA256Hash((unsigned char*)temp,(unsigned char *) canonicalRequest,len);
	char Hexreq[65] = {0};
	ustr_to_hexes((unsigned char*)temp,sizeof(temp),(unsigned char*)Hexreq);

	char stringToSign[1024] = {0};
	len = 0;
#define stringToSign_append(format, ...)                             \
		len += snprintf_s(&(stringToSign[len]), sizeof(stringToSign) - len, _TRUNCATE, 	\
						format, __VA_ARGS__)
	stringToSign_append("%s\n","AWS4-HMAC-SHA256");
    //time_t now = time(NULL);
    char date[64] = {0};
	char datime[64]= {0};
    //strftime(date, sizeof(date), "%Y%m%d", gmtime(&now));
	//strftime(datime, sizeof(datime), "%H%M%S", gmtime(&now));

	for(i = 0; i < values->amzHeadersCount; i++)
	{
		if (0 == strncmp(values->amzHeaders[i], "x-amz-date:", strlen("x-amz-date:")))
		{
			sscanf_s(values->amzHeaders[i], "x-amz-date: %8sT%6sZ", date, (unsigned)countof(date), datime, (unsigned)countof(datime));//ok
		}
	}

	stringToSign_append("%sT%sZ\n",date,datime);
	stringToSign_append("%s/%s/%s/%s\n",date,defaultRegionG,"s3","aws4_request");
	stringToSign_append("%s",Hexreq);
//	printf("stosign=%s\n",stringToSign);
	//COMMLOG(OBS_LOGDEBUG, "StringToSign = %s", stringToSign);

	char temp_key[256] = {0};
	unsigned char dateKey[32] = {0};
	unsigned char dateRegionKey[32] = {0};
	unsigned char dateRegionServicekey[32] = {0};
	unsigned char signingKey[32] = {0};
	unsigned char signature_hmac[32] = {0};
	unsigned char signature[64+1] = {0};

	unsigned char service[2];
	memcpy_s(service, sizeof(service), "s3", strlen("s3"));//ok
	unsigned char req[12];;
	memcpy_s(req, sizeof(req), "aws4_request", strlen("aws4_request"));//ok
	snprintf_s(temp_key,sizeof(temp_key), _TRUNCATE, "AWS4%s",params->bucketContext.secretAccessKey);//ok
//printf("temp_key = %s\n",temp_key);
	HMAC_SHA256(dateKey,  (unsigned char*)temp_key,strlen(temp_key), (unsigned char*)date,strlen(date));
	HMAC_SHA256(dateRegionKey,  dateKey,sizeof(dateKey), (unsigned char*)defaultRegionG,strlen(defaultRegionG));
	HMAC_SHA256(dateRegionServicekey,  dateRegionKey,sizeof(dateRegionKey), service,sizeof(service));
	HMAC_SHA256(signingKey,  dateRegionServicekey,sizeof(dateRegionServicekey), req,sizeof(req));
	HMAC_SHA256(signature_hmac,  signingKey,sizeof(signingKey), (unsigned char*)stringToSign,strlen(stringToSign));
	ustr_to_hexes(signature_hmac,sizeof(signature_hmac),signature);

//printf("dateKey=");
//unsigned int x;
/*for(x = 0;x < sizeof(dateKey);x++)printf("%.2x",dateKey[x]);
printf("\n");
printf("dateRegionKey=");
for(x = 0;x < sizeof(dateRegionKey);x++)printf("%.2x",dateRegionKey[x]);
printf("\n");
printf("dateRegionServicekey=");
for(x = 0;x < sizeof(dateRegionServicekey);x++)printf("%.2x",dateRegionServicekey[x]);
printf("\n");
printf("signingKey=");
for(x = 0;x < sizeof(signingKey);x++)printf("%.2x",signingKey[x]);
printf("\n");
*/
    snprintf_s(values->authorizationHeader, sizeof(values->authorizationHeader),_TRUNCATE, 
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/%s,SignedHeaders=%s,Signature=%s", params->bucketContext.accessKeyId,date,defaultRegionG,"s3","aws4_request",tempheaders,signature);
	

	
	
    return S3StatusOK;	
}


// Composes the Authorization header for the request
static S3Status compose_auth_header(const RequestParams *params,
                                    RequestComputedValues *values)
{
    // We allow for:
    // 17 bytes for HTTP-Verb + \n
    // 129 bytes for Content-MD5 + \n
    // 129 bytes for Content-Type + \n
    // 1 byte for empty Date + \n
    // CanonicalizedAmzHeaders & CanonicalizedResource
    char signbuf[17 + 129 + 129 + 1 + 
                 (sizeof(values->canonicalizedAmzHeaders) - 1) +
                 (sizeof(values->canonicalizedResource) - 1) + 1];
    int len = 0;
//cheack array index by jwx329074 2016.11.17
#define signbuf_append(format, ...)                             \
	if (snprintf_s(&(signbuf[len]), sizeof(signbuf) - len, _TRUNCATE,format, __VA_ARGS__) > 0)	\
	{																		\
		len += snprintf_s(&(signbuf[len]), sizeof(signbuf) - len, _TRUNCATE,      \
			format, __VA_ARGS__);											\
	}\
   

    signbuf_append
        ("%s\n", http_request_type_to_verb(params->httpRequestType));//lint !e666

    // For MD5 and Content-Type, use the value in the actual header, because
    // it's already been trimmed
    signbuf_append("%s\n", values->md5Header[0] ? 
                   &(values->md5Header[sizeof("Content-MD5: ") - 1]) : "");

    signbuf_append
        ("%s\n", values->contentTypeHeader[0] ? 
         &(values->contentTypeHeader[sizeof("Content-Type: ") - 1]) : "");

    signbuf_append("%s", "\n"); // Date - we always use x-amz-date

    signbuf_append("%s", values->canonicalizedAmzHeaders);

    signbuf_append("%s", values->canonicalizedResource);
	if( NULL != params->queryParams)
	{
		const char* pos;
		char tmp[1024]={0};
		if((pos=strstr(params->queryParams,"uploadId")) != NULL)
		{
			int len1 = pos - params->queryParams;
			if((pos=strstr(params->queryParams + len1,"&")) != NULL)
			{
				len1 = pos - params->queryParams;
			}
			else
			{
				len1 = strlen(params->queryParams);			
			}
			strncpy_s(tmp, sizeof(tmp),params->queryParams,len1);//ok
			signbuf_append("?%s", tmp);
		}
		if((pos=strstr(params->queryParams,"versionId")) != NULL)
		{
			if(params->subResource)
			{
				signbuf_append("&%s", params->queryParams);
			}
			else
			{
				signbuf_append("?%s", params->queryParams);
			}
		}
	}

    // Generate an HMAC-SHA-1 of the signbuf            .
	unsigned char hmac[20] = {0};
    HMAC_SHA1(hmac, (unsigned char *) params->bucketContext.secretAccessKey,
              strlen(params->bucketContext.secretAccessKey),
              (unsigned char *) signbuf, len);

    // Now base-64 encode the results
	char b64[((20 + 1) * 4) / 3] = {0};
    int b64Len = base64Encode(hmac, 20, b64);
    
    snprintf_s(values->authorizationHeader, sizeof(values->authorizationHeader),_TRUNCATE, 
             "Authorization: AWS %s:%.*s", params->bucketContext.accessKeyId,
             b64Len, b64);
    return S3StatusOK;
}


// Compose the URI to use for the request given the request parameters
static S3Status compose_uri(char *buffer, int bufferSize,
                            const S3BucketContext *bucketContext,
                            const char *urlEncodedKey,
                            const char *subResource, const char *queryParams)
{
    int len = 0;
    
#define uri_append(fmt, ...)                                                 \
    do {                                                                     \
        len += snprintf_s(&(buffer[len]), bufferSize - len, _TRUNCATE,  fmt, __VA_ARGS__); \
        if (len >= bufferSize) {                                             \
            return S3StatusUriTooLong;                                       \
        }                                                                    \
    } while (0)

    uri_append("http%s://", 
               (bucketContext->protocol == S3ProtocolHTTP) ? "" : "s");//lint !e409

    const char *hostName = 
        bucketContext->hostName ? bucketContext->hostName : defaultHostNameG;

    if (bucketContext->bucketName && 
        bucketContext->bucketName[0]) {//lint !e409
        if (bucketContext->uriStyle == S3UriStyleVirtualHost) {
            uri_append("%s.%s", bucketContext->bucketName, hostName);//lint !e409
        }
        else {
            uri_append("%s/%s", hostName, bucketContext->bucketName);//lint !e409
        }
    }
    else {
        uri_append("%s", hostName);//lint !e409
    }

    uri_append("%s", "/");//lint !e409

    uri_append("%s", urlEncodedKey);//lint !e409
    
    if (subResource && subResource[0]) {//lint !e409
        uri_append("?%s", subResource);//lint !e409
    }
    
    if (queryParams) {
        uri_append("%s%s", (subResource && subResource[0]) ? "&" : "?",
                   queryParams);//lint !e409
    }
    
    return S3StatusOK;
}


// Deal with the certificate
static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
    (void)curl;
    //(void)parm;

    X509_STORE *store = NULL;
    X509 *cert = NULL;
    BIO *bio = NULL;

    /* get a BIO */
    bio = BIO_new_mem_buf((char *)parm, -1);

    /* use it to read the PEM formatted certificate from memory into an X509
     * structure that SSL can use
    */
    PEM_read_bio_X509(bio, &cert, 0, NULL);
    
    /* get a pointer to the X509 certificage store */
    store = SSL_CTX_get_cert_store((SSL_CTX *)sslctx);

    /* add our certificate to this store */
    X509_STORE_add_cert(store, cert);

    /* decrease reference counts */
    X509_free(cert);
    BIO_free(bio);

    /* all set to go */
    return CURLE_OK;
}


// Sets up the curl handle given the completely computed RequestParams
static S3Status setup_curl(Request *request,
                           const RequestParams *params,
                           const RequestComputedValues *values)
{
    CURLcode status = CURLE_OK;

#define curl_easy_setopt_safe(opt, val)                                 \
    if ((status = curl_easy_setopt                                      \
         (request->curl, opt, val)) != CURLE_OK) {                      \
        return S3StatusFailedToInitializeRequest;                       \
    }

    // Debugging only
    // curl_easy_setopt_safe(CURLOPT_VERBOSE, 1);
    
    // Set private data to request for the benefit of S3RequestContext
    curl_easy_setopt_safe(CURLOPT_PRIVATE, request);
    
    // Set header callback and data
    curl_easy_setopt_safe(CURLOPT_HEADERDATA, request);
    curl_easy_setopt_safe(CURLOPT_HEADERFUNCTION, &curl_header_func);
    
    // Set read callback, data, and readSize
    curl_easy_setopt_safe(CURLOPT_READFUNCTION, &curl_read_func);
    curl_easy_setopt_safe(CURLOPT_READDATA, request);
    
    // Set write callback and data
    curl_easy_setopt_safe(CURLOPT_WRITEFUNCTION, &curl_write_func);
    curl_easy_setopt_safe(CURLOPT_WRITEDATA, request);

    // Ask curl to parse the Last-Modified header.  This is easier than
    // parsing it ourselves.
    curl_easy_setopt_safe(CURLOPT_FILETIME, 1);

    // Curl docs suggest that this is necessary for multithreaded code.
    // However, it also points out that DNS timeouts will not be honored
    // during DNS lookup, which can be worked around by using the c-ares
    // library, which we do not do yet.
    curl_easy_setopt_safe(CURLOPT_NOSIGNAL, 1);
    //curl_easy_setopt_safe(CURLOPT_TIMEOUT , 300L);

    // Turn off Curl's built-in progress meter
    curl_easy_setopt_safe(CURLOPT_NOPROGRESS, 1);

    // xxx todo - support setting the proxy for Curl to use (can't use https
    // for proxies though)

    // xxx todo - support setting the network interface for Curl to use

    // I think this is useful - we don't need interactive performance, we need
    // to complete large operations quickly
    curl_easy_setopt_safe(CURLOPT_TCP_NODELAY, 1);
    
    // Don't use Curl's 'netrc' feature
    curl_easy_setopt_safe(CURLOPT_NETRC, CURL_NETRC_IGNORED);

    // Don't verify S3's certificate, there are known to be issues with
    // them sometimes
    // xxx todo - support an option for verifying the S3 CA (default false)
    //curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0);
	
    //curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);

	if (1 == params->isCheckCA)
	{
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 1);
		
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);
		
		curl_easy_setopt_safe(CURLOPT_SSL_CTX_DATA, (void *)params->bucketContext.certificateInfo);
		
		curl_easy_setopt_safe(CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
	}
	else
	{
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0);
	
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);
	}

    // Follow any redirection directives that S3 sends
    curl_easy_setopt_safe(CURLOPT_FOLLOWLOCATION, 1);

    // A safety valve in case S3 goes bananas with redirects
    curl_easy_setopt_safe(CURLOPT_MAXREDIRS, 10);

    // Set the User-Agent; maybe Huawei will track these?
    curl_easy_setopt_safe(CURLOPT_USERAGENT, userAgentG);

    // Set the low speed limit and time; we abort transfers that stay at
    // less than 1K per second for more than 15 seconds.
    // xxx todo - make these configurable
    // xxx todo - allow configurable max send and receive speed
	
	// timeout value can be set Add by cwx298983 2016.08.19 Start
    curl_easy_setopt_safe(CURLOPT_LOW_SPEED_LIMIT, 1);
	
#if defined __GNUC__ || defined LINUX
    pthread_mutex_lock(&setTimeoutMutexG);
#else
	WaitForSingleObject(setTimeoutMutexG, INFINITE);
#endif

	if (0 == g_unTimeout)
	{
		// default value is 300 seconds
		curl_easy_setopt_safe(CURLOPT_LOW_SPEED_TIME, 300);
	}
	else
	{
		curl_easy_setopt_safe(CURLOPT_LOW_SPEED_TIME, g_unTimeout);
	}
	curl_easy_setopt_safe(CURLOPT_CONNECTTIMEOUT, 60);
	
#if defined __GNUC__ || defined LINUX
    pthread_mutex_unlock(&setTimeoutMutexG);
#else
	ReleaseMutex(setTimeoutMutexG);
#endif	    
	// timeout value can be set Add by cwx298983 2016.08.19 End

    // Append standard headers
#define append_standard_header(fieldName)                               \
    if (values-> fieldName [0]) {                                       \
        request->headers = curl_slist_append(request->headers,          \
                                             values-> fieldName);       \
    }

    // Would use CURLOPT_INFILESIZE_LARGE, but it is buggy in libcurl
    if ((params->httpRequestType == HttpRequestTypePUT) || (params->httpRequestType == HttpRequestTypePOST)) {
		char header[256] = {0};
        snprintf_s(header, sizeof(header),_TRUNCATE, "Content-Length: %llu", 
                 (unsigned long long) params->toS3CallbackTotalSize);
        request->headers = curl_slist_append(request->headers, header);
        request->headers = curl_slist_append(request->headers, 
                                             "Transfer-Encoding:");
    }
    else if (params->httpRequestType == HttpRequestTypeCOPY) {
        request->headers = curl_slist_append(request->headers, 
                                             "Transfer-Encoding:");
    }
    
    append_standard_header(cacheControlHeader);
	
	// delete default content-type by cwx298983 2015.11.24 Start
	if (values->contentTypeHeader[0])
	{
		request->headers = curl_slist_append(request->headers, 
                                             values->contentTypeHeader);
	}
	else
	{
		request->headers = curl_slist_append(request->headers, 
                                             "Content-Type:");
	}
	// delete default content-type by cwx298983 2015.11.24 End
											 
    append_standard_header(md5Header);
    append_standard_header(contentDispositionHeader);
    append_standard_header(contentEncodingHeader);
    append_standard_header(expiresHeader);
    append_standard_header(ifModifiedSinceHeader);
    append_standard_header(ifUnmodifiedSinceHeader);
    append_standard_header(ifMatchHeader);
    append_standard_header(ifNoneMatchHeader);
    append_standard_header(rangeHeader);
    append_standard_header(authorizationHeader);
    append_standard_header(storagepolicyHeader);
    append_standard_header(websiteredirectlocationHeader);

    // Append x-amz- headers
    int i;
    for (i = 0; i < values->amzHeadersCount; i++) {
        request->headers = 
            curl_slist_append(request->headers, values->amzHeaders[i]);
    }

    // Set the HTTP headers
    curl_easy_setopt_safe(CURLOPT_HTTPHEADER, request->headers);

    // Set URI
    curl_easy_setopt_safe(CURLOPT_URL, request->uri);

	// 增加日志记录内容 by cwx298983 2015.12.09 Start
    // Set request type.
    switch (params->httpRequestType) {
    case HttpRequestTypeHEAD:
		curl_easy_setopt_safe(CURLOPT_NOBODY, 1);
		COMMLOG(OBS_LOGINFO, "Method: HEAD");
        break;
    case HttpRequestTypePUT:
    case HttpRequestTypeCOPY:
        curl_easy_setopt_safe(CURLOPT_UPLOAD, 1);
		COMMLOG(OBS_LOGINFO, "Method: PUT");
        break;
    case HttpRequestTypeDELETE:
		curl_easy_setopt_safe(CURLOPT_CUSTOMREQUEST, "DELETE");
		COMMLOG(OBS_LOGINFO, "Method: DELETE");
        break;
    case HttpRequestTypePOST:        
        curl_easy_setopt_safe(CURLOPT_POST, 1L);
		COMMLOG(OBS_LOGINFO, "Method: POST");
		break;
	case HttpRequestTypeOPTIONS:
		curl_easy_setopt_safe(CURLOPT_CUSTOMREQUEST, "OPTIONS");
		COMMLOG(OBS_LOGINFO, "Method: OPTIONS");
		break;
    default: // HttpRequestTypeGET
		COMMLOG(OBS_LOGINFO, "Method: GET");
        break;
    }
	// 增加日志记录内容 by cwx298983 2015.12.09 End
    
    return S3StatusOK;
}


static void request_deinitialize(Request *request)
{
    if (request->headers) {
        curl_slist_free_all(request->headers);
    }
    
    error_parser_deinitialize(&(request->errorParser));

    // curl_easy_reset prevents connections from being re-used for some
    // reason.  This makes HTTP Keep-Alive meaningless and is very bad for
    // performance.  But it is necessary to allow curl to work properly.
    // xxx todo figure out why
    curl_easy_reset(request->curl);
}


static S3Status request_get(const RequestParams *params, 
                            const RequestComputedValues *values,
                            Request **reqReturn)
{
    Request *request = 0;
    
    // Try to get one from the request stack.  We hold the lock for the
    // shortest time possible here.

#if defined __GNUC__ || defined LINUX
    pthread_mutex_lock(&requestStackMutexG);
#else
	WaitForSingleObject(hmutex, INFINITE);
#endif

    if (requestStackCountG) {
        request = requestStackG[--requestStackCountG];
    }

#if defined __GNUC__ || defined LINUX
    pthread_mutex_unlock(&requestStackMutexG);
#else
	ReleaseMutex(hmutex);
#endif

    // If we got one, deinitialize it for re-use
    if (request) {
        request_deinitialize(request);
    }
    // Else there wasn't one available in the request stack, so create one
    else {
        if ((request = (Request *) malloc(sizeof(Request))) == NULL) {
            return S3StatusOutOfMemory;
        }
		memset_s(request,sizeof(Request), 0, sizeof(Request));
        if ((request->curl = curl_easy_init()) == NULL) {
            free(request);  //zwx367245 2016.10.19
			request = NULL; //zwx367245 2016.10.19 Set a pointer NULL after free();
            return S3StatusFailedToInitializeRequest;
        }
    }

    // Initialize the request
    request->prev = 0;
    request->next = 0;

    // Request status is initialized to no error, will be updated whenever
    // an error occurs
    request->status = S3StatusOK;

    S3Status status = S3StatusOK;
                        
    // Start out with no headers
    request->headers = 0;

    // Compute the URL
    if ((status = compose_uri
         (request->uri, sizeof(request->uri), 
          &(params->bucketContext), values->urlEncodedKey,
          params->subResource, params->queryParams)) != S3StatusOK) {
        curl_easy_cleanup(request->curl);
        free(request); //zwx367245 2016.10.19
		request = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
        return status;
    }

    // Set all of the curl handle options
    if ((status = setup_curl(request, params, values)) != S3StatusOK) {
        curl_easy_cleanup(request->curl);
		free(request); //zwx367245 2016.10.19
        request = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
        return status;
    }

    request->propertiesCallback = params->propertiesCallback;

    request->toS3Callback = params->toS3Callback;

    request->toS3CallbackBytesRemaining = params->toS3CallbackTotalSize;

    request->fromS3Callback = params->fromS3Callback;

    request->completeCallback = params->completeCallback;

    request->callbackData = params->callbackData;

    response_headers_handler_initialize(&(request->responseHeadersHandler));

    request->propertiesCallbackMade = 0;
    
    error_parser_initialize(&(request->errorParser));

    *reqReturn = request;
    
    return S3StatusOK;
}


static void request_destroy(Request *request)
{
    request_deinitialize(request);
    curl_easy_cleanup(request->curl);
    free(request);
	request = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
}


static void request_release(Request *request)
{
#if defined __GNUC__ || defined LINUX
	pthread_mutex_lock(&requestStackMutexG);
#else
	WaitForSingleObject(hmutex, INFINITE);
#endif

    // If the request stack is full, destroy this one
    if (requestStackCountG == REQUEST_STACK_SIZE) {
#if defined __GNUC__ || defined LINUX
		pthread_mutex_unlock(&requestStackMutexG);
#else
		ReleaseMutex(hmutex);
#endif
        request_destroy(request);
    }
    // Else put this one at the front of the request stack; we do this because
    // we want the most-recently-used curl handle to be re-used on the next
    // request, to maximize our chances of re-using a TCP connection before it
    // times out
    else {
        requestStackG[requestStackCountG++] = request;
#if defined __GNUC__ || defined LINUX
		pthread_mutex_unlock(&requestStackMutexG);
#else
		ReleaseMutex(hmutex);
#endif
    }
}


S3Status request_api_initialize(const char *userAgentInfo, int flags,
                                const char *defaultHostName,S3Authorization auth,const char* defaultRegion)
{
    if (curl_global_init(CURL_GLOBAL_ALL & 
                         ~((flags & S3_INIT_WINSOCK) ? 0 : CURL_GLOBAL_WIN32))
        != CURLE_OK) {
        return S3StatusInternalError;
    }
	
	init_locks();

    if (!defaultHostName) {
        defaultHostName = S3_DEFAULT_HOSTNAME;
    }

    if (snprintf_s(defaultHostNameG, S3_MAX_HOSTNAME_SIZE, _TRUNCATE, 
                 "%s", defaultHostName) >= S3_MAX_HOSTNAME_SIZE) {
        return S3StatusUriTooLong;
    }
    if (snprintf_s(defaultRegionG, REGION_SIZE, _TRUNCATE, 
                 "%s", defaultRegion) >= REGION_SIZE) {
        return S3StatusInvalidParameter;
    }
	authG = auth;

#if defined __GNUC__ || defined LINUX
    pthread_mutex_init(&requestStackMutexG, 0);
	pthread_mutex_init(&setTimeoutMutexG, 0);
#else
	hmutex = CreateMutexA(NULL, FALSE, "");
	setTimeoutMutexG = CreateMutexA(NULL, FALSE, "");
#endif

    requestStackCountG = 0;
	g_unTimeout = 0;

    if (!userAgentInfo || !*userAgentInfo) {
        userAgentInfo = "Unknown";
    }

	char platform[96];
#if defined __GNUC__ || defined LINUX
    struct utsname utsn;
    if (uname(&utsn)) {
        strncpy_s(platform, sizeof(platform), "Unknown", sizeof(platform));
        // Because strncpy doesn't always zero terminate
        platform[sizeof(platform) - 1] = 0;
    }
    else {
        snprintf_s(platform, sizeof(platform), _TRUNCATE, "%s%s%s", utsn.sysname, 
                 utsn.machine[0] ? " " : "", utsn.machine);
    }
#else
	OSVERSIONINFOEX os;
	if(GetVersionEx((OSVERSIONINFO *)&os))   
	{

	}
	else
	{
		strncpy_s(platform, sizeof(platform), "Unknown", sizeof(platform));
		platform[sizeof(platform) - 1] = 0;
	}

#endif
    //snprintf(userAgentG, sizeof(userAgentG), 
    //         "Mozilla/4.0 (Compatible; %s; libs3 %s.%s; %s)",
    //         userAgentInfo, LIBS3_VER_MAJOR, LIBS3_VER_MINOR, platform);
	snprintf_s(userAgentG, sizeof(userAgentG),_TRUNCATE, 
             "%s-%s.%s",
             PRODUCT, LIBS3_VER_MAJOR, LIBS3_VER_MINOR);
    
    return S3StatusOK;
}


void request_api_deinitialize()
{
#if defined __GNUC__ || defined LINUX
    pthread_mutex_destroy(&requestStackMutexG);
	pthread_mutex_destroy(&setTimeoutMutexG);
#else
	CloseHandle(hmutex);
	CloseHandle(setTimeoutMutexG);
#endif

	kill_locks();

    while (requestStackCountG--) {
        request_destroy(requestStackG[requestStackCountG]);
    }
}


void request_api_setTimeout(unsigned int unTimeout)
{
#if defined __GNUC__ || defined LINUX
    pthread_mutex_lock(&setTimeoutMutexG);
#else
	WaitForSingleObject(setTimeoutMutexG, INFINITE);
#endif

	g_unTimeout = unTimeout;
	
#if defined __GNUC__ || defined LINUX
    pthread_mutex_unlock(&setTimeoutMutexG);
#else
	ReleaseMutex(setTimeoutMutexG);
#endif
}

//lint -e607
void request_perform(const RequestParams *params, S3RequestContext *context)
{
    Request *request = NULL;
    S3Status status = S3StatusOK;

#define return_status(status)                                           \
    (*(params->completeCallback))(status, 0, params->callbackData);     \
	COMMLOG(OBS_LOGWARN, "%s status = %d", __FUNCTION__,status);\
    return

    // These will hold the computed values
    RequestComputedValues computed;
	memset_s(&computed,sizeof(RequestComputedValues), 0, sizeof(RequestComputedValues));//setadd

    // Validate the bucket name
    if (params->bucketContext.bucketName && 
        ((status = S3_validate_bucket_name
          (params->bucketContext.bucketName, 
           params->bucketContext.uriStyle)) != S3StatusOK)) {
        return_status(status);
    }

    // Compose the amz headers
    if ((status = compose_amz_headers(params, &computed)) != S3StatusOK) {
        return_status(status);
    }

    // Compose standard headers
    if ((status = compose_standard_headers
         (params, &computed)) != S3StatusOK) {
        return_status(status);
    }

    // URL encode the key
    if ((status = encode_key(params, &computed)) != S3StatusOK) {
        return_status(status);
    }

    // Compute the canonicalized amz headers
    canonicalize_amz_headers(&computed);

    // Compute the canonicalized resource
    canonicalize_resource(params->bucketContext.bucketName,
                          params->subResource, computed.urlEncodedKey,
                          computed.canonicalizedResource, sizeof(computed.canonicalizedResource));

	if(authG)
	{
		if ((status = compose_authV4_header(params, &computed)) != S3StatusOK) {
    	    return_status(status);
    	}
	}
	else
	{
	    // Compose Authorization header
	    if ((status = compose_auth_header(params, &computed)) != S3StatusOK) {
	        return_status(status);
	    }
	}

    //printf("authorizationHeader = %s \n",computed.authorizationHeader);
    // Get an initialized Request structure now
    if ((status = request_get(params, &computed, &request)) != S3StatusOK) {
        return_status(status);
    }

	char errorBuffer[CURL_ERROR_SIZE];
	memset_s(errorBuffer, sizeof(errorBuffer), 0, CURL_ERROR_SIZE);//setadd

	//Cheack return value by jwx329074 2016.11.16
	CURLcode setoptResult =  curl_easy_setopt(request->curl,CURLOPT_ERRORBUFFER,errorBuffer);
	if (setoptResult != CURLE_OK)
	{
		COMMLOG(OBS_LOGWARN, "%s curl_easy_perform failed! CURLcode = %d", __FUNCTION__,setoptResult);
	}

    // If a RequestContext was provided, add the request to the curl multi
    if (context) {
        CURLMcode code = curl_multi_add_handle(context->curlm, request->curl);
        if (code == CURLM_OK) {
            if (context->requests) {
                request->prev = context->requests->prev;
                request->next = context->requests;
                context->requests->prev->next = request;
                context->requests->prev = request;
            }
            else {
                context->requests = request->next = request->prev = request;
            }
        }
        else {
            if (request->status == S3StatusOK) {
                request->status = (code == CURLM_OUT_OF_MEMORY) ?
                    S3StatusOutOfMemory : S3StatusInternalError;
            }
            request_finish(request);
        }
    }

    // Else, perform the request immediately
    else {
        CURLcode code = curl_easy_perform(request->curl);
        if ((code != CURLE_OK) && (request->status == S3StatusOK)) {
            request->status = request_curl_code_to_status(code);
			COMMLOG(OBS_LOGWARN, "%s curl_easy_perform code = %d,status = %d,errorBuffer = %s", __FUNCTION__,code,request->status,errorBuffer);
        }
        // Finish the request, ensuring that all callbacks have been made, and
        // also releases the request
        request_finish(request);
    }
}
//lint +e607
//lint -e115
void request_finish(Request *request)
{
    // If we haven't detected this already, we now know that the headers are
    // definitely done being read in
    request_headers_done(request);
    
	OBS_LOGLEVEL logLevel;
	
	if ((request->status != S3StatusOK) || (((request->httpResponseCode < 200) || (request->httpResponseCode > 299)) && (100 != request->httpResponseCode)))
	{
		logLevel = OBS_LOGWARN;
	}
	else
	{
		logLevel = OBS_LOGINFO;
	}
	
	struct curl_slist* tmp = request->headers;
		while (NULL != tmp)
		{
			if (0 != strncmp(tmp->data, "Authorization:", 14))
			{
				COMMLOG(logLevel, tmp->data);
			}	
			tmp = tmp->next;
		}
		COMMLOG(logLevel, "%s request_finish status = %d,httpResponseCode = %d", __FUNCTION__,request->status,request->httpResponseCode);
		COMMLOG(logLevel, "Message: %s", request->errorParser.s3ErrorDetails.message);
		COMMLOG(logLevel, "Request Id: %s", request->responseHeadersHandler.responseProperties.requestId);
//lint +e115
    if(request->errorParser.codeLen)//lint !e539
    {
        COMMLOG(logLevel, "Code: %s", request->errorParser.code);
    }
	// 增加日志记录内容 by cwx298983 2015.12.09 End
    // If there was no error processing the request, then possibly there was
    // an S3 error parsed, which should be converted into the request status
    if (request->status == S3StatusOK) {
        error_parser_convert_status(&(request->errorParser), 
                                    &(request->status));
        // If there still was no error recorded, then it is possible that
        // there was in fact an error but that there was no error XML
        // detailing the error
        if ((request->status == S3StatusOK) &&
            ((request->httpResponseCode < 200) ||
             (request->httpResponseCode > 299))) {
            switch (request->httpResponseCode) {
            case 0:
                // This happens if the request never got any HTTP response
                // headers at all, we call this a ConnectionFailed error
                request->status = S3StatusConnectionFailed;
                break;
            case 100: // Some versions of libcurl erroneously set HTTP
                      // status to this
                break;
            case 301:
                request->status = S3StatusPermanentRedirect;
                break;
            case 307:
                request->status = S3StatusHttpErrorMovedTemporarily;
                break;
            case 400:
                request->status = S3StatusHttpErrorBadRequest;
                break;
            case 403: 
                request->status = S3StatusHttpErrorForbidden;
                break;
            case 404:
                request->status = S3StatusHttpErrorNotFound;
                break;
            case 405:
                request->status = S3StatusMethodNotAllowed;
                break;
            case 409:
                request->status = S3StatusHttpErrorConflict;
                break;
            case 411:
                request->status = S3StatusMissingContentLength;
                break;
            case 412:
                request->status = S3StatusPreconditionFailed;
                break;
            case 416:
                request->status = S3StatusInvalidRange;
                break;
            case 500:
                request->status = S3StatusInternalError;
                break;
            case 501:
                request->status = S3StatusNotImplemented;
                break;
            case 503:
                request->status = S3StatusSlowDown;
                break;
            default:
                request->status = S3StatusHttpErrorUnknown;
                break;
            }
        }
    }
    (*(request->completeCallback))
        (request->status, &(request->errorParser.s3ErrorDetails),
         request->callbackData);
    request_release(request);
}

//lint -e30 -e142
S3Status request_curl_code_to_status(CURLcode code)
{
    switch (code) {
    case CURLE_OUT_OF_MEMORY:
        return S3StatusOutOfMemory;
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_RESOLVE_HOST:
        return S3StatusNameLookupError;
    case CURLE_COULDNT_CONNECT:
        return S3StatusFailedToConnect;
    case CURLE_WRITE_ERROR:
    case CURLE_OPERATION_TIMEDOUT:
        return S3StatusConnectionFailed;
    case CURLE_PARTIAL_FILE:
        return S3StatusPartialFile;
    case CURLE_SSL_CACERT:
        return S3StatusServerFailedVerification;
    default:
        return S3StatusInternalError;
    }
}
//lint +e30 +e142

S3Status S3_generate_authenticated_query_string
	(char *buffer, const S3BucketContext *bucketContext,
	const char *key, int64_t expires, const char *resource)
{
#define MAX_EXPIRES (((int64_t) 1 << 31) - 1)
	// S3 seems to only accept expiration dates up to the number of seconds
	// representably by a signed 32-bit integer
	if (expires < 0) {
		expires = MAX_EXPIRES;
	}
	else if (expires > MAX_EXPIRES) {
		expires = MAX_EXPIRES;
	}

	// xxx todo: rework this so that it can be incorporated into shared code
	// with request_perform().  It's really unfortunate that this code is not
	// shared with request_perform().

	// URL encode the key
	char urlEncodedKey[S3_MAX_KEY_SIZE * 3] = {0};
	int urlEncode_value;
	if (key) {
		urlEncode_value = urlEncode(urlEncodedKey, key, strlen(key));
	}
	else {
		urlEncodedKey[0] = 0;
	}

	// Compute canonicalized resource
	char canonicalizedResource[MAX_CANONICALIZED_RESOURCE_SIZE] = {0};
	canonicalize_resource(bucketContext->bucketName, resource, urlEncodedKey,
		canonicalizedResource, MAX_CANONICALIZED_RESOURCE_SIZE);

	// We allow for:
	// 17 bytes for HTTP-Verb + \n
	// 1 byte for empty Content-MD5 + \n
	// 1 byte for empty Content-Type + \n
	// 20 bytes for Expires + \n
	// 0 bytes for CanonicalizedAmzHeaders
	// CanonicalizedResource
	char signbuf[17 + 1 + 1 + 1 + 20 + sizeof(canonicalizedResource) + 1] = {0};
	int len = 0;

	signbuf_append("%s\n", "GET"); // HTTP-Verb
	signbuf_append("%s\n", ""); // Content-MD5
	signbuf_append("%s\n", ""); // Content-Type
	signbuf_append("%llu\n", (unsigned long long) expires);
	signbuf_append("%s", canonicalizedResource);

	// Generate an HMAC-SHA-1 of the signbuf
	unsigned char hmac[20] = {0};

	HMAC_SHA1(hmac, (unsigned char *) bucketContext->secretAccessKey,
		strlen(bucketContext->secretAccessKey),
		(unsigned char *) signbuf, len);

	// Now base-64 encode the results
	char b64[((20 + 1) * 4) / 3] = {0};
	int b64Len = base64Encode(hmac, 20, b64);

	// Now urlEncode that
	char signature[sizeof(b64) * 3] = {0};

	// 增加返回值判断 by jwx329074 2016.10.11
	int urlEncodeValue;
	urlEncodeValue = urlEncode(signature, b64, b64Len);
	if (urlEncodeValue == 1)
	{
		return S3StatusInternalError;
	}


	// Finally, compose the uri, with params:
	// ?AWSAccessKeyId=xxx[&Expires=]&Signature=xxx
	char queryParams[sizeof("AWSAccessKeyId=") + 20 + 
		sizeof("&Expires=") + 20 + 
		sizeof("&Signature=") + sizeof(signature) + 1] = {0};

	sprintf_s(queryParams, sizeof(queryParams), "AWSAccessKeyId=%s&Expires=%ld&Signature=%s",
		bucketContext->accessKeyId, (long) expires, signature);//ok

	return compose_uri(buffer, S3_MAX_AUTHENTICATED_QUERY_STRING_SIZE,
		bucketContext, urlEncodedKey, resource, queryParams);//lint !e550
}


#define OVECCOUNT 100  

int pcre_replace(const char* src,char ** destOut)
{
	pcre  *re = NULL;
	const char *error = NULL;
	int src_len = 0;
	int  erroffset = 0;
	int  ovector[OVECCOUNT]={0};
	src_len = strlen(src);
	re = pcre_compile("[&\'\"<>]",
		0,
		&error,
		&erroffset,
		NULL);
	if (re == NULL)
	{
		//printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
		return 0;
	}
	int count = 0;
	int offset = 0;
	while( pcre_exec(re,NULL,src,src_len,offset,0,&ovector[count*2],OVECCOUNT) > 0)
	{
		offset=ovector[count*2 + 1];
		count++;
	}
	CHECK_NULL_FREE(re);
	if(count == 0)
	{
		return 0;
	}
	if(src_len + count*6<1)
	{
		COMMLOG(OBS_LOGERROR, "Invalid Malloc Parameter!");
		return 0;
	}
	char* dest = (char *)malloc(sizeof(char)*(src_len + count*6));
	if(dest==NULL)   //zwx367245 2016.10.08 添加对分配内存结果的判断
	{
		COMMLOG(OBS_LOGERROR, "Malloc dest failed !");
		return 0;
	}
	memset_s(dest, sizeof(char)*(src_len + count*6), 0,(src_len + count*6));
	int i;
	offset = 0;
	for(i = 0; i < count; i++)
	{
		if(i == 0)
		{
			strncpy_s(dest + offset, src_len + count*6 - offset, src , ovector[i*2]);
			offset = ovector[i*2];
		}
		else
		{
			strncpy_s(dest + offset, src_len + count*6 - offset, src + ovector[i*2-1], ovector[i*2]-ovector[i*2-1]);
			offset += ovector[i*2]-ovector[i*2-1];
		}
		if(src[ovector[i*2]] == '<')
		{
			strcat_s(dest, sizeof(char)*(src_len + count*6), "&lt;");
			offset += 4;
		}
		if(src[ovector[i*2]] == '>')
		{
			strcat_s(dest, sizeof(char)*(src_len + count*6), "&gt;");
			offset += 4;
		}
		if(src[ovector[i*2]] == '&')
		{
			strcat_s(dest, sizeof(char)*(src_len + count*6), "&amp;");
			offset += 5;
		}
		if(src[ovector[i*2]] == '\'')
		{
			strcat_s(dest, sizeof(char)*(src_len + count*6), "&apos;");
			offset += 6;
		}
		if(src[ovector[i*2]] == '\"')
		{
			strcat_s(dest, sizeof(char)*(src_len + count*6), "&quot;");
			offset += 6;
		}

	}
	*destOut = dest;
	return count;
}
//lint +e26 +e31 +e63 +e64 +e78 +e101 +e119 +e129 +e144 +e156 +e438 +e505 +e516 +e515 +e522 +e529 +e530 +e533 +e534 +e546 +e551 +e578 +e601
