/** **************************************************************************
 * s3.c
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

/**
 * This is a 'driver' program that simply converts command-line input into
 * calls to libs3 functions, and prints the results.
 **/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#if defined __GNUC__ || defined LINUX
#include <string.h>
#include <getopt.h>
#include <strings.h>
#include <unistd.h>
#else
#include "getopt.h"
#endif

#include "eSDKOBSS3.h"
#include "securec.h"

// Some Windows stuff
#ifndef FOPEN_EXTRA_FLAGS
#define FOPEN_EXTRA_FLAGS ""
#endif

// Some Unix stuff (to work around Windows issues)
#ifndef SLEEP_UNITS_PER_SECOND
#define SLEEP_UNITS_PER_SECOND 1
#endif

#ifndef SLEEP_UNITS_PER_SECOND_WIN
#define SLEEP_UNITS_PER_SECOND_WIN 1000
#endif

#ifdef _MSC_VER
#define snprintf_s _snprintf_s
#endif

// Also needed for Windows, because somehow MinGW doesn't define this
#if defined __GNUC__ || defined LINUX
extern int putenv(char *);
#endif 

#if defined __GNUC__ || defined LINUX
/* _TRUNCATE */
#define _TRUNCATE ((size_t)-1)
#endif

// Command-line options, saved as globals ------------------------------------
//lint -e26 -e30 -e31 -e42 -e48 -e50 -e63 -e64 -e78 -e86 -e101 -e119 -e129 -e142 -e144 -e156 -e409 -e438 -e505 -e515 -e516 -e522 -e525 -e528 -e529 -e530 -e533 -e534 -e539 -e546 -e550 -e551 -e560 -e565 -e574 -e578 -e601
static int forceG = 0;
static int showResponsePropertiesG = 1;
static S3Protocol protocolG = S3ProtocolHTTPS;
static S3UriStyle uriStyleG = S3UriStylePath;
static int retriesG = 5;


// Environment variables, saved as globals ----------------------------------

static const char *accessKeyIdG = 0;
static const char *secretAccessKeyG = 0;


// Request results, saved as globals -----------------------------------------

static S3Status statusG = S3StatusOK;
static char errorDetailsG[4096] = { 0 };


// Other globals -------------------------------------------------------------

static char putenvBufG[256] = {0};


// Certificate Information
static char *pCAInfo = 0;

// Option prefixes -----------------------------------------------------------

#define LOCATION_PREFIX "location="
#define LOCATION_PREFIX_LEN (sizeof(LOCATION_PREFIX) - 1)
#define CANNED_ACL_PREFIX "cannedAcl="
#define CANNED_ACL_PREFIX_LEN (sizeof(CANNED_ACL_PREFIX) - 1)
#define PREFIX_PREFIX "prefix="
#define PREFIX_PREFIX_LEN (sizeof(PREFIX_PREFIX) - 1)
#define MARKER_PREFIX "marker="
#define MARKER_PREFIX_LEN (sizeof(MARKER_PREFIX) - 1)
#define DELIMITER_PREFIX "delimiter="
#define DELIMITER_PREFIX_LEN (sizeof(DELIMITER_PREFIX) - 1)
#define UPLOADIDMARKE_PREFIX "uploadidmarke="
#define UPLOADIDMARKE_PREFIX_LEN (sizeof(UPLOADIDMARKE_PREFIX) - 1)
#define MAXKEYS_PREFIX "maxkeys="
#define MAXKEYS_PREFIX_LEN (sizeof(MAXKEYS_PREFIX) - 1)
#define FILENAME_PREFIX "filename="
#define FILENAME_PREFIX_LEN (sizeof(FILENAME_PREFIX) - 1)
#define CONTENT_LENGTH_PREFIX "contentLength="
#define CONTENT_LENGTH_PREFIX_LEN (sizeof(CONTENT_LENGTH_PREFIX) - 1)
#define CACHE_CONTROL_PREFIX "cacheControl="
#define CACHE_CONTROL_PREFIX_LEN (sizeof(CACHE_CONTROL_PREFIX) - 1)
#define CONTENT_TYPE_PREFIX "contentType="
#define CONTENT_TYPE_PREFIX_LEN (sizeof(CONTENT_TYPE_PREFIX) - 1)
#define MD5_PREFIX "md5="
#define MD5_PREFIX_LEN (sizeof(MD5_PREFIX) - 1)
#define CONTENT_DISPOSITION_FILENAME_PREFIX "contentDispositionFilename="
#define CONTENT_DISPOSITION_FILENAME_PREFIX_LEN \
    (sizeof(CONTENT_DISPOSITION_FILENAME_PREFIX) - 1)
#define CONTENT_ENCODING_PREFIX "contentEncoding="
#define CONTENT_ENCODING_PREFIX_LEN (sizeof(CONTENT_ENCODING_PREFIX) - 1)
#define EXPIRES_PREFIX "expires="
#define EXPIRES_PREFIX_LEN (sizeof(EXPIRES_PREFIX) - 1)
#define X_AMZ_META_PREFIX "x-amz-meta-"
#define X_AMZ_META_PREFIX_LEN (sizeof(X_AMZ_META_PREFIX) - 1)
#define USE_SERVER_SIDE_ENCRYPTION_PREFIX "useServerSideEncryption="
#define USE_SERVER_SIDE_ENCRYPTION_PREFIX_LEN \
    (sizeof(USE_SERVER_SIDE_ENCRYPTION_PREFIX) - 1)
#define IF_MODIFIED_SINCE_PREFIX "ifModifiedSince="
#define IF_MODIFIED_SINCE_PREFIX_LEN (sizeof(IF_MODIFIED_SINCE_PREFIX) - 1)
#define IF_NOT_MODIFIED_SINCE_PREFIX "ifNotmodifiedSince="
#define IF_NOT_MODIFIED_SINCE_PREFIX_LEN \
    (sizeof(IF_NOT_MODIFIED_SINCE_PREFIX) - 1)
#define IF_MATCH_PREFIX "ifMatch="
#define IF_MATCH_PREFIX_LEN (sizeof(IF_MATCH_PREFIX) - 1)
#define IF_NOT_MATCH_PREFIX "ifNotMatch="
#define IF_NOT_MATCH_PREFIX_LEN (sizeof(IF_NOT_MATCH_PREFIX) - 1)
#define START_BYTE_PREFIX "startByte="
#define START_BYTE_PREFIX_LEN (sizeof(START_BYTE_PREFIX) - 1)
#define BYTE_COUNT_PREFIX "byteCount="
#define BYTE_COUNT_PREFIX_LEN (sizeof(BYTE_COUNT_PREFIX) - 1)
#define ALL_DETAILS_PREFIX "allDetails="
#define ALL_DETAILS_PREFIX_LEN (sizeof(ALL_DETAILS_PREFIX) - 1)
#define NO_STATUS_PREFIX "noStatus="
#define NO_STATUS_PREFIX_LEN (sizeof(NO_STATUS_PREFIX) - 1)
#define RESOURCE_PREFIX "resource="
#define RESOURCE_PREFIX_LEN (sizeof(RESOURCE_PREFIX) - 1)
#define TARGET_BUCKET_PREFIX "targetBucket="
#define TARGET_BUCKET_PREFIX_LEN (sizeof(TARGET_BUCKET_PREFIX) - 1)
#define TARGET_PREFIX_PREFIX "targetPrefix="
#define TARGET_PREFIX_PREFIX_LEN (sizeof(TARGET_PREFIX_PREFIX) - 1)
#define KEY_PREFIX "key="
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1)
#define UPLOADID_PREFIX "uploadId="
#define UPLOADID_PREFIX_LEN (sizeof(UPLOADID_PREFIX) - 1)
#define RECIVE_STREAM_LENGTH 256
#define VERSIONID_PREFIX "versionId="
#define VERSIONID_PREFIX_LEN (sizeof(VERSIONID_PREFIX) - 1)
#define STATUS_PREFIX "status="
#define STATUS_PREFIX_LEN (sizeof(STATUS_PREFIX) - 1)
#define GRANTEE_PREFIX "grantee="
#define GRANTEE_PREFIX_LEN (sizeof(GRANTEE_PREFIX) - 1)
#define PERMISSION_PREFIX "permission="
#define PERMISSION_PREFIX_LEN (sizeof(PERMISSION_PREFIX) - 1)
#define OWNERID_PREFIX "ownerID="
#define OWNERID_PREFIX_LEN (sizeof(OWNERID_PREFIX) - 1)
#define OWNERID_DISPLAY_NAME_PREFIX "ownerDisplayName="
#define OWNERID_DISPLAY_NAME_PREFIX_LEN (sizeof(OWNERID_DISPLAY_NAME_PREFIX) - 1)

#define USEKMS_PREFIX "usekms="
#define USEKMS_PREFIX_LEN (sizeof(USEKMS_PREFIX) - 1)
#define USESSEC_PREFIX "usessec="
#define USESSEC_PREFIX_LEN (sizeof(USESSEC_PREFIX) - 1)
#define KMSSERVERSIDEENCRYPTION_PREFIX "kmsServerSideEncryption="
#define KMSSERVERSIDEENCRYPTION_PREFIX_LEN (sizeof(KMSSERVERSIDEENCRYPTION_PREFIX) - 1)
#define KMSKEYID_PREFIX "kmsKeyId="
#define KMSKEYID_PREFIX_LEN (sizeof(KMSKEYID_PREFIX) - 1)
#define KMSENCRYPTIONCONTEXT_PREFIX "kmsEncryptionContext="
#define KMSENCRYPTIONCONTEXT_PREFIX_LEN (sizeof(KMSENCRYPTIONCONTEXT_PREFIX) - 1)
#define SSECCUSTOMERALGORITHM_PREFIX "ssecCustomerAlgorithm="
#define SSECCUSTOMERALGORITHM_PREFIX_LEN (sizeof(SSECCUSTOMERALGORITHM_PREFIX) - 1)
#define SSECCUSTOMERKEY_PREFIX "ssecCustomerKey="
#define SSECCUSTOMERKEY_PREFIX_LEN (sizeof(SSECCUSTOMERKEY_PREFIX) - 1)
#define SSECCUSTOMERKEYMD5_PREFIX "ssecCustomerKeyMD5="
#define SSECCUSTOMERKEYMD5_PREFIX_LEN (sizeof(SSECCUSTOMERKEYMD5_PREFIX) - 1)
#define DESSSECCUSTOMERALGORITHM_PREFIX "des_ssecCustomerAlgorithm="
#define DESSSECCUSTOMERALGORITHM_PREFIX_LEN (sizeof(DESSSECCUSTOMERALGORITHM_PREFIX) - 1)
#define DESSSECCUSTOMERKEY_PREFIX "des_ssecCustomerKey="
#define DESSSECCUSTOMERKEY_PREFIX_LEN (sizeof(DESSSECCUSTOMERKEY_PREFIX) - 1)
#define DESSSECCUSTOMERKEYMD5_PREFIX "des_ssecCustomerKeyMD5="
#define DESSSECCUSTOMERKEYMD5_PREFIX_LEN (sizeof(DESSSECCUSTOMERKEYMD5_PREFIX) - 1)


// util ----------------------------------------------------------------------

static void S3_init()
{
    S3Status status = S3StatusOK;
    const char *hostname = getenv("S3_HOSTNAME");
    
    if ((status = S3_initialize("s3", S3_INIT_ALL, hostname,AuthorizationV4, "china"))
        != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", 
                S3_get_status_name(status));
        exit(-1);
    }
}


static void printError()
{
    if (statusG < S3StatusAccessDenied) {
        fprintf(stderr, "\nERROR: %s\n", S3_get_status_name(statusG));
    }
    else {
        fprintf(stderr, "\nERROR: %s\n", S3_get_status_name(statusG));
        fprintf(stderr, "%s\n", errorDetailsG);
    }
}


static void usageExit(FILE *out)
{
    fprintf(out,
"\n Options:\n"
"\n"
"   Command Line:\n"
"\n"
"   -f/--force           : force operation despite warnings\n"
"   -h/--vhost-style     : use virtual-host-style URIs (default is "
                          "path-style)\n"
"   -u/--unencrypted     : unencrypted (use HTTP instead of HTTPS)\n"
"   -s/--show-properties : show response properties on stdout\n"
"   -r/--retries         : retry retryable failures this number of times\n"
"                          (default is 5)\n"
"\n"
"   Environment:\n"
"\n"
"   S3_ACCESS_KEY_ID     : S3 access key ID (required)\n"
"   S3_SECRET_ACCESS_KEY : S3 secret access key (required)\n"
"   S3_HOSTNAME          : specify alternative S3 host (optional)\n"
"\n" 
" Commands (with <required parameters> and [optional parameters]) :\n"
"\n"
"   (NOTE: all command parameters take a value and are specified using the\n"
"          pattern parameter=value)\n"
"\n"
"   help                 : Prints this help text\n"
"\n"
"   list                 : Lists owned buckets\n"
"     [allDetails]       : Show full details\n"
"\n"
"   test                 : Tests a bucket for existence and accessibility\n"
"     <bucket>           : Bucket to test\n"
"\n"
"   create               : Create a new bucket\n"
"     <bucket>           : Bucket to create\n"
"     [cannedAcl]        : Canned ACL for the bucket (see Canned ACLs)\n"
"     [location]         : Location for bucket (for example, EU)\n"
"\n"
"   delete               : Delete a bucket or key\n"
"     <bucket>[/<key>]   : Bucket or bucket/key to delete\n"
"\n"
"   list                 : List bucket contents\n"
"     <bucket>           : Bucket to list\n"
"     [prefix]           : Prefix for results set\n"
"     [marker]           : Where in results set to start listing\n"
"     [delimiter]        : Delimiter for rolling up results set\n"
"     [maxkeys]          : Maximum number of keys to return in results set\n"
"     [allDetails]       : Show full details for each key\n"
"\n"
"   getacl               : Get the ACL of a bucket or key\n"
"     <bucket>[/<key>]   : Bucket or bucket/key to get the ACL of\n"
"     [filename]         : Output filename for ACL (default is stdout)\n"
"\n"
"   setacl               : Set the ACL of a bucket or key\n"
"     <bucket>[/<key>]   : Bucket or bucket/key to set the ACL of\n"
"     [filename]         : Input filename for ACL (default is stdin)\n"
"\n"
"   getlogging           : Get the logging status of a bucket\n"
"     <bucket>           : Bucket to get the logging status of\n"
"     [filename]         : Output filename for ACL (default is stdout)\n"
"\n"
"   setlogging           : Set the logging status of a bucket\n"
"     <bucket>           : Bucket to set the logging status of\n"
"     [targetBucket]     : Target bucket to log to; if not present, disables\n"
"                          logging\n"
"     [targetPrefix]     : Key prefix to use for logs\n"
"     [filename]         : Input filename for ACL (default is stdin)\n"
"\n"
"   put                  : Puts an object\n"
"     <bucket>/<key>     : Bucket/key to put object to\n"
"     [filename]         : Filename to read source data from "
                          "(default is stdin)\n"
"     [contentLength]    : How many bytes of source data to put (required if\n"
"                          source file is stdin)\n"
"     [cacheControl]     : Cache-Control HTTP header string to associate with\n"
"                          object\n"
"     [contentType]      : Content-Type HTTP header string to associate with\n"
"                          object\n"
"     [md5]              : MD5 for validating source data\n"
"     [contentDispositionFilename] : Content-Disposition filename string to\n"
"                          associate with object\n"
"     [contentEncoding]  : Content-Encoding HTTP header string to associate\n"
"                          with object\n"
"     [expires]          : Expiration date to associate with object\n"
"     [cannedAcl]        : Canned ACL for the object (see Canned ACLs)\n"
"     [x-amz-meta-...]]  : Metadata headers to associate with the object\n"
"     [useServerSideEncryption] : Whether or not to use server-side\n"
"                          encryption for the object\n"
"\n"
"   copy                 : Copies an object; if any options are set, the "
                          "entire\n"
"                          metadata of the object is replaced\n"
"     <sourcebucket>/<sourcekey> : Source bucket/key\n"
"     <destbucket>/<destkey> : Destination bucket/key\n"
"     [cacheControl]     : Cache-Control HTTP header string to associate with\n"
"                          object\n"
"     [contentType]      : Content-Type HTTP header string to associate with\n"
"                          object\n"
"     [contentDispositionFilename] : Content-Disposition filename string to\n"
"                          associate with object\n"
"     [contentEncoding]  : Content-Encoding HTTP header string to associate\n"
"                          with object\n"
"     [expires]          : Expiration date to associate with object\n"
"     [cannedAcl]        : Canned ACL for the object (see Canned ACLs)\n"
"     [x-amz-meta-...]]  : Metadata headers to associate with the object\n"
"\n"
"   get                  : Gets an object\n"
"     <buckey>/<key>     : Bucket/key of object to get\n"
"     [filename]         : Filename to write object data to (required if -s\n"
"                          command line parameter was used)\n"
"     [ifModifiedSince]  : Only return the object if it has been modified "
                          "since\n"
"                          this date\n"
"     [ifNotmodifiedSince] : Only return the object if it has not been "
                          "modified\n"
"                          since this date\n"
"     [ifMatch]          : Only return the object if its ETag header matches\n"
"                          this string\n"
"     [ifNotMatch]       : Only return the object if its ETag header does "
                          "not\n"
"                          match this string\n"
"     [startByte]        : First byte of byte range to return\n"
"     [byteCount]        : Number of bytes of byte range to return\n"
"\n"
"   head                 : Gets only the headers of an object, implies -s\n"
"     <bucket>/<key>     : Bucket/key of object to get headers of\n"
"\n"
"   gqs                  : Generates an authenticated query string\n"
"     <bucket>[/<key>]   : Bucket or bucket/key to generate query string for\n"
"     [expires]          : Expiration date for query string\n"
"     [resource]         : Sub-resource of key for query string, without a\n"
"                          leading '?', for example, \"torrent\"\n"
"\n"
" Canned ACLs:\n"
"\n"
"  The following canned ACLs are supported:\n"
"    private (default), public-read, public-read-write, authenticated-read\n"
"\n"
" ACL Format:\n"
"\n"
"  For the getacl and setacl commands, the format of the ACL list is:\n"
"  1) An initial line giving the owner id in this format:\n"
"       OwnerID <Owner ID> <Owner Display Name>\n"
"  2) Optional header lines, giving column headers, starting with the\n"
"     word \"Type\", or with some number of dashes\n"
"  3) Grant lines, of the form:\n"
"       <Grant Type> (whitespace) <Grantee> (whitespace) <Permission>\n"
"     where Grant Type is one of: Email, UserID, or Group, and\n"
"     Grantee is the identification of the grantee based on this type,\n"
"     and Permission is one of: READ, WRITE, READ_ACP, or FULL_CONTROL.\n"
"\n"
"  Note that the easiest way to modify an ACL is to first get it, saving it\n"
"  into a file, then modifying the file, and then setting the modified file\n"
"  back as the new ACL for the bucket/object.\n"
"\n"
" Date Format:\n"
"\n"
"  The format for dates used in parameters is as ISO 8601 dates, i.e.\n"
"  YYYY-MM-DDTHH:MM:SS[+/-dd:dd].  Examples:\n"
"      2008-07-29T20:36:14\n"
"      2008-07-29T20:36:14-06:00\n"
"      2008-07-29T20:36:14+11:30\n"
"\n");

    exit(-1);
}


static uint64_t convertInt(const char *str, const char *paramName)
{
    uint64_t ret = 0;

    while (*str) {
        if (!isdigit(*str)) {
            fprintf(stderr, "\nERROR: Nondigit in %s parameter: %c\n", 
                    paramName, *str);
            usageExit(stderr);
        }
        ret *= 10;
        ret += (*str++ - '0');
    }

    return ret;
}


typedef struct growbuffer
{
    // The total number of bytes, and the start byte
    int size;
    // The start byte
    int start;
    // The blocks
    char data[64 * 1024];
    struct growbuffer *prev, *next;
} growbuffer;


// returns nonzero on success, zero on out of memory
static int growbuffer_append(growbuffer **gb, const char *data, int dataLen)
{
    while (dataLen) {
        growbuffer *buf = *gb ? (*gb)->prev : 0;
        if (!buf || (buf->size == sizeof(buf->data))) {
            buf = (growbuffer *) malloc(sizeof(growbuffer));
            if (!buf) {
                return 0;
            }
			memset_s(buf, sizeof(growbuffer), 0, sizeof(growbuffer));
            buf->size = 0;
            buf->start = 0;
            if (*gb && (*gb)->prev) {
                buf->prev = (*gb)->prev;
                buf->next = *gb;
                (*gb)->prev->next = buf;
                (*gb)->prev = buf;
            }
            else {
                buf->prev = buf->next = buf;
                *gb = buf;
            }
        }

        int toCopy = (sizeof(buf->data) - buf->size);
        if (toCopy > dataLen) {
            toCopy = dataLen;
        }

        memcpy_s(&(buf->data[buf->size]), sizeof(buf->data)-buf->size, data, toCopy);
        
        buf->size += toCopy, data += toCopy, dataLen -= toCopy;
    }

    return 1;
}


static void growbuffer_read(growbuffer **gb, int amt, int *amtReturn, 
                            char *buffer)
{
    *amtReturn = 0;

    growbuffer *buf = *gb;

    if (!buf) {
        return;
    }

    *amtReturn = (buf->size > amt) ? amt : buf->size;

    memcpy_s(buffer, strlen(buffer), &(buf->data[buf->start]), *amtReturn);
    
    buf->start += *amtReturn, buf->size -= *amtReturn;

    if (buf->size == 0) {
        if (buf->next == buf) {
            *gb = 0;
        }
        else {
            *gb = buf->next;
            buf->prev->next = buf->next;
            buf->next->prev = buf->prev;
        }
        free(buf);
    }
}


static void growbuffer_destroy(growbuffer *gb)
{
    growbuffer *start = gb;

    while (gb) {
        growbuffer *next = gb->next;
        free(gb);
        gb = (next == start) ? 0 : next;
    }
}


// Convenience utility for making the code look nicer.  Tests a string
// against a format; only the characters specified in the format are
// checked (i.e. if the string is longer than the format, the string still
// checks out ok).  Format characters are:
// d - is a digit
// anything else - is that character
// Returns nonzero the string checks out, zero if it does not.
static int checkString(const char *str, const char *format)
{
    while (*format) {
        if (*format == 'd') {
            if (!isdigit(*str)) {
                return 0;
            }
        }
        else if (*str != *format) {
            return 0;
        }
        str++, format++;
    }

    return 1;
}


static int64_t parseIso8601Time(const char *str)
{
    // Check to make sure that it has a valid format
    if (!checkString(str, "dddd-dd-ddTdd:dd:dd")) {
        return -1;
    }

#define nextnum() (((*str - '0') * 10) + (*(str + 1) - '0'))

    // Convert it
    struct tm stm;
    memset_s(&stm, sizeof(stm), 0, sizeof(stm));

    stm.tm_year = (nextnum() - 19) * 100;
    str += 2;
    stm.tm_year += nextnum();
    str += 3;

    stm.tm_mon = nextnum() - 1;
    str += 3;

    stm.tm_mday = nextnum();
    str += 3;

    stm.tm_hour = nextnum();
    str += 3;

    stm.tm_min = nextnum();
    str += 3;

    stm.tm_sec = nextnum();
    str += 2;

    stm.tm_isdst = -1;

    // This is hokey but it's the recommended way ...
    char *tz = getenv("TZ");
    snprintf_s(putenvBufG, sizeof(putenvBufG), _TRUNCATE, "TZ=UTC");
    putenv(putenvBufG);

    int64_t ret = mktime(&stm);

    snprintf_s(putenvBufG, sizeof(putenvBufG), _TRUNCATE, "TZ=%s", tz ? tz : "");
    putenv(putenvBufG);

    // Skip the millis

    if (*str == '.') {
        str++;
        while (isdigit(*str)) {
            str++;
        }
    }
    
    if (checkString(str, "-dd:dd") || checkString(str, "+dd:dd")) {
        int sign = (*str++ == '-') ? -1 : 1;
        int hours = nextnum();
        str += 3;
        int minutes = nextnum();
        ret += (-sign * (((hours * 60) + minutes) * 60));
    }
    // Else it should be Z to be a conformant time string, but we just assume
    // that it is rather than enforcing that

    return ret;
}


// Simple ACL format:  Lines of this format:
// Type - ignored
// Starting with a dash - ignored
// Email email_address permission
// UserID user_id (display_name) permission
// Group Authenticated AWS Users permission
// Group All Users  permission
// permission is one of READ, WRITE, READ_ACP, WRITE_ACP, FULL_CONTROL
static int convert_simple_acl(char *aclXml, char *ownerId,
                              char *ownerDisplayName,
                              int *aclGrantCountReturn,
                              S3AclGrant *aclGrants)
{
    *aclGrantCountReturn = 0;
    *ownerId = 0;
    *ownerDisplayName = 0;

#define SKIP_SPACE(require_more)                \
    do {                                        \
        while (isspace(*aclXml)) {              \
            aclXml++;                           \
        }                                       \
        if (require_more && !*aclXml) {         \
            return 0;                           \
        }                                       \
    } while (0)
    
#define COPY_STRING_MAXLEN(field, maxlen)               \
    do {                                                \
        SKIP_SPACE(1);                                  \
        int len = 0;                                    \
        while ((len < maxlen) && !isspace(*aclXml)) {   \
            field[len++] = *aclXml++;                   \
        }                                               \
        field[len] = 0;                                 \
    } while (0)

#define COPY_STRING(field)                              \
    COPY_STRING_MAXLEN(field, (int) (sizeof(field) - 1))

    while (1) {
        SKIP_SPACE(0);

        if (!*aclXml) {
            break;
        }
        
        // Skip Type lines and dash lines
        if (!strncmp(aclXml, "Type", sizeof("Type") - 1) ||
            (*aclXml == '-')) {
            while (*aclXml && ((*aclXml != '\n') && (*aclXml != '\r'))) {
                aclXml++;
            }
            continue;
        }
        
        if (!strncmp(aclXml, "OwnerID", sizeof("OwnerID") - 1)) {
            aclXml += sizeof("OwnerID") - 1;
            COPY_STRING_MAXLEN(ownerId, S3_MAX_GRANTEE_USER_ID_SIZE);
            SKIP_SPACE(1);
            COPY_STRING_MAXLEN(ownerDisplayName,
                               S3_MAX_GRANTEE_DISPLAY_NAME_SIZE);
            continue;
        }

        if (*aclGrantCountReturn == S3_MAX_ACL_GRANT_COUNT) {
            return 0;
        }

        S3AclGrant *grant = &(aclGrants[(*aclGrantCountReturn)++]);

        if (!strncmp(aclXml, "Email", sizeof("Email") - 1)) {
            grant->granteeType = S3GranteeTypeHuaweiCustomerByEmail;
            aclXml += sizeof("Email") - 1;
            COPY_STRING(grant->grantee.huaweiCustomerByEmail.emailAddress);
        }
        else if (!strncmp(aclXml, "UserID", sizeof("UserID") - 1)) {
            grant->granteeType = S3GranteeTypeCanonicalUser;
            aclXml += sizeof("UserID") - 1;
            COPY_STRING(grant->grantee.canonicalUser.id);
            SKIP_SPACE(1);
            // Now do display name
            COPY_STRING(grant->grantee.canonicalUser.displayName);
        }
        else if (!strncmp(aclXml, "Group", sizeof("Group") - 1)) {
            aclXml += sizeof("Group") - 1;
            SKIP_SPACE(1);
            if (!strncmp(aclXml, "Authenticated AWS Users",
                         sizeof("Authenticated AWS Users") - 1)) {
                grant->granteeType = S3GranteeTypeAllAwsUsers;
                aclXml += (sizeof("Authenticated AWS Users") - 1);
            }
            else if (!strncmp(aclXml, "All Users", sizeof("All Users") - 1)) {
                grant->granteeType = S3GranteeTypeAllUsers;
                aclXml += (sizeof("All Users") - 1);
            }
            else if (!strncmp(aclXml, "Log Delivery", 
                              sizeof("Log Delivery") - 1)) {
                grant->granteeType = S3GranteeTypeLogDelivery;
                aclXml += (sizeof("Log Delivery") - 1);
            }
            else {
                return 0;
            }
        }
        else {
            return 0;
        }

        SKIP_SPACE(1);
        
        if (!strncmp(aclXml, "READ_ACP", sizeof("READ_ACP") - 1)) {
            grant->permission = S3PermissionReadACP;
            aclXml += (sizeof("READ_ACP") - 1);
        }
        else if (!strncmp(aclXml, "READ", sizeof("READ") - 1)) {
            grant->permission = S3PermissionRead;
            aclXml += (sizeof("READ") - 1);
        }
        else if (!strncmp(aclXml, "WRITE_ACP", sizeof("WRITE_ACP") - 1)) {
            grant->permission = S3PermissionWriteACP;
            aclXml += (sizeof("WRITE_ACP") - 1);
        }
        else if (!strncmp(aclXml, "WRITE", sizeof("WRITE") - 1)) {
            grant->permission = S3PermissionWrite;
            aclXml += (sizeof("WRITE") - 1);
        }
        else if (!strncmp(aclXml, "FULL_CONTROL", 
                          sizeof("FULL_CONTROL") - 1)) {
            grant->permission = S3PermissionFullControl;
            aclXml += (sizeof("FULL_CONTROL") - 1);
        }
    }

    return 1;
}

static int should_retry()
{
    if (retriesG--) {
#if defined __GNUC__ || defined LINUX
        // Sleep before next retry; start out with a 1 second sleep
        static int retrySleepInterval = 1 * SLEEP_UNITS_PER_SECOND;
        sleep(retrySleepInterval);
        // Next sleep 1 second longer
        retrySleepInterval++;
#else
		// Sleep before next retry; start out with a 1 second sleep
		static int retrySleepInterval = 1 * SLEEP_UNITS_PER_SECOND_WIN;
		Sleep(retrySleepInterval);
		// Next sleep 1 second longer
		retrySleepInterval += SLEEP_UNITS_PER_SECOND_WIN;
#endif
        return 1;
    }

    return 0;
}
//lint -e121
static struct option longOptionsG[] =
{
    { "force",                no_argument,        0,  'f' }, //lint !e155
    { "vhost-style",          no_argument,        0,  'h' },
    { "unencrypted",          no_argument,        0,  'u' },
    { "show-properties",      no_argument,        0,  's' },
    { "retries",              required_argument,  0,  'r' },
    { 0,                      0,                  0,   0  }
};
//lint +e121

// response properties callback ----------------------------------------------

// This callback does the same thing for every request type: prints out the
// properties if the user has requested them to be so
static S3Status responsePropertiesCallback
    (const S3ResponseProperties *properties, void *callbackData)
{
    (void) callbackData;

    if (!showResponsePropertiesG) {
        return S3StatusOK;
    }

#define print_nonnull(name, field)                                 \
    do {                                                           \
        if (properties-> field) {                                  \
            printf("%s: %s\n", name, properties-> field);          \
        }                                                          \
    } while (0)
    
    print_nonnull("Content-Type", contentType);
    print_nonnull("Request-Id", requestId);
    print_nonnull("Request-Id-2", requestId2);
    if (properties->contentLength > 0) {
        printf("Content-Length: %lld\n", 
               (unsigned long long) properties->contentLength);
    }
    print_nonnull("Server", server);
    print_nonnull("ETag", eTag);
    print_nonnull("expiration", expiration);
    print_nonnull("websiteRedirectLocation", websiteRedirectLocation);
    print_nonnull("versionId", versionId);
    print_nonnull("Access-Control-Allow-Origin", allowOrigin);
    print_nonnull("Access-Control-Allow-Headers", allowHeaders);
    print_nonnull("Access-Control-Max-Age", maxAge);
    print_nonnull("Access-Control-Allow-Methods", allowMethods);
    print_nonnull("Access-Control-Expose-Headers", exposeHeaders);
    if (properties->lastModified > 0) {
		char timebuf[256] = {0};
        time_t t = (time_t) properties->lastModified;
        // gmtime is not thread-safe but we don't care here.
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
        printf("Last-Modified: %s\n", timebuf);
    }
    int i;
    for (i = 0; i < properties->metaDataCount; i++) {
        printf("x-amz-meta-%s: %s\n", properties->metaData[i].name,
               properties->metaData[i].value);
    }
    if (properties->usesServerSideEncryption) {
        printf("UsesServerSideEncryption: true\n");
    }

    return S3StatusOK;
}


// response complete callback ------------------------------------------------

// This callback does the same thing for every request type: saves the status
// and error stuff in global variables
static void responseCompleteCallback(S3Status status,
                                     const S3ErrorDetails *error, 
                                     void *callbackData)
{
    (void) callbackData;

    statusG = status;
    // Compose the error details message now, although we might not use it.
    // Can't just save a pointer to [error] since it's not guaranteed to last
    // beyond this callback
    int len = 0;
    if (error && error->message) {
        len += snprintf_s(&(errorDetailsG[len]), sizeof(errorDetailsG) - len, _TRUNCATE,
                        "  Message: %s\n", error->message);
    }
    if (error && error->resource) {
        len += snprintf_s(&(errorDetailsG[len]), sizeof(errorDetailsG) - len, _TRUNCATE,
                        "  Resource: %s\n", error->resource);
    }
    if (error && error->furtherDetails) {
        len += snprintf_s(&(errorDetailsG[len]), sizeof(errorDetailsG) - len, _TRUNCATE,
                        "  Further Details: %s\n", error->furtherDetails);
    }
    if (error && error->extraDetailsCount) {
        len += snprintf_s(&(errorDetailsG[len]), sizeof(errorDetailsG) - len, _TRUNCATE,
                        "%s", "  Extra Details:\n");
        int i;
        for (i = 0; i < error->extraDetailsCount; i++) {
            len += snprintf_s(&(errorDetailsG[len]), 
                            sizeof(errorDetailsG) - len,  _TRUNCATE, "    %s: %s\n", 
                            error->extraDetails[i].name,
                            error->extraDetails[i].value);
        }
    }
}


// list service --------------------------------------------------------------

typedef struct list_service_data
{
    int headerPrinted;
    int allDetails;
} list_service_data;


static void printListServiceHeader(int allDetails)
{
    printf("%-56s  %-20s", "                         Bucket",
           "      Created");
    if (allDetails) {
        printf("  %-64s  %-12s", 
               "                            Owner ID",
               "Display Name");
    }
    printf("\n");
    printf("--------------------------------------------------------  "
           "--------------------");
    if (allDetails) {
        printf("  -------------------------------------------------"
               "---------------  ------------");
    }
    printf("\n");
}


static S3Status listServiceCallback(const char *ownerId, 
                                    const char *ownerDisplayName,
                                    const char *bucketName,
                                    int64_t creationDate, void *callbackData)
{
    list_service_data *data = (list_service_data *) callbackData;

    if (!data->headerPrinted) {
        data->headerPrinted = 1;
        printListServiceHeader(data->allDetails);
    }

	char timebuf[256] = {0};
    if (creationDate >= 0) {
        time_t t = (time_t) creationDate;
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    }
    else {
        timebuf[0] = 0;
    }

    printf("%-56s  %-20s", bucketName, timebuf);
    if (data->allDetails) {
        printf("  %-64s  %-12s", ownerId ? ownerId : "", 
               ownerDisplayName ? ownerDisplayName : "");
    }
    printf("\n");

    return S3StatusOK;
}


static void list_service(int allDetails)
{
    list_service_data data;

    data.headerPrinted = 0;
    data.allDetails = allDetails;

    S3_init();

    S3ListServiceHandler listServiceHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &listServiceCallback
    };

    S3BucketContext bucketContext = 
	{
		0,
		0,
		protocolG,
		S3UriStyleVirtualHost,
		accessKeyIdG,
		secretAccessKeyG,
		pCAInfo
	};
	
    do {
        // ListBuckets(protocolG, accessKeyIdG, secretAccessKeyG, 0, 0, 
        //                &listServiceHandler, &data);
		ListBucketsCA(&bucketContext, 0, 
                        &listServiceHandler, &data);
		
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG == S3StatusOK) {
        if (!data.headerPrinted) {
            printListServiceHeader(allDetails);
        }
    }
    else {
        printError();
    }

    S3_deinitialize();
}


// test bucket ---------------------------------------------------------------

static void test_bucket(int argc, char **argv, int optindex)
{
    // test bucket
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];

    if (optindex != argc) {
        fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
        usageExit(stderr);
    }

    S3_init();
	
	S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

	char locationConstraint[64] = {0};
    do {
        GetBucketLocationCA(&bucketContext, sizeof(locationConstraint),
                       locationConstraint, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

	if (statusG != S3StatusOK) {
		printError();
	}else{
		const char *result = locationConstraint[0] ? locationConstraint : "USA";
		if (NULL != result)
		{
		printf("%-56s  %-20s\n", "                         Bucket",
			           "       Status");
			    printf("--------------------------------------------------------  "
			           "--------------------\n");
			    printf("%-56s  %-20s\n", bucketName, result);
		}
	}

    S3_deinitialize();
}


// create bucket -------------------------------------------------------------

static void create_bucket(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];

    if (!forceG && (S3_validate_bucket_name
                    (bucketName, S3UriStyleVirtualHost) != S3StatusOK)) {
        fprintf(stderr, "\nWARNING: Bucket name is not valid for "
                "virtual-host style URI access.\n");
        fprintf(stderr, "Bucket not created.  Use -f option to force the "
                "bucket to be created despite\n");
        fprintf(stderr, "this warning.\n\n");
        exit(-1);
    }

    const char *locationConstraint = 0;
	const char *storagepolicy = 0;
    S3CannedAcl cannedAcl = S3CannedAclPrivate;
    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, LOCATION_PREFIX, LOCATION_PREFIX_LEN)) {
            locationConstraint = &(param[LOCATION_PREFIX_LEN]);
        }
        else if (!strncmp(param, CANNED_ACL_PREFIX, CANNED_ACL_PREFIX_LEN)) {
            char *val = &(param[CANNED_ACL_PREFIX_LEN]);
            if (!strcmp(val, "private")) {
                cannedAcl = S3CannedAclPrivate;
            }
            else if (!strcmp(val, "public-read")) {
                cannedAcl = S3CannedAclPublicRead;
            }
            else if (!strcmp(val, "public-read-write")) {
                cannedAcl = S3CannedAclPublicReadWrite;
            }
            else if (!strcmp(val, "authenticated-read")) {
                cannedAcl = S3CannedAclAuthenticatedRead;
            }
            else {
                fprintf(stderr, "\nERROR: Unknown canned ACL: %s\n", val);
                usageExit(stderr);
            }
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    S3_init();
	
	S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    do {
        CreateBucketCA(&bucketContext, cannedAcl,storagepolicy, locationConstraint, 0,
                         &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG == S3StatusOK) {
        printf("Bucket successfully created.\n");
    }
    else {
        printError();
    }
    
    S3_deinitialize();
}


// delete bucket -------------------------------------------------------------

static void delete_bucket(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];

    if (optindex != argc) {
        fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
        usageExit(stderr);
    }

    S3_init();
	
	S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    do {
        DeleteBucketCA(&bucketContext, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }

    S3_deinitialize();
}


// list bucket ---------------------------------------------------------------

typedef struct list_bucket_callback_data
{
    int isTruncated;
    char nextMarker[1024];
    int keyCount;
    int allDetails;
} list_bucket_callback_data;


static void printListBucketHeader(int allDetails)
{
    printf("%-50s  %-20s  %-5s", 
           "   Key", 
           "   Last Modified", "Size");
    if (allDetails) {
        printf("  %-34s  %-64s  %-12s", 
               "   ETag", 
               "   Owner ID",
               "Display Name");
    }
    printf("\n");
    printf("--------------------------------------------------  "
           "--------------------  -----");
    if (allDetails) {
        printf("  ----------------------------------  "
               "-------------------------------------------------"
               "---------------  ------------");
    }
    printf("\n");
}


static S3Status listBucketCallback(int isTruncated, const char *nextMarker,
                                   int contentsCount, 
                                   const S3ListBucketContent *contents,
                                   int commonPrefixesCount,
                                   const char **commonPrefixes,
                                   void *callbackData)
{
    list_bucket_callback_data *data = 
        (list_bucket_callback_data *) callbackData;

    data->isTruncated = isTruncated;
    // This is tricky.  S3 doesn't return the NextMarker if there is no
    // delimiter.  Why, I don't know, since it's still useful for paging
    // through results.  We want NextMarker to be the last content in the
    // list, so set it to that if necessary.
    if ((!nextMarker || !nextMarker[0]) && contentsCount) {
        nextMarker = contents[contentsCount - 1].key;
    }
    if (nextMarker) {
        snprintf_s(data->nextMarker, sizeof(data->nextMarker), _TRUNCATE, "%s", 
                 nextMarker);
    }
    else {
        data->nextMarker[0] = 0;
    }
    
    if (contentsCount && !data->keyCount) {
        printListBucketHeader(data->allDetails);
    }

    int i;
    for (i = 0; i < contentsCount; i++) {
        const S3ListBucketContent *content = &(contents[i]);
		char timebuf[256] = {0};
        if (0) {
            time_t t = (time_t) content->lastModified;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ",
                     gmtime(&t));
            printf("\nKey: %s\n", content->key);
            printf("Last Modified: %s\n", timebuf);
            printf("ETag: %s\n", content->eTag);
            printf("Size: %llu\n", (unsigned long long) content->size);
            if (content->ownerId) {
                printf("Owner ID: %s\n", content->ownerId);
            }
            if (content->ownerDisplayName) {
                printf("Owner Display Name: %s\n", content->ownerDisplayName);
            }
        }
        else {
            time_t t = (time_t) content->lastModified;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", 
                     gmtime(&t));
			char sizebuf[16] = {0};
            if (content->size < 100000) {
                sprintf_s(sizebuf, sizeof(sizebuf), "%5llu", (unsigned long long) content->size);
            }
            else if (content->size < (1024 * 1024)) {
                sprintf_s(sizebuf, sizeof(sizebuf),"%4lluK", 
                        ((unsigned long long) content->size) / 1024ULL);
            }
            else if (content->size < (10 * 1024 * 1024)) {
                float f = (float)content->size;
                f /= (1024 * 1024);
                sprintf_s(sizebuf, sizeof(sizebuf), "%1.2fM", f);
            }
            else if (content->size < (1024 * 1024 * 1024)) {
                sprintf_s(sizebuf, sizeof(sizebuf), "%4lluM", 
                        ((unsigned long long) content->size) / 
                        (1024ULL * 1024ULL));
            }
            else {
                float f = (float)(content->size / 1024);
                f /= (1024 * 1024);
                sprintf_s(sizebuf, sizeof(sizebuf), "%1.2fG", f);
            }
            printf("%-50s  %s  %s", content->key, timebuf, sizebuf);
            if (data->allDetails) {
                printf("  %-34s  %-64s  %-12s",
                       content->eTag, 
                       content->ownerId ? content->ownerId : "",
                       content->ownerDisplayName ? 
                       content->ownerDisplayName : "");
            }
            printf("\n");
        }
    }

    data->keyCount += contentsCount;

    for (i = 0; i < commonPrefixesCount; i++) {
        printf("\nCommon Prefix: %s\n", commonPrefixes[i]);
    }

    return S3StatusOK;
}


static void list_bucket(const char *bucketName, const char *prefix,
                        const char *marker, const char *delimiter,
                        int maxkeys, int allDetails)
{
    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ListBucketHandler listBucketHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &listBucketCallback
    };

    list_bucket_callback_data data;
	memset_s(&data, sizeof(list_bucket_callback_data), 0, sizeof(list_bucket_callback_data));

    snprintf_s(data.nextMarker, sizeof(data.nextMarker), _TRUNCATE, "%s", marker);
    data.keyCount = 0;
    data.allDetails = allDetails;

    do {
        data.isTruncated = 0;
        do {
            ListObjects(&bucketContext, prefix, marker,
                           delimiter, maxkeys, 0, &listBucketHandler, &data);
        } while (S3_status_is_retryable(statusG) && should_retry());
        if (statusG != S3StatusOK) {
            break;
        }
    } while (data.isTruncated && (!maxkeys || (data.keyCount < maxkeys)));

    if (statusG == S3StatusOK) {
        if (!data.keyCount) {
            printListBucketHeader(allDetails);
        }
    }
    else {
        printError();
    }

    S3_deinitialize();
}


static void list(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        list_service(0);
        return;
    }

    const char *bucketName = 0;

    const char *prefix = 0, *marker = 0, *delimiter = 0;
    int maxkeys = 0, allDetails = 0;
    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, PREFIX_PREFIX, PREFIX_PREFIX_LEN)) {
            prefix = &(param[PREFIX_PREFIX_LEN]);
        }
        else if (!strncmp(param, MARKER_PREFIX, MARKER_PREFIX_LEN)) {
            marker = &(param[MARKER_PREFIX_LEN]);
        }
        else if (!strncmp(param, DELIMITER_PREFIX, DELIMITER_PREFIX_LEN)) {
            delimiter = &(param[DELIMITER_PREFIX_LEN]);
        }
        else if (!strncmp(param, MAXKEYS_PREFIX, MAXKEYS_PREFIX_LEN)) {
            maxkeys = (int)convertInt(&(param[MAXKEYS_PREFIX_LEN]), "maxkeys");
        }
        else if (!strncmp(param, ALL_DETAILS_PREFIX,
                          ALL_DETAILS_PREFIX_LEN)) {
            const char *ad = &(param[ALL_DETAILS_PREFIX_LEN]);
            if (!strcmp(ad, "true") || !strcmp(ad, "TRUE") || 
                !strcmp(ad, "yes") || !strcmp(ad, "YES") ||
                !strcmp(ad, "1")) {
                allDetails = 1;
            }
        }
        else if (!bucketName) {
            bucketName = param;
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    if (bucketName) {
        list_bucket(bucketName, prefix, marker, delimiter, maxkeys, 
                    allDetails);
    }
    else {
        list_service(allDetails);
    }
}

    

// delete object -------------------------------------------------------------


static S3Status DeleteObjectsDataCallback(int contentsCount, 
                                         S3DeleteObjects *delobjs,
                                         void *callbackData)
{
	(void)callbackData;
    int i;
    for (i = 0; i < contentsCount; i++) {
        const S3DeleteObjects*content = &(delobjs[i]);
		int iRet = atoi(content->code);
    	if(0 != iRet)
    	{
    	    printf("delete object result:\nobject key:%s\nerror code:%s\nerror message:%s\n", content->key, content->code, content->message);
    	}
    	else
    	{
    	    printf("delete object result:\nobject key:%s\nerror code:%s\n", content->key, content->code);
    	}			
	}

    

    return S3StatusOK;
}


static void delete_object(int argc, char **argv, int optindex)
{
    (void) argc;

    // Split bucket/key
    char *slash = argv[optindex];

    // We know there is a slash in there, put_object is only called if so
    while (*slash && (*slash != '/')) {
        slash++;
    }
    *slash++ = 0;

    const char* temp = slash;
	S3DelBucketInfo info[S3_MAX_DELETE_OBJECT_NUMBER];
    const char *keyArray[S3_MAX_DELETE_OBJECT_NUMBER] = {0};
    unsigned int uiCnt = 0;
    while(*slash)
    {
        while (*slash && (*slash != '/')) {
            slash++;
        }
       if('\0'==*slash)
       {
	    keyArray[uiCnt]=temp;
		info[uiCnt].key=keyArray[uiCnt];
		info[uiCnt].versionId=0;
       } 
       else
       {
           *slash++ = 0;
           keyArray[uiCnt] = temp;
		   info[uiCnt].key=keyArray[uiCnt];
		   info[uiCnt].versionId=0;
           temp = slash;
       }
	uiCnt++;
    }   

    const char *bucketName = argv[optindex++];
    //const char *key = slash;

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    

    if(1 == uiCnt)
    {
        S3ResponseHandler responseHandler =
        { 
            0,
            &responseCompleteCallback
        };
        
        const char *key = keyArray[0];
		const char * versionId = 0;
        do {
#if defined __GNUC__ || defined LINUX
            DeleteObject(&bucketContext, key,versionId, 0, &responseHandler, 0);
#else
			deleteObject(&bucketContext, key,versionId, 0, &responseHandler, 0);
#endif
        } while (S3_status_is_retryable(statusG) && should_retry());

        if ((statusG != S3StatusOK) &&
            (statusG != S3StatusPreconditionFailed)) {
            printError();
        }
    }
    else
    {


        const char *cacheControl = 0, *contentType = 0, *md5 = 0;
        const char *contentDispositionFilename = 0, *contentEncoding = 0;        
        while (optindex < argc) {
            char *param = argv[optindex++];
            if (!strncmp(param, CACHE_CONTROL_PREFIX, 
                              CACHE_CONTROL_PREFIX_LEN)) {
                cacheControl = &(param[CACHE_CONTROL_PREFIX_LEN]);
            }
            else if (!strncmp(param, CONTENT_TYPE_PREFIX, 
                              CONTENT_TYPE_PREFIX_LEN)) {
                contentType = &(param[CONTENT_TYPE_PREFIX_LEN]);
            }
            else if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
                md5 = &(param[MD5_PREFIX_LEN]);
            }
            else if (!strncmp(param, CONTENT_DISPOSITION_FILENAME_PREFIX, 
                              CONTENT_DISPOSITION_FILENAME_PREFIX_LEN)) {
                contentDispositionFilename = 
                    &(param[CONTENT_DISPOSITION_FILENAME_PREFIX_LEN]);
            }
            else if (!strncmp(param, CONTENT_ENCODING_PREFIX, 
                              CONTENT_ENCODING_PREFIX_LEN)) {
                contentEncoding = &(param[CONTENT_ENCODING_PREFIX_LEN]);
            }
            else {
                fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
                usageExit(stderr);
            }        
        }

        S3PutProperties putProperties =
        {
            contentType,
            md5,
            cacheControl,
            contentDispositionFilename,
            contentEncoding,
            0,
            0,
            0,
            0,
            0,
            -1,
            S3CannedAclPrivate,
            0,
            0,
            0
        };

        S3DeleteObjectHandler responseHandler = {{ &responsePropertiesCallback, &responseCompleteCallback }, DeleteObjectsDataCallback};
        do {
            DeleteObjects(&bucketContext, info, uiCnt, 1, &putProperties, 0, &responseHandler, 0);
        } while (S3_status_is_retryable(statusG) && should_retry());

        if ((statusG != S3StatusOK) &&
            (statusG != S3StatusPreconditionFailed)) {
            printError();
        }
    }


    S3_deinitialize();
}


// put object ----------------------------------------------------------------

typedef struct put_object_callback_data
{
    FILE *infile;
    growbuffer *gb;
    uint64_t contentLength, originalContentLength;
    int noStatus;
} put_object_callback_data;


static int putObjectDataCallback(int bufferSize, char *buffer,
                                 void *callbackData)
{
    put_object_callback_data *data = 
        (put_object_callback_data *) callbackData;
    
    int ret = 0;

    if (data->contentLength) {
        int toRead = (int)((data->contentLength > (unsigned) bufferSize) ?
                      (unsigned) bufferSize : data->contentLength);
        if (data->gb) {
            growbuffer_read(&(data->gb), toRead, &ret, buffer);
        }
        else if (data->infile) {
            ret = fread(buffer, 1, toRead, data->infile);
        }
    }

    data->contentLength -= ret;

    if (data->contentLength && !data->noStatus) {
        // Avoid a weird bug in MingW, which won't print the second integer
        // value properly when it's in the same call, so print separately
        printf("%llu bytes remaining ", 
               (unsigned long long) data->contentLength);
        printf("(%d%% complete) ...\n",
               (int) (((data->originalContentLength - 
                        data->contentLength) * 100) /
                      data->originalContentLength));
    }

    return ret;
}


static void put_object(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    char *slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *bucketName = argv[optindex++];
    const char *key = slash;

	char use_kms = 0;
	char use_ssec = 0;
	char *kmsServerSideEncryption = 0;
	char *kmsKeyId = 0;
	char *kmsEncryptionContext = 0;
	char *ssecCustomerAlgorithm = 0;
	char *ssecCustomerKey = 0;
	char *ssecCustomerKeyMD5 = 0;
	char *des_ssecCustomerAlgorithm = 0;
	char *des_ssecCustomerKey = 0;
	char *des_ssecCustomerKeyMD5 = 0;

    const char *filename = 0;
    uint64_t contentLength = 0;
    const char *cacheControl = 0, *contentType = 0, *md5 = 0;
    const char *contentDispositionFilename = 0, *contentEncoding = 0;
    int64_t expires = -1;
    S3CannedAcl cannedAcl = S3CannedAclPrivate;
    int metaPropertiesCount = 0;
	S3NameValue metaProperties[S3_MAX_METADATA_COUNT];
    char useServerSideEncryption = 0;
    int noStatus = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_LENGTH_PREFIX, 
                          CONTENT_LENGTH_PREFIX_LEN)) {
            contentLength = convertInt(&(param[CONTENT_LENGTH_PREFIX_LEN]),
                                       "contentLength");
            if (contentLength > (5LL * 1024 * 1024 * 1024)) {
                fprintf(stderr, "\nERROR: contentLength must be no greater "
                        "than 5 GB\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, CACHE_CONTROL_PREFIX, 
                          CACHE_CONTROL_PREFIX_LEN)) {
            cacheControl = &(param[CACHE_CONTROL_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_TYPE_PREFIX, 
                          CONTENT_TYPE_PREFIX_LEN)) {
            contentType = &(param[CONTENT_TYPE_PREFIX_LEN]);
        }
        else if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
            md5 = &(param[MD5_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_DISPOSITION_FILENAME_PREFIX, 
                          CONTENT_DISPOSITION_FILENAME_PREFIX_LEN)) {
            contentDispositionFilename = 
                &(param[CONTENT_DISPOSITION_FILENAME_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_ENCODING_PREFIX, 
                          CONTENT_ENCODING_PREFIX_LEN)) {
            contentEncoding = &(param[CONTENT_ENCODING_PREFIX_LEN]);
        }
        else if (!strncmp(param, EXPIRES_PREFIX, EXPIRES_PREFIX_LEN)) {
            expires = parseIso8601Time(&(param[EXPIRES_PREFIX_LEN]));
            if (expires < 0) {
                fprintf(stderr, "\nERROR: Invalid expires time "
                        "value; ISO 8601 time format required\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, X_AMZ_META_PREFIX, X_AMZ_META_PREFIX_LEN)) {
            if (metaPropertiesCount == S3_MAX_METADATA_COUNT) {
                fprintf(stderr, "\nERROR: Too many x-amz-meta- properties, "
                        "limit %lu: %s\n", 
                        (unsigned long) S3_MAX_METADATA_COUNT, param);
                usageExit(stderr);
            }
            char *name = &(param[X_AMZ_META_PREFIX_LEN]);
            char *value = name;
            while (*value && (*value != '=')) {
                value++;
            }
            if (!*value || !*(value + 1)) {
                fprintf(stderr, "\nERROR: Invalid parameter: %s\n", param);
                usageExit(stderr);
            }
            *value++ = 0;
            metaProperties[metaPropertiesCount].name = name;
            metaProperties[metaPropertiesCount++].value = value;
        }
        else if (!strncmp(param, USE_SERVER_SIDE_ENCRYPTION_PREFIX,
                          USE_SERVER_SIDE_ENCRYPTION_PREFIX_LEN)) {
            const char *val = &(param[USE_SERVER_SIDE_ENCRYPTION_PREFIX_LEN]);
            if (!strcmp(val, "true") || !strcmp(val, "TRUE") || 
                !strcmp(val, "yes") || !strcmp(val, "YES") ||
                !strcmp(val, "1")) {
                useServerSideEncryption = 1;
            }
            else {
                useServerSideEncryption = 0;
            }
        }
        else if (!strncmp(param, CANNED_ACL_PREFIX, CANNED_ACL_PREFIX_LEN)) {
            char *val = &(param[CANNED_ACL_PREFIX_LEN]);
            if (!strcmp(val, "private")) {
                cannedAcl = S3CannedAclPrivate;
            }
            else if (!strcmp(val, "public-read")) {
                cannedAcl = S3CannedAclPublicRead;
            }
            else if (!strcmp(val, "public-read-write")) {
                cannedAcl = S3CannedAclPublicReadWrite;
            }
            else if (!strcmp(val, "authenticated-read")) {
                cannedAcl = S3CannedAclAuthenticatedRead;
            }
            else {
                fprintf(stderr, "\nERROR: Unknown canned ACL: %s\n", val);
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, NO_STATUS_PREFIX, NO_STATUS_PREFIX_LEN)) {
            const char *ns = &(param[NO_STATUS_PREFIX_LEN]);
            if (!strcmp(ns, "true") || !strcmp(ns, "TRUE") || 
                !strcmp(ns, "yes") || !strcmp(ns, "YES") ||
                !strcmp(ns, "1")) {
                noStatus = 1;
            }
        }
		else if (!strncmp(param, USEKMS_PREFIX, USEKMS_PREFIX_LEN)) {
			const char *ns = &(param[USEKMS_PREFIX_LEN]);
			if (!strcmp(ns, "true") || !strcmp(ns, "TRUE") || 
				!strcmp(ns, "yes") || !strcmp(ns, "YES") ||
				!strcmp(ns, "1")) {
					use_kms = 1;
			}
		}
		else if (!strncmp(param, USESSEC_PREFIX, USESSEC_PREFIX_LEN)) {
			const char *ns = &(param[USESSEC_PREFIX_LEN]);
			if (!strcmp(ns, "true") || !strcmp(ns, "TRUE") || 
				!strcmp(ns, "yes") || !strcmp(ns, "YES") ||
				!strcmp(ns, "1")) {
					use_ssec = 1;
			}
		}
		else if (!strncmp(param, KMSSERVERSIDEENCRYPTION_PREFIX, KMSSERVERSIDEENCRYPTION_PREFIX_LEN)) {
			kmsServerSideEncryption = &(param[KMSSERVERSIDEENCRYPTION_PREFIX_LEN]);
		}
		else if (!strncmp(param, KMSKEYID_PREFIX, KMSKEYID_PREFIX_LEN)) {
			kmsKeyId = &(param[KMSKEYID_PREFIX_LEN]);
		}
		else if (!strncmp(param, KMSENCRYPTIONCONTEXT_PREFIX, KMSENCRYPTIONCONTEXT_PREFIX_LEN)) {
			kmsEncryptionContext = &(param[KMSENCRYPTIONCONTEXT_PREFIX_LEN]);
		}
		else if (!strncmp(param, SSECCUSTOMERALGORITHM_PREFIX, SSECCUSTOMERALGORITHM_PREFIX_LEN)) {
			ssecCustomerAlgorithm = &(param[SSECCUSTOMERALGORITHM_PREFIX_LEN]);
		}
		else if (!strncmp(param, SSECCUSTOMERKEY_PREFIX, SSECCUSTOMERKEY_PREFIX_LEN)) {
			ssecCustomerKey = &(param[SSECCUSTOMERKEY_PREFIX_LEN]);
		}
		else if (!strncmp(param, SSECCUSTOMERKEYMD5_PREFIX, SSECCUSTOMERKEYMD5_PREFIX_LEN)) {
			ssecCustomerKeyMD5 = &(param[SSECCUSTOMERKEYMD5_PREFIX_LEN]);
		}
		else if (!strncmp(param, DESSSECCUSTOMERALGORITHM_PREFIX, DESSSECCUSTOMERALGORITHM_PREFIX_LEN)) {
			ssecCustomerAlgorithm = &(param[DESSSECCUSTOMERALGORITHM_PREFIX_LEN]);
		}
		else if (!strncmp(param, DESSSECCUSTOMERKEY_PREFIX, DESSSECCUSTOMERKEY_PREFIX_LEN)) {
			ssecCustomerKey = &(param[DESSSECCUSTOMERKEY_PREFIX_LEN]);
		}
		else if (!strncmp(param, DESSSECCUSTOMERKEYMD5_PREFIX, DESSSECCUSTOMERKEYMD5_PREFIX_LEN)) {
			ssecCustomerKeyMD5 = &(param[DESSSECCUSTOMERKEYMD5_PREFIX_LEN]);
		}
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    put_object_callback_data data;
	memset_s(&data, sizeof(put_object_callback_data), 0, sizeof(put_object_callback_data));
	//lint -e115
    data.infile = 0;
    data.gb = 0;
    data.noStatus = noStatus;
    if (filename) {
        if (!contentLength) {
            struct stat statbuf;
            // Stat the file to get its length
            if (stat(filename, &statbuf) == -1) {
                fprintf(stderr, "\nERROR: Failed to stat file %s: ",
                        filename);
                perror(0);
                exit(-1);
            }
            contentLength = statbuf.st_size;
        }
        // Open the file
        if (!(data.infile = fopen(filename, "rb" FOPEN_EXTRA_FLAGS))) {
            fprintf(stderr, "\nERROR: Failed to open input file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }//lint +e115
    else {
        // Read from stdin.  If contentLength is not provided, we have
        // to read it all in to get contentLength.
        if (!contentLength) {
            // Read all if stdin to get the data
			char buffer[RECIVE_STREAM_LENGTH] = {0};
            while (1) {
#if defined __GNUC__ || defined LINUX
                int amtRead = fread(buffer, 1, sizeof(buffer), stdin);
#else
				char tempBuf[RECIVE_STREAM_LENGTH] = {0};
				scanf_s("%255s", tempBuf, RECIVE_STREAM_LENGTH);
				tempBuf[RECIVE_STREAM_LENGTH - 1] = '\0';
				strncat_s(buffer, sizeof(buffer), tempBuf, RECIVE_STREAM_LENGTH - strlen(buffer) -1);//Use safe function by jwx329074 2016.11.18
				buffer[RECIVE_STREAM_LENGTH - 1] = '\0';
				int amtRead = strlen(buffer);
				contentLength = amtRead;
#endif								
                if (amtRead == 0) {
                    break;
                }
                if (!growbuffer_append(&(data.gb), buffer, amtRead)) {
                    fprintf(stderr, "\nERROR: Out of memory while reading "
                            "stdin\n");
                    exit(-1);
                }
#if defined __GNUC__ || defined LINUX
                contentLength += amtRead;
                if (amtRead <= (int) (sizeof(buffer))) {				
                    break;
				}
#else
				if (amtRead < (int) (sizeof(buffer)-1)) {				
					continue;								
                }
				else
				{
					break;
				}
#endif		
			}
        }
        else {
            data.infile = stdin;
        }
    }

    data.contentLength = data.originalContentLength = contentLength;
	const char * websiteredirectlocation = 0;
    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3PutProperties putProperties =
    {
        contentType,
        md5,
        cacheControl,
        contentDispositionFilename,
        contentEncoding,
        0,
        websiteredirectlocation,
        0,
        0,
        0,
        expires,
        cannedAcl,
        metaPropertiesCount,
        metaProperties,
        useServerSideEncryption
    };
	ServerSideEncryptionParams serverSideEncryptionParams = {
		use_kms,
		use_ssec,
		kmsServerSideEncryption,
		kmsKeyId,
		kmsEncryptionContext,
		ssecCustomerAlgorithm,
		ssecCustomerKey,
		ssecCustomerKeyMD5,
		des_ssecCustomerAlgorithm,
		des_ssecCustomerKey,
		des_ssecCustomerKeyMD5
	};
    S3PutObjectHandler putObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &putObjectDataCallback
    };

    do {
        PutObjectWithServerSideEncryption(&bucketContext, key, contentLength, &putProperties, &serverSideEncryptionParams, 0,
                      &putObjectHandler, &data);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (data.infile) {
        fclose(data.infile);
    }
    else if (data.gb) {
        growbuffer_destroy(data.gb);
    }

    if (statusG != S3StatusOK) {
        printError();
    }
    else if (data.contentLength) {
        fprintf(stderr, "\nERROR: Failed to read remaining %llu bytes from "
                "input\n", (unsigned long long) data.contentLength);
    }

    S3_deinitialize();
}


// copy object ---------------------------------------------------------------

static void copy_object(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: source bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    char *slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid source bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *sourceBucketName = argv[optindex++];
    const char *sourceKey = slash;

    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: "
                "destination bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid destination bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *destinationBucketName = argv[optindex++];
    const char *destinationKey = slash;

    const char *cacheControl = 0, *contentType = 0;
    const char *contentDispositionFilename = 0, *contentEncoding = 0;
    int64_t expires = -1;
    S3CannedAcl cannedAcl = S3CannedAclPrivate;
    int metaPropertiesCount = 0;
	S3NameValue metaProperties[S3_MAX_METADATA_COUNT];
    char useServerSideEncryption = 0;
    int anyPropertiesSet = 0;

	 int64_t ifModifiedSince = -1, ifNotModifiedSince = -1;
	 const char *ifMatch = 0, *ifNotMatch = 0;
	
	while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, CACHE_CONTROL_PREFIX, 
                          CACHE_CONTROL_PREFIX_LEN)) {
            cacheControl = &(param[CACHE_CONTROL_PREFIX_LEN]);
            anyPropertiesSet = 1;
        }
        else if (!strncmp(param, CONTENT_TYPE_PREFIX, 
                          CONTENT_TYPE_PREFIX_LEN)) {
            contentType = &(param[CONTENT_TYPE_PREFIX_LEN]);
            anyPropertiesSet = 1;
        }
        else if (!strncmp(param, CONTENT_DISPOSITION_FILENAME_PREFIX, 
                          CONTENT_DISPOSITION_FILENAME_PREFIX_LEN)) {
            contentDispositionFilename = 
                &(param[CONTENT_DISPOSITION_FILENAME_PREFIX_LEN]);
            anyPropertiesSet = 1;
        }
        else if (!strncmp(param, CONTENT_ENCODING_PREFIX, 
                          CONTENT_ENCODING_PREFIX_LEN)) {
            contentEncoding = &(param[CONTENT_ENCODING_PREFIX_LEN]);
            anyPropertiesSet = 1;
        }
        else if (!strncmp(param, EXPIRES_PREFIX, EXPIRES_PREFIX_LEN)) {
            expires = parseIso8601Time(&(param[EXPIRES_PREFIX_LEN]));
            if (expires < 0) {
                fprintf(stderr, "\nERROR: Invalid expires time "
                        "value; ISO 8601 time format required\n");
                usageExit(stderr);
            }
            anyPropertiesSet = 1;
        }
        else if (!strncmp(param, X_AMZ_META_PREFIX, X_AMZ_META_PREFIX_LEN)) {
            if (metaPropertiesCount == S3_MAX_METADATA_COUNT) {
                fprintf(stderr, "\nERROR: Too many x-amz-meta- properties, "
                        "limit %lu: %s\n", 
                        (unsigned long) S3_MAX_METADATA_COUNT, param);
                usageExit(stderr);
            }
            char *name = &(param[X_AMZ_META_PREFIX_LEN]);
            char *value = name;
            while (*value && (*value != '=')) {
                value++;
            }
            if (!*value || !*(value + 1)) {
                fprintf(stderr, "\nERROR: Invalid parameter: %s\n", param);
                usageExit(stderr);
            }
            *value++ = 0;
            metaProperties[metaPropertiesCount].name = name;
            metaProperties[metaPropertiesCount++].value = value;
            anyPropertiesSet = 1;
        }
        else if (!strncmp(param, USE_SERVER_SIDE_ENCRYPTION_PREFIX,
                          USE_SERVER_SIDE_ENCRYPTION_PREFIX_LEN)) {
            if (!strcmp(param, "true") || !strcmp(param, "TRUE") || 
                !strcmp(param, "yes") || !strcmp(param, "YES") ||
                !strcmp(param, "1")) {
                useServerSideEncryption = 1;
                anyPropertiesSet = 1;
            }
            else {
                useServerSideEncryption = 0;
            }
        }
        else if (!strncmp(param, CANNED_ACL_PREFIX, CANNED_ACL_PREFIX_LEN)) {
            char *val = &(param[CANNED_ACL_PREFIX_LEN]);
            if (!strcmp(val, "private")) {
                cannedAcl = S3CannedAclPrivate;
            }
            else if (!strcmp(val, "public-read")) {
                cannedAcl = S3CannedAclPublicRead;
            }
            else if (!strcmp(val, "public-read-write")) {
                cannedAcl = S3CannedAclPublicReadWrite;
            }
            else if (!strcmp(val, "authenticated-read")) {
                cannedAcl = S3CannedAclAuthenticatedRead;
            }
            else {
                fprintf(stderr, "\nERROR: Unknown canned ACL: %s\n", val);
                usageExit(stderr);
            }
            anyPropertiesSet = 1;
        }
		 else if (!strncmp(param, IF_MODIFIED_SINCE_PREFIX, 
					  IF_MODIFIED_SINCE_PREFIX_LEN)) {
			 // Parse ifModifiedSince
			 ifModifiedSince = parseIso8601Time
				 (&(param[IF_MODIFIED_SINCE_PREFIX_LEN]));
			 if (ifModifiedSince < 0) {
				 fprintf(stderr, "\nERROR: Invalid ifModifiedSince time "
						 "value; ISO 8601 time format required\n");
				 usageExit(stderr);
			 }
			 anyPropertiesSet = 1;
		 }
		 else if (!strncmp(param, IF_NOT_MODIFIED_SINCE_PREFIX, 
						   IF_NOT_MODIFIED_SINCE_PREFIX_LEN)) {
			 // Parse ifModifiedSince
			 ifNotModifiedSince = parseIso8601Time
				 (&(param[IF_NOT_MODIFIED_SINCE_PREFIX_LEN]));
			 if (ifNotModifiedSince < 0) {
				 fprintf(stderr, "\nERROR: Invalid ifNotModifiedSince time "
						 "value; ISO 8601 time format required\n");
				 usageExit(stderr);
			 }
			 anyPropertiesSet = 1;
		 }
		 else if (!strncmp(param, IF_MATCH_PREFIX, IF_MATCH_PREFIX_LEN)) {
			 ifMatch = &(param[IF_MATCH_PREFIX_LEN]);
			 anyPropertiesSet = 1;
		 }
		 else if (!strncmp(param, IF_NOT_MATCH_PREFIX,
						   IF_NOT_MATCH_PREFIX_LEN)) {
			 ifNotMatch = &(param[IF_NOT_MATCH_PREFIX_LEN]);
			 anyPropertiesSet = 1;
		 }
		 else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        sourceBucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	const char*webrl = 0;
    S3GetConditions getConditions =
    {
        ifModifiedSince,
        ifNotModifiedSince,
        ifMatch,
        ifNotMatch
    };
    S3PutProperties putProperties =
    {
        contentType,
        0,
        cacheControl,
        contentDispositionFilename,
        contentEncoding,
        0,
        webrl,
        &getConditions,
        0,
        0,
        expires,
        cannedAcl,
        metaPropertiesCount,
        metaProperties,
        useServerSideEncryption
    };

    S3ResponseHandler responseHandler =
    { 
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    int64_t lastModified;
	const char* versionId = 0;
	char eTag[256] = {0};

	unsigned int nIsCopy = 0;

    do {
        CopyObject(&bucketContext, sourceKey, destinationBucketName,
                       destinationKey,versionId, nIsCopy, anyPropertiesSet ? &putProperties : 0,
                       &lastModified, sizeof(eTag), eTag, 0,
                       &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG == S3StatusOK) {
        if (lastModified >= 0) {
			char timebuf[256] = {0};
            time_t t = (time_t) lastModified;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ",
                     gmtime(&t));
            printf("Last-Modified: %s\n", timebuf);
        }
        if (eTag[0]) {
            printf("ETag: %s\n", eTag);
        }
    }
    else {
        printError();
    }

    S3_deinitialize();
}


// get object ----------------------------------------------------------------

static S3Status getObjectDataCallback(int bufferSize, const char *buffer,
                                      void *callbackData)
{
    FILE *outfile = (FILE *) callbackData;

    size_t wrote = fwrite(buffer, 1, bufferSize, outfile);
    
    return ((wrote < (size_t) bufferSize) ? 
            S3StatusAbortedByCallback : S3StatusOK);
}


static void get_object(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    char *slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *bucketName = argv[optindex++];
    const char *key = slash;

    const char *filename = 0;
    int64_t ifModifiedSince = -1, ifNotModifiedSince = -1;
    const char *ifMatch = 0, *ifNotMatch = 0;
    uint64_t startByte = 0, byteCount = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else if (!strncmp(param, IF_MODIFIED_SINCE_PREFIX, 
                     IF_MODIFIED_SINCE_PREFIX_LEN)) {
            // Parse ifModifiedSince
            ifModifiedSince = parseIso8601Time
                (&(param[IF_MODIFIED_SINCE_PREFIX_LEN]));
            if (ifModifiedSince < 0) {
                fprintf(stderr, "\nERROR: Invalid ifModifiedSince time "
                        "value; ISO 8601 time format required\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, IF_NOT_MODIFIED_SINCE_PREFIX, 
                          IF_NOT_MODIFIED_SINCE_PREFIX_LEN)) {
            // Parse ifModifiedSince
            ifNotModifiedSince = parseIso8601Time
                (&(param[IF_NOT_MODIFIED_SINCE_PREFIX_LEN]));
            if (ifNotModifiedSince < 0) {
                fprintf(stderr, "\nERROR: Invalid ifNotModifiedSince time "
                        "value; ISO 8601 time format required\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, IF_MATCH_PREFIX, IF_MATCH_PREFIX_LEN)) {
            ifMatch = &(param[IF_MATCH_PREFIX_LEN]);
        }
        else if (!strncmp(param, IF_NOT_MATCH_PREFIX,
                          IF_NOT_MATCH_PREFIX_LEN)) {
            ifNotMatch = &(param[IF_NOT_MATCH_PREFIX_LEN]);
        }
        else if (!strncmp(param, START_BYTE_PREFIX, START_BYTE_PREFIX_LEN)) {
            startByte = convertInt
                (&(param[START_BYTE_PREFIX_LEN]), "startByte");
        }
        else if (!strncmp(param, BYTE_COUNT_PREFIX, BYTE_COUNT_PREFIX_LEN)) {
            byteCount = convertInt
                (&(param[BYTE_COUNT_PREFIX_LEN]), "byteCount");
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    FILE *outfile = 0;

    if (filename) {
        // Stat the file, and if it doesn't exist, open it in w mode
        struct stat buf;
        if (stat(filename, &buf) == -1) {
            outfile = fopen(filename, "w" FOPEN_EXTRA_FLAGS);
        }
        else {
            // Open in r+ so that we don't truncate the file, just in case
            // there is an error and we write no bytes, we leave the file
            // unmodified
            outfile = fopen(filename, "r+" FOPEN_EXTRA_FLAGS);
        }
        
        if (!outfile) {
            fprintf(stderr, "\nERROR: Failed to open output file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }
    else if (showResponsePropertiesG) {
        fprintf(stderr, "\nERROR: get -s requires a filename parameter\n");
        usageExit(stderr);
    }
    else {
        outfile = stdout;
    }

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3GetConditions getConditions =
    {
        ifModifiedSince,
        ifNotModifiedSince,
        ifMatch,
        ifNotMatch
    };

    S3GetObjectHandler getObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &getObjectDataCallback
    };

    do {
#if defined __GNUC__ || defined LINUX
        GetObject(&bucketContext, key, 0, &getConditions, startByte,
                      byteCount, 0, &getObjectHandler, outfile);
#else
		getObject(&bucketContext, key, 0, &getConditions, startByte,
			byteCount, 0, &getObjectHandler, outfile);
#endif
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }

    fclose(outfile);

    S3_deinitialize();
}


// head object ---------------------------------------------------------------

static void head_object(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket/key\n");
        usageExit(stderr);
    }
    
    // Head implies showing response properties
    showResponsePropertiesG = 1;

    // Split bucket/key
    char *slash = argv[optindex];
	const char *key = 0;
    while (*slash && (*slash != '/')) {
        slash++;
    }
	
	if (*slash) {
        *slash++ = 0;
        key = slash;
    }
    else {
        key = 0;
    }
	
//    if (!*slash || !*(slash + 1)) {
//        fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
//                argv[optindex]);
//        usageExit(stderr);
//    }
//    *slash++ = 0;

    const char *bucketName = argv[optindex++];
//    const char *key = slash;

    if (optindex != argc) {
        fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
        usageExit(stderr);
    }

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    { 
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    do {
        HeadBucket(&bucketContext,0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if ((statusG != S3StatusOK) &&
        (statusG != S3StatusPreconditionFailed)) {
        printError();
    }

    S3_deinitialize();
}


// generate query string ------------------------------------------------------

static void generate_query_string(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex];
    const char *key = 0;

    // Split bucket/key
    char *slash = argv[optindex++];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (*slash) {
        *slash++ = 0;
        key = slash;
    }
    else {
        key = 0;
    }

    int64_t expires = -1;

    const char *resource = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, EXPIRES_PREFIX, EXPIRES_PREFIX_LEN)) {
            expires = parseIso8601Time(&(param[EXPIRES_PREFIX_LEN]));
            if (expires < 0) {
                fprintf(stderr, "\nERROR: Invalid expires time "
                        "value; ISO 8601 time format required\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, RESOURCE_PREFIX, RESOURCE_PREFIX_LEN)) {
            resource = &(param[RESOURCE_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	char buffer[S3_MAX_AUTHENTICATED_QUERY_STRING_SIZE] = {0};

    S3Status status = S3_generate_authenticated_query_string
        (buffer, &bucketContext, key, expires, resource);
    
    if (status != S3StatusOK) {
        printf("Failed to generate authenticated query string: %s\n",
               S3_get_status_name(status));
    }
    else {
        printf("%s\n", buffer);
    }

    S3_deinitialize();
}


// get acl -------------------------------------------------------------------

void get_acl(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex];
    const char *key = 0;

    // Split bucket/key
    char *slash = argv[optindex++];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (*slash) {
        *slash++ = 0;
        key = slash;
    }
    else {
        key = 0;
    }

    const char *filename = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    FILE *outfile = 0;

    if (filename) {
        // Stat the file, and if it doesn't exist, open it in w mode
        struct stat buf;
        if (stat(filename, &buf) == -1) {
            outfile = fopen(filename, "w" FOPEN_EXTRA_FLAGS);
        }
        else {
            // Open in r+ so that we don't truncate the file, just in case
            // there is an error and we write no bytes, we leave the file
            // unmodified
            outfile = fopen(filename, "r+" FOPEN_EXTRA_FLAGS);
        }
        
        if (!outfile) {
            fprintf(stderr, "\nERROR: Failed to open output file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }
    else if (showResponsePropertiesG) {
        fprintf(stderr, "\nERROR: getacl -s requires a filename parameter\n");
        usageExit(stderr);
    }
    else {
        outfile = stdout;
    }

    int aclGrantCount;
    S3AclGrant aclGrants[S3_MAX_ACL_GRANT_COUNT];
	char ownerId[S3_MAX_GRANTEE_USER_ID_SIZE] = {0};
    char ownerDisplayName[S3_MAX_GRANTEE_DISPLAY_NAME_SIZE] = {0};

    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback,
        &responseCompleteCallback
    };
	
	const char * versionId = 0;
    do {
        GetObjectAcl(&bucketContext, key,versionId, ownerId, ownerDisplayName, 
                   &aclGrantCount, aclGrants, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG == S3StatusOK) {
        fprintf(outfile, "OwnerID %s %s\n", ownerId, ownerDisplayName);
        fprintf(outfile, "%-6s  %-90s  %-12s\n", " Type", 
                "                                   User Identifier",
                " Permission");
        fprintf(outfile, "------  "
                "------------------------------------------------------------"
                "------------------------------  ------------\n");
        int i;
        for (i = 0; i < aclGrantCount; i++) {
            S3AclGrant *grant = &(aclGrants[i]);
            const char *type;
            char composedId[S3_MAX_GRANTEE_USER_ID_SIZE + 
                            S3_MAX_GRANTEE_DISPLAY_NAME_SIZE + 16] = {0};
            const char *id;

            switch (grant->granteeType) {
            case S3GranteeTypeHuaweiCustomerByEmail:
                type = "Email";
                id = grant->grantee.huaweiCustomerByEmail.emailAddress;
                break;
            case S3GranteeTypeCanonicalUser:
                type = "UserID";
                snprintf_s(composedId, sizeof(composedId), _TRUNCATE,
                         "%s (%s)", grant->grantee.canonicalUser.id,
                         grant->grantee.canonicalUser.displayName);
                id = composedId;
                break;
            case S3GranteeTypeAllAwsUsers:
                type = "Group";
                id = "Authenticated AWS Users";
                break;
            case S3GranteeTypeAllUsers:
                type = "Group";
                id = "All Users";
                break;
            default:
                type = "Group";
                id = "Log Delivery";
                break;
            }
            const char *perm;
            switch (grant->permission) {
            case S3PermissionRead:
                perm = "READ";
                break;
            case S3PermissionWrite:
                perm = "WRITE";
                break;
            case S3PermissionReadACP:
                perm = "READ_ACP";
                break;
            case S3PermissionWriteACP:
                perm = "WRITE_ACP";
                break;
            default:
                perm = "FULL_CONTROL";
                break;
            }
            fprintf(outfile, "%-6s  %-90s  %-12s\n", type, id, perm);
        }
    }
    else {
        printError();
    }

    fclose(outfile);

    S3_deinitialize();
}

void get_bktacl(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
		usageExit(stderr);
	}

	const char *bucketName = argv[optindex];

	char ownerId[S3_MAX_GRANTEE_USER_ID_SIZE]="376254D0224859F65A773CEAE34221B5";
	char ownerDisplayName[S3_MAX_GRANTEE_DISPLAY_NAME_SIZE]="yasuo";
	int aclGrantCount;
	int i=0;

	S3AclGrant aclGrants[S3_MAX_ACL_GRANT_COUNT]={};		

	S3RequestContext *req=NULL;	

	S3_init();

	S3BucketContext bucketContext =
	{
		0,
		bucketName,
		protocolG,
		uriStyleG,
		accessKeyIdG,
		secretAccessKeyG,
		pCAInfo
	};

	S3ResponseHandler responseHandler =
	{
		&responsePropertiesCallback,
		&responseCompleteCallback
	};

	do {
		GetBucketAcl(&bucketContext,
			ownerId, ownerDisplayName, &aclGrantCount, aclGrants, req, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry());

	if (statusG == S3StatusOK) {
		for (i = 0; i < aclGrantCount; i++) {
			S3AclGrant *grant = &(aclGrants[i]);
			const char *type;
			char composedId[S3_MAX_GRANTEE_USER_ID_SIZE + 
				S3_MAX_GRANTEE_DISPLAY_NAME_SIZE + 16] = {0};
			const char *id;

			switch (grant->granteeType) {
			case S3GranteeTypeHuaweiCustomerByEmail:
				type = "Email";
				id = grant->grantee.huaweiCustomerByEmail.emailAddress;
				break;
			case S3GranteeTypeCanonicalUser:
				type = "UserID";
				snprintf_s(composedId, sizeof(composedId), _TRUNCATE,
					"%s (%s)", grant->grantee.canonicalUser.id,
					grant->grantee.canonicalUser.displayName);
				id = composedId;
				break;
			case S3GranteeTypeAllAwsUsers:
				type = "Group";
				id = "Authenticated AWS Users";
				break;
			case S3GranteeTypeAllUsers:
				type = "Group";
				id = "All Users";
				break;
			default:
				type = "Group";
				id = "Log Delivery";
				break;
			}
			const char *perm;
			switch (grant->permission) {
			case S3PermissionRead:
				perm = "READ";
				break;
			case S3PermissionWrite:
				perm = "WRITE";
				break;
			case S3PermissionReadACP:
				perm = "READ_ACP";
				break;
			case S3PermissionWriteACP:
				perm = "WRITE_ACP";
				break;
			default:
				perm = "FULL_CONTROL";
				break;
			}
			printf("group = %s\n", type);
			printf("granteeID,granteeName = %s\n", id);
			printf("permisssion  = %s\n", perm);
		}
	}
	else {
		printError();
	}
	S3_deinitialize();
}

// set acl -------------------------------------------------------------------

void set_acl(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex];
    const char *key = 0;

    // Split bucket/key
    char *slash = argv[optindex++];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (*slash) {
        *slash++ = 0;
        key = slash;
    }
    else {
        key = 0;
    }

    const char *filename = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    FILE *infile;

    if (filename) {
        if (!(infile = fopen(filename, "r" FOPEN_EXTRA_FLAGS))) {
            fprintf(stderr, "\nERROR: Failed to open input file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }
    else 
	{
		fprintf(stderr, "\nERROR: please input aclfile.");
		usageExit(stderr);
		exit(-1);
    }

    // Read in the complete ACL
    char aclBuf[RECIVE_STREAM_LENGTH] = {0};
    aclBuf[fread(aclBuf, 1, sizeof(aclBuf), infile)] = 0;
    char ownerId[S3_MAX_GRANTEE_USER_ID_SIZE] = {0};
    char ownerDisplayName[S3_MAX_GRANTEE_DISPLAY_NAME_SIZE] = {0};
    
    // Parse it
    int aclGrantCount;
    S3AclGrant aclGrants[S3_MAX_ACL_GRANT_COUNT];
    if (!convert_simple_acl(aclBuf, ownerId, ownerDisplayName,
                            &aclGrantCount, aclGrants)) {
        fprintf(stderr, "\nERROR: Failed to parse ACLs\n");
        fclose(infile);
        exit(-1);
    }

    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    do {
//        SetBucketAcl(&bucketContext, key, ownerId, ownerDisplayName,
//                   aclGrantCount, aclGrants, 0, &responseHandler, 0);
        SetObjectAcl(&bucketContext, key,NULL, ownerId, ownerDisplayName,
                   aclGrantCount, aclGrants, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());
    
    if (statusG != S3StatusOK) {
        printError();
    }

    fclose(infile);

    S3_deinitialize();
}


void set_bktacl(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
		usageExit(stderr);
	}

	const char *bucketName = argv[optindex++];

	char ownerId[S3_MAX_GRANTEE_USER_ID_SIZE]={0};
	char ownerDisplayName[S3_MAX_GRANTEE_DISPLAY_NAME_SIZE]={0};
	
	S3AclGrant aclGrants[S3_MAX_ACL_GRANT_COUNT];

	int aclGrantCount=0;	
	while(optindex<argc){
		char *param = argv[optindex++];
		if (!strncmp(param, GRANTEE_PREFIX, GRANTEE_PREFIX_LEN)) {
			const char *ad = &(param[GRANTEE_PREFIX_LEN]);
			if(!strcmp(ad,"0")){
				aclGrants[aclGrantCount].granteeType=S3GranteeTypeHuaweiCustomerByEmail;
			}else if(!strcmp(ad,"1")){
				aclGrants[aclGrantCount].granteeType=S3GranteeTypeCanonicalUser;
			}else if(!strcmp(ad,"2")){
				aclGrants[aclGrantCount].granteeType=S3GranteeTypeAllAwsUsers;
			}else if(!strcmp(ad,"3")){
				aclGrants[aclGrantCount].granteeType=S3GranteeTypeAllUsers;
			}else if(!strcmp(ad,"4")){
				aclGrants[aclGrantCount].granteeType=S3GranteeTypeLogDelivery;
			}else{
				fprintf(stderr, "\nERROR: Invalid param: %s\n", param);
				usageExit(stderr);
			}
		}else if(!strncmp(param, PERMISSION_PREFIX, PERMISSION_PREFIX_LEN)) {
			const char *ad = &(param[PERMISSION_PREFIX_LEN]);
			if(!strcmp(ad,"0")){
				aclGrants[aclGrantCount].permission=S3PermissionRead;
			}else if(!strcmp(ad,"1")){
				aclGrants[aclGrantCount].permission=S3PermissionWrite;
			}else if(!strcmp(ad,"2")){
				aclGrants[aclGrantCount].permission=S3PermissionReadACP;
			}else if(!strcmp(ad,"3")){
				aclGrants[aclGrantCount].permission=S3PermissionWriteACP;
			}else if(!strcmp(ad,"4")){
				aclGrants[aclGrantCount].permission=S3PermissionFullControl;
			}else{
				fprintf(stderr, "\nERROR: Invalid param: %s\n", param);
				usageExit(stderr);
			}
		}else if (!strncmp(param, OWNERID_PREFIX, OWNERID_PREFIX_LEN)){
			const char *ad = &(param[GRANTEE_PREFIX_LEN]);
			strcpy_s(aclGrants[aclGrantCount].grantee.canonicalUser.id, S3_MAX_GRANTEE_USER_ID_SIZE, ad);
			strcpy_s(ownerId, S3_MAX_GRANTEE_USER_ID_SIZE, ad);
		}else if (!strncmp(param, OWNERID_DISPLAY_NAME_PREFIX, OWNERID_DISPLAY_NAME_PREFIX_LEN)){
			const char *ad = &(param[OWNERID_DISPLAY_NAME_PREFIX_LEN]);
			strcpy_s(aclGrants[aclGrantCount].grantee.canonicalUser.displayName, S3_MAX_GRANTEE_DISPLAY_NAME_SIZE, ad);
			strcpy_s(ownerDisplayName, S3_MAX_GRANTEE_DISPLAY_NAME_SIZE, ad);
		}else{
			fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
			usageExit(stderr);
		}
		//aclGrantCount++;
	}
	S3_init();
	S3BucketContext bucketContext =
	{
		0,
		bucketName,
		protocolG,
		uriStyleG,
		accessKeyIdG,
		secretAccessKeyG,
		pCAInfo
	};

	S3RequestContext *req=NULL;		
	S3ResponseHandler responseHandler =
	{
		&responsePropertiesCallback, &responseCompleteCallback
	};		

	do {
		SetBucketAcl(&bucketContext,
			ownerId, ownerDisplayName, aclGrantCount, aclGrants, req, &responseHandler, 0);
		//"", "", aclGrantCount, aclGrants, req, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry());

	if (statusG != S3StatusOK) {
		printError();
	}
	else
	{
		printf("set acl status is %d\n", S3StatusOK);
	}


	S3_deinitialize();
}


void set_aclbyhead(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex];
    const char *key = 0;

    // Split bucket/key
    char *slash = argv[optindex++];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (*slash) {
        *slash++ = 0;
        key = slash;
    }
    else {
        key = 0;
    }

 
    S3_init();
	
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    do {
        SetObjectAclByHead(&bucketContext, key,0,S3CannedAclPublicRead , 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());
    
    if (statusG != S3StatusOK) {
        printError();
    }

 
    S3_deinitialize();
}

void set_bucketaclbyhead(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex];
    const char *key = 0;

    // Split bucket/key
    char *slash = argv[optindex++];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (*slash) {
        *slash++ = 0;
        key = slash;
    }
    else {
        key = 0;
    }

 
    S3_init();
	
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    do {
		SetBucketAclByHead(&bucketContext,S3CannedAclPublicRead , 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());
    
    if (statusG != S3StatusOK) {
        printError();
    }

 
    S3_deinitialize();
}

// get logging ----------------------------------------------------------------

void get_logging(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];
    const char *filename = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    FILE *outfile = 0;

    if (filename) {
        // Stat the file, and if it doesn't exist, open it in w mode
		struct stat buf;
        if (stat(filename, &buf) == -1) {
            outfile = fopen(filename, "w" FOPEN_EXTRA_FLAGS);
        }
        else {
            // Open in r+ so that we don't truncate the file, just in case
            // there is an error and we write no bytes, we leave the file
            // unmodified
            outfile = fopen(filename, "r+" FOPEN_EXTRA_FLAGS);
        }
        
        if (!outfile) {
            fprintf(stderr, "\nERROR: Failed to open output file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }
    else if (showResponsePropertiesG) {
        fprintf(stderr, "\nERROR: getlogging -s requires a filename "
                "parameter\n");
        usageExit(stderr);
    }
    else {
        outfile = stdout;
    }

    int aclGrantCount = 0;
    S3AclGrant aclGrants[S3_MAX_ACL_GRANT_COUNT];
    char targetBucket[S3_MAX_BUCKET_NAME_SIZE] ={0};
    char targetPrefix[S3_MAX_KEY_SIZE] = {0};

    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    do {
        GetBucketLoggingConfiguration(&bucketContext, targetBucket, targetPrefix,
                                     &aclGrantCount, aclGrants, 0, 
                                     &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG == S3StatusOK) {
        if (targetBucket[0]) {
            printf("Target Bucket: %s\n", targetBucket);
            if (targetPrefix[0]) {
                printf("Target Prefix: %s\n", targetPrefix);
            }
            fprintf(outfile, "%-6s  %-90s  %-12s\n", " Type", 
                    "                                   User Identifier",
                    " Permission");
            fprintf(outfile, "------  "
                    "---------------------------------------------------------"
                    "---------------------------------  ------------\n");
            int i;
            for (i = 0; i < aclGrantCount; i++) {
                S3AclGrant *grant = &(aclGrants[i]);
                const char *type;
                char composedId[S3_MAX_GRANTEE_USER_ID_SIZE + 
                                S3_MAX_GRANTEE_DISPLAY_NAME_SIZE + 16] = {0};
                const char *id;
                
                switch (grant->granteeType) {
                case S3GranteeTypeHuaweiCustomerByEmail:
                    type = "Email";
                    id = grant->grantee.huaweiCustomerByEmail.emailAddress;
                    break;
                case S3GranteeTypeCanonicalUser:
                    type = "UserID";
                    snprintf_s(composedId, sizeof(composedId), _TRUNCATE,
                             "%s (%s)", grant->grantee.canonicalUser.id,
                             grant->grantee.canonicalUser.displayName);
                    id = composedId;
                    break;
                case S3GranteeTypeAllAwsUsers:
                    type = "Group";
                    id = "Authenticated AWS Users";
                    break;
                default:
                    type = "Group";
                    id = "All Users";
                    break;
                }
                const char *perm;
                switch (grant->permission) {
                case S3PermissionRead:
                    perm = "READ";
                    break;
                case S3PermissionWrite:
                    perm = "WRITE";
                    break;
                case S3PermissionReadACP:
                    perm = "READ_ACP";
                    break;
                case S3PermissionWriteACP:
                    perm = "WRITE_ACP";
                    break;
                default:
                    perm = "FULL_CONTROL";
                    break;
                }
                fprintf(outfile, "%-6s  %-90s  %-12s\n", type, id, perm);
            }
        }
        else {
            printf("Service logging is not enabled for this bucket.\n");
        }
    }
    else {
        printError();
    }

    fclose(outfile);

    S3_deinitialize();
}


// set logging ----------------------------------------------------------------

void set_logging(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];

    const char *targetBucket = 0, *targetPrefix = 0, *filename = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, TARGET_BUCKET_PREFIX, TARGET_BUCKET_PREFIX_LEN)) {
            targetBucket = &(param[TARGET_BUCKET_PREFIX_LEN]);
        }
        else if (!strncmp(param, TARGET_PREFIX_PREFIX, 
                          TARGET_PREFIX_PREFIX_LEN)) {
            targetPrefix = &(param[TARGET_PREFIX_PREFIX_LEN]);
        }
        else if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    int aclGrantCount = 0;
    S3AclGrant aclGrants[S3_MAX_ACL_GRANT_COUNT];

    if (targetBucket) {
        FILE *infile;
        
        if (filename) {
            if (!(infile = fopen(filename, "r" FOPEN_EXTRA_FLAGS))) {
                fprintf(stderr, "\nERROR: Failed to open input file %s: ",
                        filename);
                perror(0);
                exit(-1);
            }
        }
        else 
		{
			fprintf(stderr, "\nERROR: please input aclfile.");
			usageExit(stderr);
			exit(-1);
        }

        // Read in the complete ACL
        char aclBuf[RECIVE_STREAM_LENGTH] = {0};
        aclBuf[fread(aclBuf, 1, sizeof(aclBuf), infile)] = 0;
        char ownerId[S3_MAX_GRANTEE_USER_ID_SIZE] = {0};
        char ownerDisplayName[S3_MAX_GRANTEE_DISPLAY_NAME_SIZE] = {0};
        
        // Parse it
        if (!convert_simple_acl(aclBuf, ownerId, ownerDisplayName,
                                &aclGrantCount, aclGrants)) {
            fprintf(stderr, "\nERROR: Failed to parse ACLs\n");
            fclose(infile);
            exit(-1);
        }

        fclose(infile);
    }

    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    do {
        SetBucketLoggingConfiguration(&bucketContext, targetBucket, 
                                     targetPrefix, aclGrantCount, aclGrants, 
                                     0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());
    
    if (statusG != S3StatusOK) {
        printError();
    }

    S3_deinitialize();
}

// getbucketquota-------------------------------------------------------------
static void get_bucketquota(int argc, char **argv, int optindex)
{
    // 
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];

    if (optindex != argc) {
        fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
        usageExit(stderr);
    }

    S3_init();
	
	S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    char bucketquota[64] = {0};
    do {
        GetBucketQuotaCA(&bucketContext, sizeof(bucketquota),
                       bucketquota, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

	if (statusG != S3StatusOK) {
		printError();
	}else{
		const char *result = bucketquota;
		if (NULL != result)
		{
		printf("%-56s  %-20s\n", "                         Bucket",
			"       bucketquota");
		printf("--------------------------------------------------------  "
			"--------------------\n");
		printf("%-56s  %-20s\n", bucketName, result);
		}
	}

    S3_deinitialize();
}

// setbucketquota-------------------------------------------------------------
static void set_bucketquota(int argc, char **argv, int optindex)
{
    // 
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];
    char *bucketquota = argv[optindex++];   //不再使用默认的10000配额值，可以任意定义一个值

    if (optindex != argc) {
        fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
        usageExit(stderr);
    }

    S3_init();
	
	S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        S3UriStyleVirtualHost,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    //char bucketquota[64]="100000";
    do {
        SetBucketQuotaCA(&bucketContext,
                       bucketquota, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

 
 if (statusG == S3StatusOK) {
	 printf("set_bucketquota success .\n");
 }
 else {
	 printError();
 }
 

    S3_deinitialize();
}

static void get_bucketinfo(int argc, char **argv, int optindex)
{
		if (optindex == argc) {
			fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
			usageExit(stderr);
		}
	
		const char *bucketName = argv[optindex++];
	
		if (optindex != argc) {
			fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
			usageExit(stderr);
		}
	
		S3_init();
	   
		S3BucketContext bucketContext =
		{
			0,
			bucketName,
			protocolG,
			uriStyleG,
			accessKeyIdG,
			secretAccessKeyG,
			pCAInfo
		};
	
		S3ResponseHandler responseHandler =
		{
			&responsePropertiesCallback, &responseCompleteCallback
		};
	
	char size[256] = {0};
	char obj[256] = {0};
   do {
	   GetBucketStorageInfoCA(&bucketContext, sizeof(size),
                       size,sizeof(obj),obj, 0, &responseHandler, 0);
   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("%-26s %-26s %-20s\n", "   Bucket           ","obj        ",
               "       size");
        printf("--------------------------------------------------------  "
               "--------------------\n");
        printf("%-26s %-26s %-20s\n", bucketName,obj, size);
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

// llist_uploads ---------------------------------------------------------------

typedef struct list_multipart_uploads_callback_data
{
    int isTruncated;
    char nextMarker[1024];
	char nextUploadIdMarker[1024];
    int keyCount;
    int allDetails;
} list_multipart_uploads_callback_data;


static void printListMultipartUploadsHeader(int allDetails)
{
    printf("%-20s  %-20s  %-5s", 
           "              Key", 
           "   initiated", "storageClass");
    if (allDetails) {
        printf("  %-34s  %-34s  %-12s", 
               "               uploadId", 
               "                  Owner ID",
               "Display Name");
    }
    printf("\n");
    printf("------------------------------  "
           "--------------------  -----");
    if (allDetails) {
        printf("  ----------------------------------  "
               "-------------------------------------------------"
               "---------------  ------------");
    }
    printf("\n");
}


static S3Status listMultipartUploadsCallback(int isTruncated, const char *nextMarker,const char*nextUploadIdMarker,
                                   int uploadsCount, 
                                   const S3ListMultipartUpload *uploads,
                                   int commonPrefixesCount,
                                   const char **commonPrefixes,
                                   void *callbackData)
{
    list_multipart_uploads_callback_data *data = 
        (list_multipart_uploads_callback_data *) callbackData;

    data->isTruncated = isTruncated;
    // This is tricky.  S3 doesn't return the NextMarker if there is no
    // delimiter.  Why, I don't know, since it's still useful for paging
    // through results.  We want NextMarker to be the last content in the
    // list, so set it to that if necessary.
    if ((!nextMarker || !nextMarker[0]) && uploadsCount) {
        nextMarker = uploads[uploadsCount - 1].key;
    }
    if (nextMarker) {
        snprintf_s(data->nextMarker, sizeof(data->nextMarker), _TRUNCATE, "%s", 
                 nextMarker);
        snprintf_s(data->nextUploadIdMarker, sizeof(data->nextUploadIdMarker), _TRUNCATE, "%s", 
                 nextUploadIdMarker);
    }
    else {
        data->nextMarker[0] = 0;
    }
    
    if (uploadsCount && !data->keyCount) {
        printListMultipartUploadsHeader(data->allDetails);
    }

    int i;
    for (i = 0; i < uploadsCount; i++) {
        const S3ListMultipartUpload *upload = &(uploads[i]);
        char timebuf[256] = {0};
        if (0) {
            time_t t = (time_t) upload->initiated;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ",
                     gmtime(&t));
            printf("\nKey: %s\n", upload->key);
            printf("initiated: %s\n", timebuf);
            printf("storageClass: %s\n", upload->storageClass);
            printf("uploadId: %s\n", upload->uploadId);
            if (upload->ownerId) {
                printf("Owner ID: %s\n", upload->ownerId);
            }
            if (upload->ownerDisplayName) {
                printf("Owner Display Name: %s\n", upload->ownerDisplayName);
            }
        }
        else {
            time_t t = (time_t) upload->initiated;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", 
                     gmtime(&t));  
            printf("%-20s  %s  %s", upload->key, timebuf, upload->storageClass);
            if (data->allDetails) {
                printf("  %-34s  %-34s  %-12s",
                       upload->uploadId, 
                       upload->ownerId ? upload->ownerId : "",
                       upload->ownerDisplayName ? 
                       upload->ownerDisplayName : "");
            }
            printf("\n");
        }
    }

    data->keyCount += uploadsCount;

    for (i = 0; i < commonPrefixesCount; i++) {
        printf("\nCommon Prefix: %s\n", commonPrefixes[i]);
    }

    return S3StatusOK;
}


static void list_uploads(int argc, char **argv, int optindex)
{
    const char *bucketName = 0;

    const char *prefix = 0, *marker = 0, *delimiter = 0, *uploadidmarke = 0;
    int maxkeys = 0, allDetails = 1;
    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, PREFIX_PREFIX, PREFIX_PREFIX_LEN)) {
            prefix = &(param[PREFIX_PREFIX_LEN]);
        }
        else if (!strncmp(param, MARKER_PREFIX, MARKER_PREFIX_LEN)) {
            marker = &(param[MARKER_PREFIX_LEN]);
        }
        else if (!strncmp(param, DELIMITER_PREFIX, DELIMITER_PREFIX_LEN)) {
            delimiter = &(param[DELIMITER_PREFIX_LEN]);
        }
        else if (!strncmp(param, UPLOADIDMARKE_PREFIX, UPLOADIDMARKE_PREFIX_LEN)) {
            uploadidmarke = &(param[UPLOADIDMARKE_PREFIX_LEN]);
        }
        else if (!strncmp(param, MAXKEYS_PREFIX, MAXKEYS_PREFIX_LEN)) {
            maxkeys = (int)convertInt(&(param[MAXKEYS_PREFIX_LEN]), "maxkeys");
        }
        else if (!strncmp(param, ALL_DETAILS_PREFIX,
                          ALL_DETAILS_PREFIX_LEN)) {
            const char *ad = &(param[ALL_DETAILS_PREFIX_LEN]);
            if (!strcmp(ad, "true") || !strcmp(ad, "TRUE") || 
                !strcmp(ad, "yes") || !strcmp(ad, "YES") ||
                !strcmp(ad, "1")) {
                allDetails = 1;
            }
        }
        else if (!bucketName) {
            bucketName = param;
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
	}
    S3_init();
    
    S3BucketContext uploadsContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
	   S3ListMultipartUploadsHandler listUploadsHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &listMultipartUploadsCallback
    };
	list_multipart_uploads_callback_data data;
	memset_s(&data, sizeof(list_multipart_uploads_callback_data), 0, sizeof(list_multipart_uploads_callback_data));

	snprintf_s(data.nextMarker, sizeof(data.nextMarker), _TRUNCATE, "%s", marker);
	snprintf_s(data.nextUploadIdMarker, sizeof(data.nextUploadIdMarker), _TRUNCATE, "%s", uploadidmarke);
    data.keyCount = 0;
    data.allDetails = allDetails;

    do {
        data.isTruncated = 0;
        do {
            ListMultipartUploads(&uploadsContext, prefix, marker,
                           delimiter,uploadidmarke, maxkeys, 0, &listUploadsHandler, &data);
        } while (S3_status_is_retryable(statusG) && should_retry());
        if (statusG != S3StatusOK) {
            break;
        }
    } while (data.isTruncated && (!maxkeys || (data.keyCount < maxkeys)));

    if (statusG == S3StatusOK) {
        if (!data.keyCount) {
            printListMultipartUploadsHeader(allDetails);
        }
    }
    else {
        printError();
    }

    S3_deinitialize();
}

static void set_bucketlc(int argc, char **argv, int optindex)
{
	   if (optindex == argc) {
		   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		   usageExit(stderr);
	   }
	
	   const char *bucketName = argv[optindex++];
	
	   if (optindex != argc) {
		   fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		   usageExit(stderr);
	   }
	
	   S3_init();
	
	   S3ResponseHandler responseHandler =
	   {
		   &responsePropertiesCallback, &responseCompleteCallback
	   };
	S3BucketContext Context =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
	char md5[256]="WJ2/ncc9ppQQpFNySZ0+Rw==";
	char id[256]="test&";
	char prefix[256]={0};
	char status[256]="Enabled";
    //char* days="2";
	char* days = NULL;
	    S3PutProperties putProperties =
    {
        0,
        md5,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        S3CannedAclPrivate,
        0,
        0,
        0
    };
	   do {
		   SetBucketLifecycleConfiguration(&Context,
						  id, prefix,status,days,"20150628T0000Z",&putProperties, 0, &responseHandler, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("SetBucketLifecycleConfiguration success .\n");
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

static void set_bucketlc_ex(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
	   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
	   usageExit(stderr);
	}

	const char *bucketName = argv[optindex++];
	const char *md5 = "dU7zzkZ9TpDoSIdAcIX5VA==";
	//const char* md5 = 0;
	while (optindex < argc) {
		char *param = argv[optindex++];
		if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
			md5 = &(param[MD5_PREFIX_LEN]);
		}
		else {
			fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
			usageExit(stderr);
		}
	}
	
	if (optindex != argc) {
		fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		usageExit(stderr);
	}
	
	S3_init();

	S3ResponseHandler responseHandler =
	{
		&responsePropertiesCallback, &responseCompleteCallback
	};
	S3BucketContext Context =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	char id_1[256] = "test1";
	char prefix_1[256] = "123";
	char status_1[256] = "Enabled";
	char* days_1 = "2";
	
	char id_2[256] = "test2";
	char prefix_2[256] = "456";
	char status_2[256] = "Disabled";
	char date_2[256] = "20150628T0000Z";
	
	S3BucketLifeCycleConf bucketLifeCycleConf[2];
	memset_s(bucketLifeCycleConf, 2*sizeof(S3BucketLifeCycleConf), 0, 2*sizeof(S3BucketLifeCycleConf));
	
	bucketLifeCycleConf[0].days = days_1;
	bucketLifeCycleConf[0].id = id_1;
	bucketLifeCycleConf[0].prefix = prefix_1;
	bucketLifeCycleConf[0].status = status_1;
	
	bucketLifeCycleConf[1].date = date_2;
	bucketLifeCycleConf[1].id = id_2;
	bucketLifeCycleConf[1].prefix = prefix_2;
	bucketLifeCycleConf[1].status = status_2;
	
	S3PutProperties putProperties =
    {
        0,
        md5,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        S3CannedAclPrivate,
        0,
        0,
        0
    };
	   do {
		   SetBucketLifecycleConfigurationEx(&Context,
						  bucketLifeCycleConf, 2, &putProperties, 0, &responseHandler, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("SetBucketLifecycleConfiguration success .\n");
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

static void get_bucketlc(int argc, char **argv, int optindex)
{
	   if (optindex == argc) {
		   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		   usageExit(stderr);
	   }
	
	   const char *bucketName = argv[optindex++];
	
	   if (optindex != argc) {
		   fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		   usageExit(stderr);
	   }
	
	   S3_init();
	
	   S3ResponseHandler responseHandler =
	   {
		   &responsePropertiesCallback, &responseCompleteCallback
	   };
	
	S3BucketContext Context =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	char id[256]={0};
	char prefix[256]={0};
	char status[256]={0};
	char days[256]={0};
	char date[256]={0};
	   do {
		   GetBucketLifecycleConfiguration(&Context,date,days,id, prefix,status, 0, &responseHandler, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("GetBucketLifecycleConfiguration success .\n");
		printf("id = %s \n prefix = %s \n status = %s \n days = %s \n date = %s \n",id,prefix,status,days,date);
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

S3Status getBucketLifecycleConfigurationCallbackEx (S3BucketLifeCycleConf* bucketLifeCycleConf,
 								unsigned int blccNumber,
								void *callbackData)
{
	(void)callbackData;
	unsigned int i = 0;
	
	#define print_nonull(name, field)                                 \
    do {                                                           \
        if (field && field[0]) {                                  \
            printf("%s: %s\n", name, field);          \
        }                                                          \
    } while (0)
	
	for(i = 0; i < blccNumber; i++)
	{
		printf("-----------------------------------------------\n");
		print_nonull("id", bucketLifeCycleConf[i].id);
		print_nonull("prefix", bucketLifeCycleConf[i].prefix);
		print_nonull("status", bucketLifeCycleConf[i].status);
		print_nonull("days", bucketLifeCycleConf[i].days);
		print_nonull("date", bucketLifeCycleConf[i].date);
	}
	printf("-----------------------------------------------\n");
	return S3StatusOK;
}

static void get_bucketlc_ex(int argc, char **argv, int optindex)
{
	   if (optindex == argc) {
		   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		   usageExit(stderr);
	   }
	
	   const char *bucketName = argv[optindex++];
	
	   if (optindex != argc) {
		   fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		   usageExit(stderr);
	   }
	
	   S3_init();
	
	   S3LifeCycleHandlerEx lifeCycleHandlerEx =
	   {
		   {&responsePropertiesCallback, &responseCompleteCallback},
		   &getBucketLifecycleConfigurationCallbackEx
	   };
	
	S3BucketContext Context =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
	
	   do {
		   GetBucketLifecycleConfigurationEx(&Context, 0, &lifeCycleHandlerEx, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("GetBucketLifecycleConfiguration success .\n");
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

static void del_bucketlc(int argc, char **argv, int optindex)
{
	   if (optindex == argc) {
		   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		   usageExit(stderr);
	   }
	
	   const char *bucketName = argv[optindex++];
	
	   if (optindex != argc) {
		   fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		   usageExit(stderr);
	   }
	
	   S3_init();
	   
	   S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
	
	   S3ResponseHandler responseHandler =
	   {
		   &responsePropertiesCallback, &responseCompleteCallback
	   };
	
	   do {
		   DeleteBucketLifecycleConfigurationCA(&bucketContext,0, &responseHandler, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("DeleteBucketLifecycleConfiguration success .\n");
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

static void get_bucketp(int argc, char **argv, int optindex)
{
	   if (optindex == argc) {
		   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		   usageExit(stderr);
	   }
	
	   const char *bucketName = argv[optindex++];
	
	   if (optindex != argc) {
		   fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		   usageExit(stderr);
	   }
	
	   S3_init();
	   
	   S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
	
	   S3ResponseHandler responseHandler =
	   {
		   &responsePropertiesCallback, &responseCompleteCallback
	   };
	

	char policy[1024]="";

	   do {
		   GetBucketPolicyCA(&bucketContext, sizeof(policy),policy, 0, &responseHandler, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	printf("policy=%s\n",policy);
	if (statusG == S3StatusOK) {
		printf("get_bucketp success .\n");
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

static void set_bucketp(int argc, char **argv, int optindex)
{
	   if (optindex == argc) {
		   fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		   usageExit(stderr);
	   }
	
	   const char *bucketName = argv[optindex++];
	

	   const char *resource = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
		if (!strncmp(param, RESOURCE_PREFIX, RESOURCE_PREFIX_LEN)) {
            resource = &(param[RESOURCE_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }
	   S3_init();
	
		S3BucketContext bucketContext =
		{
			0,
			bucketName,
			protocolG,
			S3UriStyleVirtualHost,
			accessKeyIdG,
			secretAccessKeyG,
			pCAInfo
		};
	
	   S3ResponseHandler responseHandler =
	   {
		   &responsePropertiesCallback, &responseCompleteCallback
	   };
	   //char policy[1024]="{\"Statement\": [{\"Sid\": \"AddPerm\", \"Action\": [ \"s3:GetObject\" ], \"Effect\": \"Allow\", \"Resource\": \"arn:aws:s3:::bk1/*\", \"Principal\":\"*\"} ] }";
	   char policy[1024]="{\"Statement\": [{\"Sid\": \"AddPerm\", \"Action\": [ \"s3:GetObject\" ], \"Effect\": \"Allow\", \"Resource\": \"arn:aws:s3:::";
	   char policy_postfix[1024]="/*\", \"Principal\":\"*\"} ] }";
	   strcat_s(policy, sizeof(policy), bucketName);
	   strcat_s(policy, sizeof(policy), policy_postfix);
	   do {
		   SetBucketPolicyCA(&bucketContext,
						  policy, 0, &responseHandler, 0);
	   } while (S3_status_is_retryable(statusG) && should_retry());
	
	
	if (statusG == S3StatusOK) {
		printf("SetBucketPolicy success .\n");
	}
	else {
		printError();
	}
	
	
	   S3_deinitialize();

}

static void del_bucketp(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

    const char *bucketName = argv[optindex++];

    if (optindex != argc) {
        fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
        usageExit(stderr);
    }

    S3_init();
	
	S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    do {
        DeleteBucketPolicyCA(&bucketContext, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }

    S3_deinitialize();

}


typedef struct upload_callback_data
{
    FILE *infile;
    growbuffer *gb;
    uint64_t contentLength, originalContentLength;
    int noStatus;
} upload_callback_data;

static int uploadDataCallback(int bufferSize, char *buffer,
                                 void *callbackData)
{
    upload_callback_data *data = 
        (upload_callback_data *) callbackData;
    
    int ret = 0;

    if (data->contentLength) {
        int toRead = (int)((data->contentLength > (unsigned) bufferSize) ?
                      (unsigned) bufferSize : data->contentLength);
        if (data->gb) {
            growbuffer_read(&(data->gb), toRead, &ret, buffer);
        }
        else if (data->infile) {
            ret = fread(buffer, 1, toRead, data->infile);
        }
    }

    data->contentLength -= ret;

    if (data->contentLength && !data->noStatus) {
        // Avoid a weird bug in MingW, which won't print the second integer
        // value properly when it's in the same call, so print separately
        printf("%llu bytes remaining ", 
               (unsigned long long) data->contentLength);
        printf("(%d%% complete) ...\n",
               (int) (((data->originalContentLength - 
                        data->contentLength) * 100) /
                      data->originalContentLength));
    }

    return ret;
}

static void upart(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    char *slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *bucketName = argv[optindex++];
    const char *key = slash;
    const char *filename = 0;
    uint64_t contentLength = 0;
    const char *cacheControl = 0, *contentType = 0, *md5 = 0;
    const char *contentDispositionFilename = 0, *contentEncoding = 0;
    int64_t expires = -1;
    S3CannedAcl cannedAcl = S3CannedAclPrivate;
    int metaPropertiesCount = 0;
    S3NameValue metaProperties[S3_MAX_METADATA_COUNT];
    char useServerSideEncryption = 0;
    int noStatus = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, FILENAME_PREFIX, FILENAME_PREFIX_LEN)) {
            filename = &(param[FILENAME_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_LENGTH_PREFIX, 
                          CONTENT_LENGTH_PREFIX_LEN)) {
            contentLength = convertInt(&(param[CONTENT_LENGTH_PREFIX_LEN]),
                                       "contentLength");
            if (contentLength > (5LL * 1024 * 1024 * 1024)) {
                fprintf(stderr, "\nERROR: contentLength must be no greater "
                        "than 5 GB\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, CACHE_CONTROL_PREFIX, 
                          CACHE_CONTROL_PREFIX_LEN)) {
            cacheControl = &(param[CACHE_CONTROL_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_TYPE_PREFIX, 
                          CONTENT_TYPE_PREFIX_LEN)) {
            contentType = &(param[CONTENT_TYPE_PREFIX_LEN]);
        }
        else if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
            md5 = &(param[MD5_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_DISPOSITION_FILENAME_PREFIX, 
                          CONTENT_DISPOSITION_FILENAME_PREFIX_LEN)) {
            contentDispositionFilename = 
                &(param[CONTENT_DISPOSITION_FILENAME_PREFIX_LEN]);
        }
        else if (!strncmp(param, CONTENT_ENCODING_PREFIX, 
                          CONTENT_ENCODING_PREFIX_LEN)) {
            contentEncoding = &(param[CONTENT_ENCODING_PREFIX_LEN]);
        }
        else if (!strncmp(param, EXPIRES_PREFIX, EXPIRES_PREFIX_LEN)) {
            expires = parseIso8601Time(&(param[EXPIRES_PREFIX_LEN]));
            if (expires < 0) {
                fprintf(stderr, "\nERROR: Invalid expires time "
                        "value; ISO 8601 time format required\n");
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, X_AMZ_META_PREFIX, X_AMZ_META_PREFIX_LEN)) {
            if (metaPropertiesCount == S3_MAX_METADATA_COUNT) {
                fprintf(stderr, "\nERROR: Too many x-amz-meta- properties, "
                        "limit %lu: %s\n", 
                        (unsigned long) S3_MAX_METADATA_COUNT, param);
                usageExit(stderr);
            }
            char *name = &(param[X_AMZ_META_PREFIX_LEN]);
            char *value = name;
            while (*value && (*value != '=')) {
                value++;
            }
            if (!*value || !*(value + 1)) {
                fprintf(stderr, "\nERROR: Invalid parameter: %s\n", param);
                usageExit(stderr);
            }
            *value++ = 0;
            metaProperties[metaPropertiesCount].name = name;
            metaProperties[metaPropertiesCount++].value = value;
        }
        else if (!strncmp(param, USE_SERVER_SIDE_ENCRYPTION_PREFIX,
                          USE_SERVER_SIDE_ENCRYPTION_PREFIX_LEN)) {
            const char *val = &(param[USE_SERVER_SIDE_ENCRYPTION_PREFIX_LEN]);
            if (!strcmp(val, "true") || !strcmp(val, "TRUE") || 
                !strcmp(val, "yes") || !strcmp(val, "YES") ||
                !strcmp(val, "1")) {
                useServerSideEncryption = 1;
            }
            else {
                useServerSideEncryption = 0;
            }
        }
        else if (!strncmp(param, CANNED_ACL_PREFIX, CANNED_ACL_PREFIX_LEN)) {
            char *val = &(param[CANNED_ACL_PREFIX_LEN]);
            if (!strcmp(val, "private")) {
                cannedAcl = S3CannedAclPrivate;
            }
            else if (!strcmp(val, "public-read")) {
                cannedAcl = S3CannedAclPublicRead;
            }
            else if (!strcmp(val, "public-read-write")) {
                cannedAcl = S3CannedAclPublicReadWrite;
            }
            else if (!strcmp(val, "authenticated-read")) {
                cannedAcl = S3CannedAclAuthenticatedRead;
            }
            else {
                fprintf(stderr, "\nERROR: Unknown canned ACL: %s\n", val);
                usageExit(stderr);
            }
        }
        else if (!strncmp(param, NO_STATUS_PREFIX, NO_STATUS_PREFIX_LEN)) {
            const char *ns = &(param[NO_STATUS_PREFIX_LEN]);
            if (!strcmp(ns, "true") || !strcmp(ns, "TRUE") || 
                !strcmp(ns, "yes") || !strcmp(ns, "YES") ||
                !strcmp(ns, "1")) {
                noStatus = 1;
            }
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }

    upload_callback_data data;
	memset_s(&data, sizeof(upload_callback_data), 0, sizeof(upload_callback_data));

    data.infile = 0;
    data.gb = 0;
    data.noStatus = noStatus;

    if (filename) {
        if (!contentLength) {
			struct stat statbuf;
            // Stat the file to get its length
            if (stat(filename, &statbuf) == -1) {
                fprintf(stderr, "\nERROR: Failed to stat file %s: ",
                        filename);
                perror(0);
                exit(-1);
            }
            contentLength = statbuf.st_size;//lint !e115
        }
        // Open the file
        if (!(data.infile = fopen(filename, "rb" FOPEN_EXTRA_FLAGS))) {
            fprintf(stderr, "\nERROR: Failed to open input file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }
    else {
        // Read from stdin.  If contentLength is not provided, we have
        // to read it all in to get contentLength.
        if (!contentLength) {
            // Read all if stdin to get the data
			char buffer[RECIVE_STREAM_LENGTH] = {0};
			while (1) {
#if defined __GNUC__ || defined LINUX
				int amtRead = fread(buffer, 1, sizeof(buffer), stdin);
#else
				char tempBuf[RECIVE_STREAM_LENGTH] = {0};
				scanf_s("%255s", tempBuf, RECIVE_STREAM_LENGTH);
				tempBuf[RECIVE_STREAM_LENGTH - 1] = '\0';
				strncat_s(buffer, sizeof(buffer), tempBuf, RECIVE_STREAM_LENGTH - strlen(buffer) -1);//Use safe function by jwx329074 2016.11.18
				buffer[RECIVE_STREAM_LENGTH - 1] = '\0';
				int amtRead = strlen(buffer);
				contentLength = amtRead;
#endif								
				if (amtRead == 0) {
					break;
				}
				if (!growbuffer_append(&(data.gb), buffer, amtRead)) {
					fprintf(stderr, "\nERROR: Out of memory while reading "
						"stdin\n");
					exit(-1);
				}
#if defined __GNUC__ || defined LINUX
				contentLength += amtRead;
				if (amtRead <= (int) (sizeof(buffer))) {				
					break;
				}
#else
				if (amtRead < (int) (sizeof(buffer)-1)) {				
					continue;								
				}
				else
				{
					break;
				}
#endif		
			}
		}
        else {
            data.infile = stdin;
        }
    }

    data.contentLength = data.originalContentLength = contentLength;




    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	S3PutProperties putProperties =
    {
        contentType,
        md5,
        cacheControl,
        contentDispositionFilename,
        contentEncoding,
        0,
        0,
        0,
        0,
        0,
        expires,
        cannedAcl,
        metaPropertiesCount,
        metaProperties,
        useServerSideEncryption
    };
	
    S3UploadHandler responseHandler =
    {
        {&responsePropertiesCallback,&responseCompleteCallback},
			&uploadDataCallback
    };

    do {
        UploadPart(&bucketContext, key, "1", "000001555D091E96098F51B0320D6E8A",contentLength,&putProperties,0, &responseHandler, &data);
    } while (S3_status_is_retryable(statusG) && should_retry());
    
    if (statusG != S3StatusOK) {
        printError();
    }


    S3_deinitialize();	

}

static void copart(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: source bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    char *slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid source bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *sourceBucketName = argv[optindex++];
    const char *sourceKey = slash;

    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: "
                "destination bucket/key\n");
        usageExit(stderr);
    }

    // Split bucket/key
    slash = argv[optindex];
    while (*slash && (*slash != '/')) {
        slash++;
    }
    if (!*slash || !*(slash + 1)) {
        fprintf(stderr, "\nERROR: Invalid destination bucket/key name: %s\n",
                argv[optindex]);
        usageExit(stderr);
    }
    *slash++ = 0;

    const char *destinationBucketName = argv[optindex++];
    const char *destinationKey = slash;

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        sourceBucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ResponseHandler responseHandler =
    { 
        &responsePropertiesCallback,
        &responseCompleteCallback
    };

    int64_t lastModified = 0;
	char eTag[256] = {0};

    do {
        CopyPart(&bucketContext, sourceKey, destinationBucketName,
                       destinationKey,1,4,"2","000001555D091E96098F51B0320D6E8A",
                       &lastModified, sizeof(eTag), eTag, 0,
                       &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG == S3StatusOK) {
        if (lastModified >= 0) {
			char timebuf[256] = {0};
            time_t t = (time_t) lastModified;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ",
                     gmtime(&t));
            printf("Last-Modified: %s\n", timebuf);
        }
        if (eTag[0]) {
            printf("ETag: %s\n", eTag);
        }
    }
    else {
        printError();
    }

    S3_deinitialize();

}


static void abortpart(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

	// Split bucket/key
	 char *slash = argv[optindex];
	 while (*slash && (*slash != '/')) {
		 slash++;
	 }
	 if (!*slash || !*(slash + 1)) {
		 fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
				 argv[optindex]);
		 usageExit(stderr);
	 }
	 *slash++ = 0;
	
	 const char *bucketName = argv[optindex++];
	 const char *key = slash;

    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    do {
        AbortMultipartUpload(&bucketContext,key,"917D22F59125B9F0EB25DA7089614F77", 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }

    S3_deinitialize();

}


static void initupload(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

 
 // Split bucket/key
  char *slash = argv[optindex];
  while (*slash && (*slash != '/')) {
	  slash++;
  }
  if (!*slash || !*(slash + 1)) {
	  fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
			  argv[optindex]);
	  usageExit(stderr);
  }
  *slash++ = 0;
 
  const char *bucketName = argv[optindex++];
  const char *key = slash;

	const char *cacheControl = 0, *contentType = 0, *md5 = 0;
	 const char *contentDispositionFilename = 0, *contentEncoding = 0;		  
	 while (optindex < argc) {
		 char *param = argv[optindex++];
		 if (!strncmp(param, CACHE_CONTROL_PREFIX, 
						   CACHE_CONTROL_PREFIX_LEN)) {
			 cacheControl = &(param[CACHE_CONTROL_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, CONTENT_TYPE_PREFIX, 
						   CONTENT_TYPE_PREFIX_LEN)) {
			 contentType = &(param[CONTENT_TYPE_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
			 md5 = &(param[MD5_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, CONTENT_DISPOSITION_FILENAME_PREFIX, 
						   CONTENT_DISPOSITION_FILENAME_PREFIX_LEN)) {
			 contentDispositionFilename = 
				 &(param[CONTENT_DISPOSITION_FILENAME_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, CONTENT_ENCODING_PREFIX, 
						   CONTENT_ENCODING_PREFIX_LEN)) {
			 contentEncoding = &(param[CONTENT_ENCODING_PREFIX_LEN]);
		 }
		 else {
			 fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
			 usageExit(stderr);
		 }		  
	 }
	 const char* webrl = 0;
	 S3PutProperties putProperties =
	 {
		 contentType,
		 md5,
		 cacheControl,
		 contentDispositionFilename,
		 contentEncoding,
		 0,
		 webrl,
		 0,
		 0,
		 0,
		 -1,
		 S3CannedAclPrivate,
		 0,
		 0,
		 0
	 };


    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };
	char upload[256]={0};
    do {
        InitiateMultipartUpload(&bucketContext,key,&putProperties,sizeof(upload),upload, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }
    else
    {
	    printf("upload=%s\n",upload);
    }

    S3_deinitialize();

}

S3Status CompleteMultipartUploadCallback(const char *location, 
                                         const char *bucket,
                                         const char *key,
                                         const char* eTag,
                                         void *callbackData)
{
	(void)callbackData;
	printf("location = %s \n bucket = %s \n key = %s \n eTag = %s \n",location,bucket,key,eTag);
	return S3StatusOK;
}

static void completemu(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

 
 // Split bucket/key
  char *slash = argv[optindex];
  while (*slash && (*slash != '/')) {
	  slash++;
  }
  if (!*slash || !*(slash + 1)) {
	  fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
			  argv[optindex]);
	  usageExit(stderr);
  }
  *slash++ = 0;
 
  const char *bucketName = argv[optindex++];
  const char *key = slash;

	const char *cacheControl = 0, *contentType = 0, *md5 = 0;
	 const char *contentDispositionFilename = 0, *contentEncoding = 0;		  
	 while (optindex < argc) {
		 char *param = argv[optindex++];
		 if (!strncmp(param, CACHE_CONTROL_PREFIX, 
						   CACHE_CONTROL_PREFIX_LEN)) {
			 cacheControl = &(param[CACHE_CONTROL_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, CONTENT_TYPE_PREFIX, 
						   CONTENT_TYPE_PREFIX_LEN)) {
			 contentType = &(param[CONTENT_TYPE_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
			 md5 = &(param[MD5_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, CONTENT_DISPOSITION_FILENAME_PREFIX, 
						   CONTENT_DISPOSITION_FILENAME_PREFIX_LEN)) {
			 contentDispositionFilename = 
				 &(param[CONTENT_DISPOSITION_FILENAME_PREFIX_LEN]);
		 }
		 else if (!strncmp(param, CONTENT_ENCODING_PREFIX, 
						   CONTENT_ENCODING_PREFIX_LEN)) {
			 contentEncoding = &(param[CONTENT_ENCODING_PREFIX_LEN]);
		 }
		 else {
			 fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
			 usageExit(stderr);
		 }		  
	 }
	
	 S3PutProperties putProperties =
	 {
		 contentType,
		 md5,
		 cacheControl,
		 contentDispositionFilename,
		 contentEncoding,
		 0,
		 0,
		 0,
		 0,
		 0,
		 -1,
		 S3CannedAclPrivate,
		 0,
		 0,
		 0
	 }; 

	S3UploadInfo info[10];
	info[0].partNumber="1";
	info[0].eTag="6152f813601de09432fbbeb373f5a557";
	info[1].partNumber="2";
	info[1].eTag="25204ab921fe84e0961de6fffdf03e1b";
		
    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
    S3CompleteMultipartUploadHandler responseHandler =
    {
        {&responsePropertiesCallback, &responseCompleteCallback},
		&CompleteMultipartUploadCallback
    };
	
    do {
        CompleteMultipartUpload(&bucketContext,key,"40079008567166DDCE454EAC08297120",info,2,&putProperties, 0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }

    S3_deinitialize();

}


//SetBucketWebsiteConfiguration
static void set_bwc(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		usageExit(stderr);
	}
	
	const char *bucketName = argv[optindex++];
	if (optindex != argc) {
		fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		usageExit(stderr);
	}

//	S3SetBucketRedirectAllConf setBucketRedirectAll;
//	setBucketRedirectAll.hostName = "www.huawei.com";
//	setBucketRedirectAll.protocol = "https";

	S3SetBucketWebsiteConf setBucketWebsiteConf;
	setBucketWebsiteConf.suffix = "index.html";
	setBucketWebsiteConf.key = "Error.html";
	setBucketWebsiteConf.stCount = 2;
	S3SetBucketWebsiteConfIn temp[2];
	setBucketWebsiteConf.stIn = temp;
	temp[0].keyPrefixEquals = "docs/";
	temp[0].replaceKeyPrefixWith = "documents/";
	temp[0].httpErrorCodeReturnedEquals="404";
	temp[0].httpRedirectCode = NULL;
	temp[0].hostName = "www.huawei.com";
	temp[0].protocol = "http";
	temp[0].replaceKeyWith = NULL;

	temp[1].keyPrefixEquals = "docs11111/";
	temp[1].replaceKeyPrefixWith = "documents11111/";
	temp[1].httpErrorCodeReturnedEquals="404";
	temp[1].httpRedirectCode = NULL;
	temp[1].hostName = "www.huawei.com1212";
	temp[1].protocol = "http";
	temp[1].replaceKeyWith = NULL;

	S3_init();
	
	S3ResponseHandler responseHandler =
	{
		&responsePropertiesCallback, &responseCompleteCallback
	};

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };


    do {
	   SetBucketWebsiteConfiguration(&bucketContext,
                       0, &setBucketWebsiteConf, 0, &responseHandler, 0);
   } while (S3_status_is_retryable(statusG) && should_retry());	

	if (statusG == S3StatusOK) {
		printf("SetBucketWebsiteConfiguration success .\n");
	}
	else {
		printError();
	}


   S3_deinitialize();


}

S3Status getBucketWebsiteConfigurationCallback(const char *hostname,
								const char *protocol,
								const char *suffix,
								const char *key,
								const S3SetBucketWebsiteConfIn *websiteconf,
								int webdatacount,
								void *callbackData)
{
	(void)callbackData;
	int i = 0;
	printf("hostname : %s\n", hostname);
	printf("protocol : %s\n", protocol);
	printf("suffix : %s\n", suffix);
	printf("key : %s\n", key);
	for(i = 0; i < webdatacount; i++)
	{
		printf("keyPrefixEquals : %s\n", websiteconf[i].keyPrefixEquals);
		printf("httpErrorCodeReturnedEquals : %s\n", websiteconf[i].httpErrorCodeReturnedEquals);
		printf("replaceKeyPrefixWith : %s\n", websiteconf[i].replaceKeyPrefixWith);
		printf("replaceKeyWith : %s\n", websiteconf[i].replaceKeyWith);
		printf("httpRedirectCode : %s\n", websiteconf[i].httpRedirectCode);
		printf("hostname : %s\n", websiteconf[i].hostName);
		printf("protocol : %s\n", websiteconf[i].protocol);
	}
	return S3StatusOK;
}

static void get_bwc(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		usageExit(stderr);
	}
	
	const char *bucketName = argv[optindex++];
	if (optindex != argc) {
		fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		usageExit(stderr);
	}
		
	S3_init();
	
	S3GetBucketWebsiteConfHandler responseHandler =
	{
		{&responsePropertiesCallback, &responseCompleteCallback},
			&getBucketWebsiteConfigurationCallback
	};

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	
	 do {
		GetBucketWebsiteConfiguration(&bucketContext,
						0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		printf("GetBucketWebsiteConfiguration Success \n!");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();

}

static void del_bwc(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];
	 if (optindex != argc) {
		 fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		 usageExit(stderr);
	 }
	
	 
	 S3_init();
	 
	 S3ResponseHandler responseHandler =
	 {
		 &responsePropertiesCallback, &responseCompleteCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		DeleteBucketWebsiteConfiguration(&bucketContext,
						 0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("DeleteBucketWebsiteConfiguration success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();
	

}

static void set_bvc(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];

	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: status\n");
		 usageExit(stderr);
	 }
	 const char *param = argv[optindex++];
	 const char *status = 0;
	 if (!strncmp(param, STATUS_PREFIX,STATUS_PREFIX_LEN)) {
		 const char *ad = &(param[STATUS_PREFIX_LEN]);
		 if (!strcmp(ad, "Enabled") || !strcmp(ad, "enabled")){
			 status="Enabled";
		 }else if(!strcmp(ad, "Suspended") || !strcmp(ad, "suspended")){
			 status="Suspended";
		 }
	 }else {
		 fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
		 usageExit(stderr);
	 }
	 if (optindex != argc) {
		 fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		 usageExit(stderr);
	 }	 
	 
	 S3_init();
	 
	 S3ResponseHandler responseHandler =
	 {
		 &responsePropertiesCallback, &responseCompleteCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		SetBucketVersioningConfiguration(&bucketContext,
						status, 0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("SetBucketVersioningConfiguration success .\n");
	 }
	 else {
		 printError();
	 }
	
	S3_deinitialize();
	

}

static void get_bvc(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		usageExit(stderr);
	}
	
	const char *bucketName = argv[optindex++];
	if (optindex != argc) {
		fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		usageExit(stderr);
	}
		
	S3_init();
	
	S3ResponseHandler responseHandler =
	{
		&responsePropertiesCallback, &responseCompleteCallback
	};

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

	char status[256] = {0};

	
	 do {
		GetBucketVersioningConfiguration(&bucketContext,
						sizeof(status),status,
						0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		printf("%-26s %-26s\n", "   Bucket           ","status        ");
        printf("--------------------------------------------------------  "
               "--------------------\n");
        printf("%-26s %-26s\n", bucketName,status);
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();

}

typedef struct list_versions_callback_data
{
	char bucketName[1024];
	char prefix[1024];
	char keyMarker[1024];
	char delimiter[1024];
	int maxKeys;
    int isTruncated;
    char nextKeyMarker[1024];
	char nextVersionIdMarker[1024];
    int keyCount;
    int allDetails;
} list_versions_callback_data;


static void printListVersionsHeader(int allDetails)
{
    printf("%-30s  %-20s  %-5s  %-34s", 
           "                       Key", 
           "   Last Modified", "Size" , "VersionId");
    if (allDetails) {
        printf("  %-34s  %-34s  %-12s", 
               "               ETag", 
               "                            Owner ID",
               "Display Name");
    }
    printf("\n");
    printf("-------------------------  "
           "--------------------  -----   ----------------------------------");
    if (allDetails) {
        printf("  ----------------------------------  "
               "----------------------------------"
               "---------------  ------------");
    }
    printf("\n");
}

static S3Status listVersionsCallback(int isTruncated, const char *nextKeyMarker, const char *nextVersionIdMarker,
                                   const S3ListVersions *listVersions, void *callbackData)
{
    list_versions_callback_data *data = 
        (list_versions_callback_data *) callbackData;
	
	    data->isTruncated = isTruncated;
    
    if ((!nextKeyMarker || !nextKeyMarker[0]) && listVersions->versionsCount) {
        nextKeyMarker = listVersions->versions[listVersions->versionsCount - 1].key;
    }
    if (nextKeyMarker) {
        snprintf_s(data->nextKeyMarker, sizeof(data->nextKeyMarker),  _TRUNCATE, "%s", 
                 nextKeyMarker);
    }
    else {
        data->nextKeyMarker[0] = 0;
    }
	
	if ((!nextVersionIdMarker || !nextVersionIdMarker[0]) && listVersions->versionsCount) {
        nextVersionIdMarker = listVersions->versions[listVersions->versionsCount - 1].versionId;
    }
    if (nextVersionIdMarker) {
        snprintf_s(data->nextVersionIdMarker, sizeof(data->nextVersionIdMarker), _TRUNCATE, "%s", 
                 nextVersionIdMarker);
    }
    else {
        data->nextVersionIdMarker[0] = 0;
    }
       
	if (NULL != listVersions->bucketName)
	{
		printf("Name = %s\n", listVersions->bucketName);
	}
	   
	if (NULL != listVersions->prefix)
	{
		printf("prefix = %s\n", listVersions->prefix);
	}
	if (NULL != listVersions->keyMarker)
	{
		printf("keyMarker = %s\n", listVersions->keyMarker);
	}
	if (NULL != listVersions->delimiter)
	{
		printf("delimiter = %s\n", listVersions->delimiter);
	}
	if (NULL != listVersions->maxKeys)
	{
		printf("maxKeys = %s\n", listVersions->maxKeys);
	}
			
    if (listVersions->versionsCount && !data->keyCount) {
        printListVersionsHeader(data->allDetails);
    }

    int i;
    for (i = 0; i < listVersions->versionsCount; i++) {
        const S3Version *version = &(listVersions->versions[i]);
		char timebuf[256] = {0};
        if (0) {
            time_t t = (time_t) version->lastModified;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ",
                     gmtime(&t));
            printf("\nKey: %s\n", version->key);
            printf("Last Modified: %s\n", timebuf);
            printf("ETag: %s\n", version->eTag);
            printf("Size: %llu\n", (unsigned long long) version->size);
            if (version->ownerId) {
                printf("Owner ID: %s\n", version->ownerId);
            }
            if (version->ownerDisplayName) {
                printf("Owner Display Name: %s\n", version->ownerDisplayName);
            }
        }
        else {
            time_t t = (time_t) version->lastModified;
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", 
                     gmtime(&t));
			char sizebuf[16] = {0};
            if (version->size < 100000) {
                sprintf_s(sizebuf, sizeof(sizebuf), "%5llu", (unsigned long long) version->size);
            }
            else if (version->size < (1024 * 1024)) {
                sprintf_s(sizebuf, sizeof(sizebuf), "%4lluK", 
                        ((unsigned long long) version->size) / 1024ULL);
            }
            else if (version->size < (10 * 1024 * 1024)) {
                float f = (float)version->size;
                f /= (1024 * 1024);
                sprintf_s(sizebuf, sizeof(sizebuf), "%1.2fM", f);
            }
            else if (version->size < (1024 * 1024 * 1024)) {
                sprintf_s(sizebuf, sizeof(sizebuf), "%4lluM", 
                        ((unsigned long long) version->size) / 
                        (1024ULL * 1024ULL));
            }
            else {
                float f = (float)(version->size / 1024);
                f /= (1024 * 1024);
                sprintf_s(sizebuf, sizeof(sizebuf), "%1.2fG", f);
            }
            printf("%-30s  %s  %s %s", version->key, timebuf, sizebuf, version->versionId);
            if (data->allDetails) {
                printf("  %-34s  %-64s  %-12s",
                       version->eTag, 
                       version->ownerId ? version->ownerId : "",
                       version->ownerDisplayName ? 
                       version->ownerDisplayName : "");
            }
            printf("\n");
        }
    }
	
	printf("---------------------------------------------------------------------------------\n");
	for (i=0; i<listVersions->commonPrefixesCount; i++)
	{
		printf("commonPrefix => prefix = %s\n", *(listVersions->commonPrefixes + i));
	}

    data->keyCount += listVersions->versionsCount;
    return S3StatusOK;
} 



static void list_versions(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		usageExit(stderr);
	}
	
	const char *bucketName = argv[optindex++];
	if (optindex != argc) {
		fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		usageExit(stderr);
	}

	const char *prefix = 0;
	const char *keyMarker = "k";
	const char *delimiter = "s";
	const int maxKeys = 1000;
	
	const char *version_id_marker = 0;

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ListVersionsHandler listVersionsHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &listVersionsCallback
    };
 
	list_versions_callback_data data;
	memset_s(&data, sizeof(list_versions_callback_data), 0, sizeof(list_versions_callback_data));

	data.keyCount = 0;
	data.allDetails = 1;

	do{
	data.isTruncated = 0;
    do {
        ListVersions(&bucketContext, prefix, keyMarker,
                       delimiter, maxKeys, version_id_marker,
                       0, &listVersionsHandler, &data);
    } while (S3_status_is_retryable(statusG) && should_retry());
	
	if(statusG != S3StatusOK){
		break;
		}
	}while (data.isTruncated && (!maxKeys || (data.keyCount < maxKeys)));
    if (statusG == S3StatusOK) {
		printf("ListVersions OK\n");
    }
    else {
        printError();
    }

    S3_deinitialize();

}


typedef struct list_parts_callback_data
{
    int isTruncated;
    char initiatorId[1024];
	char initiatorDisplayName[1024];
	char ownerId[1024];
	char ownerDisplayName[1024];	
	char nextPartNumberMarker[256];
	char storageClass[64];
	
    int keyCount;
    int allDetails;
}list_parts_callback_data;


static S3Status listPartsCallback(int isTruncated,
                               const char *nextPartNumberMarker,
                               const char *initiatorId,
                               const char *initiatorDisplayName,
                               const char *ownerId,
                               const char *ownerDisplayName,
                               int partsCount,
                               const S3ListParts *parts,
                               void *callbackData)
{
    
    list_parts_callback_data *data = 
        (list_parts_callback_data *) callbackData;

    data->isTruncated = isTruncated;
    
    if ((!nextPartNumberMarker || !nextPartNumberMarker[0]) && partsCount) {
        nextPartNumberMarker = parts[partsCount - 1].partNumber;
    }
    if (nextPartNumberMarker) {
        snprintf_s(data->nextPartNumberMarker, sizeof(data->nextPartNumberMarker), _TRUNCATE, "%s", 
                 nextPartNumberMarker);
    }
    else {
        data->nextPartNumberMarker[0] = 0;
    }
	
		printf("initializeId: %s\n", initiatorId);
		printf("initiatorDisplayName: %s\n",initiatorDisplayName);
		printf("ownerId: %s\n",ownerId);
		printf("ownerDisplayName: %s\n",ownerDisplayName);
		printf("IsTruncated : %d\n", isTruncated);
		printf("NextPartNumberMarker : %s\n", nextPartNumberMarker);

    int i;
    for (i = 0; i < partsCount; i++) {
        const S3ListParts *part = &(parts[i]);
		char timebuf[256] = {0};


        time_t t = (time_t) part->lastModified;
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", 
                 gmtime(&t));
        char sizebuf[16] = {0};
        if (part->size < 100000) {
            sprintf_s(sizebuf, sizeof(sizebuf), "%5llu", (unsigned long long) part->size);
        }
        else if (part->size < (1024 * 1024)) {
            sprintf_s(sizebuf, sizeof(sizebuf), "%4lluK", 
                    ((unsigned long long) part->size) / 1024ULL);
        }
        else if (part->size < (10 * 1024 * 1024)) {
            float f = (float)part->size;
            f /= (1024 * 1024);
            sprintf_s(sizebuf, sizeof(sizebuf), "%1.2fM", f);
        }
        else if (part->size < (1024 * 1024 * 1024)) {
            sprintf_s(sizebuf, sizeof(sizebuf), "%4lluM", 
                    ((unsigned long long) part->size) / 
                    (1024ULL * 1024ULL));
        }
        else {
            float f = (float)(part->size / 1024);
            f /= (1024 * 1024);
            sprintf_s(sizebuf, sizeof(sizebuf), "%1.2fG", f);
        }
	printf("-----------------------------------RESULT BEG------------------------------\n");
	printf("PartNumber : %s\n", part->partNumber);
	printf("LastModified : %s\n", timebuf);
	printf("ETag : %s\n", part->eTag);
	printf("Size : %s\n", sizebuf);
	printf("-----------------------------------RESULT END------------------------------\n");
        printf("\n");
        
    }

    data->keyCount += partsCount;


    return S3StatusOK;

}


static void list_parts(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		usageExit(stderr);
	}
	
	const char *bucketName = 0;

	const char *key = 0;
	const char *uploadId = 0;
	const char *max_parts = 0;
	const char *part_number_marker = 0;

    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, KEY_PREFIX, KEY_PREFIX_LEN)) {
            key = &(param[KEY_PREFIX_LEN]);
        }
        else if (!strncmp(param, UPLOADID_PREFIX, UPLOADID_PREFIX_LEN)) {
            uploadId = &(param[UPLOADID_PREFIX_LEN]);
        }
        else if (!bucketName) {
            bucketName = param;
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }	

    S3_init();
    
    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };

    S3ListPartsHandler listPartsHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &listPartsCallback
    };
 

	 list_parts_callback_data data;
	 memset_s(&data, sizeof(list_parts_callback_data), 0, sizeof(list_parts_callback_data));
 
	 data.keyCount = 0;
	 data.allDetails = 1;
 
	 do{
	 data.isTruncated = 0;
 do {
	 ListParts(&bucketContext, key, uploadId,
					max_parts, part_number_marker,
					0, &listPartsHandler, &data);
 } while (S3_status_is_retryable(statusG) && should_retry());
 
	 if(statusG != S3StatusOK){
			 break;
			 }
	 }while (data.isTruncated && (!max_parts || (data.keyCount < atoi(max_parts))));
 if (statusG == S3StatusOK) {
			 printf("ListParts OK\n");
 }
 else {
	 printError();
 }
 
 S3_deinitialize();
 
}

static void get_om(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
        fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
        usageExit(stderr);
    }

	// Split bucket/key
	 char *slash = argv[optindex];
	 while (*slash && (*slash != '/')) {
		 slash++;
	 }
	 if (!*slash || !*(slash + 1)) {
		 fprintf(stderr, "\nERROR: Invalid bucket/key name: %s\n",
				 argv[optindex]);
		 usageExit(stderr);
	 }
	 *slash++ = 0;
	
	 const char *bucketName = argv[optindex++];
	 const char *key = slash;

	 const char*versionId = 0;
    while (optindex < argc) {
        char *param = argv[optindex++];
        if (!strncmp(param, VERSIONID_PREFIX, VERSIONID_PREFIX_LEN)) {
            versionId = &(param[VERSIONID_PREFIX_LEN]);
        }
        else {
            fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
            usageExit(stderr);
        }
    }	

    S3_init();

    S3BucketContext bucketContext =
    {
        0,
        bucketName,
        protocolG,
        uriStyleG,
        accessKeyIdG,
        secretAccessKeyG,
		pCAInfo
    };
    S3ResponseHandler responseHandler =
    {
        &responsePropertiesCallback, &responseCompleteCallback
    };

    do {
        GetObjectMetadata(&bucketContext,key,versionId,0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
        printError();
    }

    S3_deinitialize();

}

static void set_cors(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];
	
	const char* md5 = 0;
	while (optindex < argc) {
		  char *param = argv[optindex++];
		  if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
			  md5 = &(param[MD5_PREFIX_LEN]);
		  }
		  else {
			  fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
			  usageExit(stderr);
		  }
	  }
	 const char *id = "t<abc&cc>\"abc\'";
	 //  char allowedMethod[][10],const unsigned int amNumber,
     //                 const char allowedOrigin[][256],const unsigned int aoNumber,const char allowedHeader[][256],const unsigned int ahNumber,
     //                 const char *maxAgeSeconds,const char exposeHeader[][256],const unsigned int ehNumber,

	 const char allowedMethod[][10] ={"GET","PUT","HEAD","POST","DELETE"} ;

	 unsigned int am = 5;
	const char allowedo[][256] = {"obs.huawei.com"};
	unsigned int ao = 1;
	char* max = "100";

	 S3_init();
	 
	 S3ResponseHandler responseHandler =
	 {
		 &responsePropertiesCallback, &responseCompleteCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		SetBucketCorsConfiguration(&bucketContext,id,allowedMethod,am,allowedo,ao,0,0,max,0,0,md5,0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("SetBucketCorsConfiguration success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();
	

}

static void set_cors_ex(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];
	
	const char* md5 = 0;
	while (optindex < argc) {
		  char *param = argv[optindex++];
		  if (!strncmp(param, MD5_PREFIX, MD5_PREFIX_LEN)) {
			  md5 = &(param[MD5_PREFIX_LEN]);
		  }
		  else {
			  fprintf(stderr, "\nERROR: Unknown param: %s\n", param);
			  usageExit(stderr);
		  }
	}
	
	int i = 0;
	S3BucketCorsConf bucketCorsConf[2];
	
	char id_1[10] = "1";
	const char allowedMethod_1[5][10] = {"GET","PUT","HEAD","POST","DELETE"};
	unsigned int am_1 = 5;
	const char allowedOrigin_1[2][30] = {"obs.huawei.com", "www.baidu.com"};
	unsigned int ao_1 = 2;
	const char allowedHeader_1[2][10] = {"header-1", "header-2"};
	unsigned int ah_1 = 2;
	char maxAge_1[10] = "100";
	const char exposeHeader_1[2][10] = {"hello", "world"};
	unsigned int eh_1 = 2;
	
	char id_2[10] = "2";
	const char allowedMethod_2[4][10] = {"PUT","HEAD","POST","DELETE"};
	unsigned int am_2 = 4;
	const char allowedOrigin_2[2][30] = {"obs.huawei2.com", "www.baidu2.com"};
	unsigned int ao_2 = 2;
	const char allowedHeader_2[2][10] = {"header-3", "header-4"};
	unsigned int ah_2 = 2;
	char maxAge_2[10] = "200";
	const char exposeHeader_2[2][10] = {"world", "hello"};
	unsigned int eh_2 = 2;
	
	// bucketCorsConf[0]
	bucketCorsConf[0].id = id_1;
	
	bucketCorsConf[0].allowedMethod = (const char**)malloc(sizeof(char *) * 5);
	for (i=0; i<5; i++)
	{
		bucketCorsConf[0].allowedMethod[i] = allowedMethod_1[i];
	}
	bucketCorsConf[0].amNumber = am_1;
	
	bucketCorsConf[0].allowedOrigin = (const char**)malloc(sizeof(char *) * 2);
	for (i=0; i<2; i++)
	{
		bucketCorsConf[0].allowedOrigin[i] = allowedOrigin_1[i];
	}
	bucketCorsConf[0].aoNumber = ao_1;
	
	bucketCorsConf[0].allowedHeader = (const char**)malloc(sizeof(char *) * 2);
	for (i=0; i<2; i++)
	{
		bucketCorsConf[0].allowedHeader[i] = allowedHeader_1[i];
	}
	bucketCorsConf[0].ahNumber = ah_1;
	
	bucketCorsConf[0].maxAgeSeconds = maxAge_1;
	
	bucketCorsConf[0].exposeHeader = (const char**)malloc(sizeof(char *) * 2);
	for (i=0; i<2; i++)
	{
		bucketCorsConf[0].exposeHeader[i] = exposeHeader_1[i];
	}
	bucketCorsConf[0].ehNumber = eh_1;
	
	// bucketCorsConf[1]
	bucketCorsConf[1].id = id_2;
	
	bucketCorsConf[1].allowedMethod = (const char**)malloc(sizeof(char *) * 4);
	for (i=0; i<4; i++)
	{
		bucketCorsConf[1].allowedMethod[i] = allowedMethod_2[i];
	}
	bucketCorsConf[1].amNumber = am_2;
	
	bucketCorsConf[1].allowedOrigin = (const char**)malloc(sizeof(char *) * 2);
	for (i=0; i<2; i++)
	{
		bucketCorsConf[1].allowedOrigin[i] = allowedOrigin_2[i];
	}
	bucketCorsConf[1].aoNumber = ao_2;
	
	bucketCorsConf[1].allowedHeader = (const char**)malloc(sizeof(char *) * 2);
	for (i=0; i<2; i++)
	{
		bucketCorsConf[1].allowedHeader[i] = allowedHeader_2[i];
	}
	bucketCorsConf[1].ahNumber = ah_2;
	
	bucketCorsConf[1].maxAgeSeconds = maxAge_2;
	
	bucketCorsConf[1].exposeHeader = (const char**)malloc(sizeof(char *) * 2);
	for (i=0; i<2; i++)
	{
		bucketCorsConf[1].exposeHeader[i] = exposeHeader_2[i];
	}
	bucketCorsConf[1].ehNumber = eh_2;

	 S3_init();
	 
	 S3ResponseHandler responseHandler =
	 {
		 &responsePropertiesCallback, &responseCompleteCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		SetBucketCorsConfigurationEx(&bucketContext, bucketCorsConf, 2, md5, 0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("SetBucketCorsConfiguration success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();
	

}

S3Status getBucketCorsConfigurationCallback (const char *id,
								const char *maxAgeSeconds,
								int allowedMethodCount,
								const char** allowedMethodes,
								int allowedOriginCount,
								const char** allowedOrigines,
								int allowedHeaderCount,
								const char**allowedHeaderes,
								int exposeHeaderCount,
								const char**exposeHeaderes,
								void *callbackData)
{
	(void)callbackData;
	printf("id = %s\n maxAgeSeconds = %s\n",id,maxAgeSeconds);
	int i;
	for(i = 0; i < allowedMethodCount; i++)
	{
		printf("allowedMethodes = %s\n",allowedMethodes[i]);
	}
	for(i = 0; i < allowedOriginCount; i++)
	{
		printf("allowedOrigines = %s\n",allowedOrigines[i]);
	}
	for(i = 0; i < allowedHeaderCount; i++)
	{
		printf("allowedHeaderes = %s\n",allowedHeaderes[i]);
	}
	for(i = 0; i < exposeHeaderCount; i++)
	{
		printf("exposeHeaderes = %s\n",exposeHeaderes[i]);
	}
	return S3StatusOK;
}

static void get_cors(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];
	 if (optindex != argc) {
		 fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		 usageExit(stderr);
	 }
	

	 S3_init();
	 
	 S3CORSHandler responseHandler =
	 {
		 {&responsePropertiesCallback, &responseCompleteCallback},
		 &getBucketCorsConfigurationCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		GetBucketCorsConfiguration(&bucketContext,0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("SetBucketCorsConfiguration success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();
	

}

S3Status getBucketCorsConfigurationCallbackEx (S3BucketCorsConf* bucketCorsConf,
 								unsigned int bccNumber,
								void *callbackData)
{
	(void)callbackData;
	
	unsigned int i = 0;
	for (i=0; i<bccNumber; ++i)
	{
		printf("------------------------------------------------------\n");
		printf("id = %s\nmaxAgeSeconds = %s\n", bucketCorsConf[i].id, bucketCorsConf[i].maxAgeSeconds);
		unsigned int j;
		for(j = 0; j < bucketCorsConf[i].amNumber; j++)
		{
			printf("allowedMethodes = %s\n", bucketCorsConf[i].allowedMethod[j]);
		}
		for(j = 0; j < bucketCorsConf[i].aoNumber; j++)
		{
			printf("allowedOrigines = %s\n", bucketCorsConf[i].allowedOrigin[j]);
		}
		for(j = 0; j < bucketCorsConf[i].ahNumber; j++)
		{
			printf("allowedHeaderes = %s\n", bucketCorsConf[i].allowedHeader[j]);
		}
		for(j = 0; j < bucketCorsConf[i].ehNumber; j++)
		{
			printf("exposeHeaderes = %s\n", bucketCorsConf[i].exposeHeader[j]);
		}
	}
	printf("------------------------------------------------------\n");
	return S3StatusOK;
}

static void get_cors_ex(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];
	 if (optindex != argc) {
		 fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		 usageExit(stderr);
	 }
	

	 S3_init();
	 
	 S3CORSHandlerEx responseHandlerEx =
	 {
		 {&responsePropertiesCallback, &responseCompleteCallback},
		 &getBucketCorsConfigurationCallbackEx
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		GetBucketCorsConfigurationEx(&bucketContext,0, &responseHandlerEx, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("GetBucketCorsConfigurationEx success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();
	

}

static void del_cors(int argc, char **argv, int optindex)
{
	 if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket\n");
		 usageExit(stderr);
	 }
	 
	 const char *bucketName = argv[optindex++];
	 if (optindex != argc) {
		 fprintf(stderr, "\nERROR: Extraneous parameter: %s\n", argv[optindex]);
		 usageExit(stderr);
	 }
	
	 S3_init();
	 
	 S3ResponseHandler responseHandler =
	 {
		 &responsePropertiesCallback, &responseCompleteCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	
	 do {
		DeleteBucketCorsConfiguration(&bucketContext,0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("SetBucketCorsConfiguration success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize();

}

static void optionsobject(int argc, char **argv, int optindex)
{
	if (optindex == argc) {
		 fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
		 usageExit(stderr);
	 }
	
	 const char *bucketName = argv[optindex];
	 const char *key = 0;
	
	 // Split bucket/key
	 char *slash = argv[optindex++];
	 while (*slash && (*slash != '/')) {
		 slash++;
	 }
	 if (*slash) {
		 *slash++ = 0;
		 key = slash;
	 }
	 else {
		 key = 0;
	 }
	 S3_init();
	 
	 S3ResponseHandler responseHandler =
	 {
		 &responsePropertiesCallback, &responseCompleteCallback
	 };
	
	 S3BucketContext bucketContext =
	 {
		 0,
		 bucketName,
		 protocolG,
		 uriStyleG,
		 accessKeyIdG,
		 secretAccessKeyG,
		 pCAInfo
	 };
	
	const char allowedMethod[5][256]={"GET","PUT","HEAD","POST","DELETE"};
	 unsigned int am = 5;
	char*org = "obs.huawei.com";
	 do {
		OptionsObject(&bucketContext,key,org,allowedMethod,am,0,0,0, &responseHandler, 0);
	} while (S3_status_is_retryable(statusG) && should_retry()); 
	
	 if (statusG == S3StatusOK) {
		 printf("OptionsObject success .\n");
	 }
	 else {
		 printError();
	 }
	
	
	S3_deinitialize(); 

}

static void optionsbucket(int argc, char **argv, int optindex)
{
    if (optindex == argc) {
         fprintf(stderr, "\nERROR: Missing parameter: bucket[/key]\n");
         usageExit(stderr);
     }

     const char *bucketName = argv[optindex];

     S3_init();

     S3ResponseHandler responseHandler =
     {
         &responsePropertiesCallback, &responseCompleteCallback
     };

     S3BucketContext bucketContext =
     {
         0,
         bucketName,
         protocolG,
         uriStyleG,
         accessKeyIdG,
         secretAccessKeyG,
		 pCAInfo
     };

    const char allowedMethod[][256]={"GET","PUT","HEAD","POST","DELETE"};
    const unsigned int am = 5;
    const char*org = "obs.huawei.com";
     do {
        OptionsBucket(&bucketContext,org,allowedMethod,am,NULL,0,0, &responseHandler, 0);
    } while (S3_status_is_retryable(statusG) && should_retry());

     if (statusG == S3StatusOK) {
         printf("OptionsBucket success .\n");
     }
     else {
         printError();
     }


    S3_deinitialize();

}

/*
static void setCAInfo()
{
	FILE *fp = NULL;
	int nFileLength = 0;
	int nReadSize = 0;
	
	if ((fp = fopen("client.crt", "rb")) == NULL)
	{
		fprintf(stderr, "\nWarning: Certificate file can not open or \"client.crt\" do not exist\n");
        // Usage exit
        return;
	}
	fseek(fp, 0, SEEK_END);
	nFileLength = ftell(fp);
	rewind(fp);
	pCAInfo = (char *)malloc(nFileLength * sizeof(char));
	if (pCAInfo == NULL)
	{
		fprintf(stderr, "\nError: Memory error\n");
		fclose(fp);
        // Usage exit
        usageExit(stderr);
	}
	memset(pCAInfo, 0, nFileLength * sizeof(char));
	nReadSize = fread(pCAInfo, 1, nFileLength, fp);
	if (nReadSize != nFileLength)
	{
		fprintf(stderr, "\nError: Read certificate file error\n");
		fclose(fp);
        // Usage exit
        usageExit(stderr);
	}
	fclose(fp);
}
*/

//----------------------------------------------------------------------

int main(int argc, char **argv)
{
    // Parse args
    while (1) {
        int idx = 0;
        int c = getopt_long(argc, argv, "fhusr:", longOptionsG, &idx);

        if (c == -1) {
            // End of options
            break;
        }

        switch (c) {
        case 'f':
            forceG = 1;
            break;
        case 'h':
            uriStyleG = S3UriStyleVirtualHost;
            break;
        case 'u':
            protocolG = S3ProtocolHTTP;
            break;
        case 's':
            showResponsePropertiesG = 1;
            break;
        case 'r': {
            const char *v = optarg;
            retriesG = 0;
            while (*v) {
                retriesG *= 10;
                retriesG += *v - '0';
                v++;
            }
            break;
        }
        default:
            fprintf(stderr, "\nERROR: Unknown option: -%c\n", c);
            // Usage exit
            usageExit(stderr);
        }
    }

    // The first non-option argument gives the operation to perform
    if (optind == argc) {
        fprintf(stderr, "\n\nERROR: Missing argument: command\n\n");
        usageExit(stderr);
    }

    const char *command = argv[optind++]; //lint !e52
    
    if (!strcmp(command, "help")) {
        fprintf(stdout, "\ns3 is a program for performing single requests "
                "to Huawei S3.\n");
        usageExit(stdout);
    }

    accessKeyIdG = getenv("S3_ACCESS_KEY_ID");
    if (!accessKeyIdG) {
        fprintf(stderr, "Missing environment variable: S3_ACCESS_KEY_ID\n");
        return -1;
    }
    secretAccessKeyG = getenv("S3_SECRET_ACCESS_KEY");
    if (!secretAccessKeyG) {
        fprintf(stderr, 
                "Missing environment variable: S3_SECRET_ACCESS_KEY\n");
        return -1;
    }
	
	//setCAInfo();

    if (!strcmp(command, "list")) {
        list(argc, argv, optind);
    }
    else if (!strcmp(command, "listuploads")) {
        list_uploads(argc, argv, optind);
    }
    else if (!strcmp(command, "test")) {
        test_bucket(argc, argv, optind);
    }
    else if (!strcmp(command, "getquota")) {
        get_bucketquota(argc, argv, optind);
    }
    else if (!strcmp(command, "setquota")) {
        set_bucketquota(argc, argv, optind);
    }
    else if (!strcmp(command, "setblc")) {
        set_bucketlc(argc, argv, optind);
    }
	else if (!strcmp(command, "setblc_ex")) {
        set_bucketlc_ex(argc, argv, optind);
    }
    else if (!strcmp(command, "getblc")) {
        get_bucketlc(argc, argv, optind);
    }
	else if (!strcmp(command, "getblc_ex")) {
        get_bucketlc_ex(argc, argv, optind);
    }
    else if (!strcmp(command, "delblc")) {
        del_bucketlc(argc, argv, optind);
    }
    else if (!strcmp(command, "getbucketinfo")) {
        get_bucketinfo(argc, argv, optind);
    }
    else if (!strcmp(command, "create")) {
        create_bucket(argc, argv, optind);
    }
    else if (!strcmp(command, "delete")) {
        if (optind == argc) {
            fprintf(stderr, 
                    "\nERROR: Missing parameter: bucket or bucket/key\n");
            usageExit(stderr);
        }
        char *val = argv[optind];
        int hasSlash = 0;
        while (*val) {
            if (*val++ == '/') {
                hasSlash = 1;
                break;
            }
        }
        if (hasSlash) {
            delete_object(argc, argv, optind);
        }
        else {
            delete_bucket(argc, argv, optind);
        }
    }
    else if (!strcmp(command, "put")) {
        put_object(argc, argv, optind);
    }
    else if (!strcmp(command, "copy")) {
        copy_object(argc, argv, optind);
    }
    else if (!strcmp(command, "get")) {
        get_object(argc, argv, optind);
    }
    else if (!strcmp(command, "head")) {
        head_object(argc, argv, optind);
    }
    else if (!strcmp(command, "gqs")) {
        generate_query_string(argc, argv, optind);
    }
    else if (!strcmp(command, "getacl")) {
        get_acl(argc, argv, optind);
    }
    else if (!strcmp(command, "setacl")) {
        set_acl(argc, argv, optind);
    }
	else if (!strcmp(command, "getbktacl")) {
		get_bktacl(argc, argv, optind);
	}
	else if (!strcmp(command, "setbktacl")) {
		set_bktacl(argc, argv, optind);
	}
    else if (!strcmp(command, "getlogging")) {
        get_logging(argc, argv, optind);
    }
    else if (!strcmp(command, "setlogging")) {
        set_logging(argc, argv, optind);
    }
    else if (!strcmp(command, "getbp")) {
        get_bucketp(argc, argv, optind);
    }
    else if (!strcmp(command, "setbp")) {
        set_bucketp(argc, argv, optind);
    }
    else if (!strcmp(command, "delbp")) {
        del_bucketp(argc, argv, optind);
    }
    else if (!strcmp(command, "uploadpart")) {
        upart(argc, argv, optind);
    }
    else if (!strcmp(command, "copypart")) {
        copart(argc, argv, optind);
    }
    else if (!strcmp(command, "abort")) {
        abortpart(argc, argv, optind);
    }
    else if (!strcmp(command, "initupload")) {
        initupload(argc, argv, optind);
    }
    else if (!strcmp(command, "cmu")) {
        completemu(argc, argv, optind);
    }
    else if (!strcmp(command, "setbwc")){
	set_bwc(argc, argv, optind);
    }
	else if (!strcmp(command, "getbwc")){
		get_bwc(argc, argv, optind);
	}
	else if (!strcmp(command, "delbwc")){
		del_bwc(argc, argv, optind);
	}
	else if (!strcmp(command, "setbvc")){
		set_bvc(argc, argv, optind);
	}
	else if (!strcmp(command, "getbvc")){
		get_bvc(argc, argv, optind);
	}
	else if (!strcmp(command, "listversions")){
		list_versions(argc, argv, optind);
	}
	else if (!strcmp(command, "listparts")){
		list_parts(argc, argv, optind);
	}
	else if (!strcmp(command, "gom")){
		get_om(argc, argv, optind);
	}
	else if (!strcmp(command, "setcors")){
		set_cors(argc, argv, optind);
	}
	else if (!strcmp(command, "setcors_ex")){
		set_cors_ex(argc, argv, optind);
	}
	else if (!strcmp(command, "getcors")){
		get_cors(argc, argv, optind);
	}
	else if (!strcmp(command, "getcors_ex")){
		get_cors_ex(argc, argv, optind);
	}
	else if (!strcmp(command, "delcors")){
		del_cors(argc, argv, optind);
	}
	else if (!strcmp(command, "optionso")){
		optionsobject(argc, argv, optind);
	}
	else if (!strcmp(command, "optionsb")){
		optionsbucket(argc, argv, optind);
	}
	else if (!strcmp(command, "setaclbyhead")){
		set_aclbyhead(argc, argv, optind);
	}
	else if (!strcmp(command, "setbucketaclbyhead")){
		set_bucketaclbyhead(argc, argv, optind);
	}
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return -1;
    }
	
	if (NULL != pCAInfo)
	{
		free(pCAInfo);
	}

    return 0;
}
//lint +e26 +e30 +e31 +e42 +e48 +e50 +e63 +e64 +e78 +e86 +e101 +e119 +e129 +e142 +e144 +e156 +e409 +e438 +e505 +e516 +e515 +e522 +e525 +e528 +e529 +e530 +e533 +e534 +e539 +e546 +e550 +e551 +e560 +e565 +e574 +e578 +e601