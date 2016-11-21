#ifndef LOG_H_
#define LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef WIN32
#include <Windows.h>
#endif

#if defined __GNUC__ || defined LINUX
#include <time.h>
#include <sys/time.h>
#endif
#include "../../self_dev/eSDK_LogAPI_V2.1.00/include/eSDKLogAPI.h"

#if defined __GNUC__ || defined LINUX
#define PRODUCT "eSDK-OBS-API-Linux-C"
#endif

#ifdef WIN32
#define PRODUCT "eSDK-OBS-API-Windows-C"
#endif

#define OBSINIFILE   "/OBS.ini";

#if defined __GNUC__ || defined LINUX
#define MAX_MSG_SIZE 4097
#else
#define MAX_MSG_SIZE 257
#endif

#define MAX_LOG_SIZE 4096

#define CHECK_NULL_FREE(x) \
do{\
	if (NULL != x)\
	{\
	free(x);\
	x = NULL;\
	}\
}while(0)

typedef enum
{
	OBS_LOGDEBUG = 0,
	OBS_LOGINFO,
	OBS_LOGWARN,
	OBS_LOGERROR
}OBS_LOGLEVEL;

#if defined __GNUC__ || defined LINUX
typedef struct
{
	struct tm stTm;
	struct timeval tv;     /* seconds */
}SYSTEMTIME;


#define GetLocalTime(SYSTEMTIME) do			\
{												\
	time_t tm_t;								\
	time(&tm_t);								\
	(void)localtime_r(&tm_t, &(SYSTEMTIME)->stTm);	\
	(void)gettimeofday(&(SYSTEMTIME)->tv, NULL);	\
} while (0);


/**
 * Gets the complete path of the current process's loaded module files
 *
 * @param[in]	sModuleName	The aassociated module
 * @param[out]  sPath         	The complete path of the current process's loaded module files
 * @param[in]	unSize		The size of sPath
 * @return 	0		SUCCESSED
 * @return 	non-NULL	FAILED
 **/
int GetModuleFilePath(const char* sModuleName, char* sPath, unsigned int unSize);
#endif
/**
 * Gets the path 
 *
 * @param[out]	strPath		
 *
 **/
void getCurrentPath(char *strPath);

/**
 * Initialize the log Setting
 *
 * @return	0		SUCCESSED
 * @return	non-NULL	FAILED
 * @attention			Do call this function before using the log module.
 **/
int LOG_INIT();

/**
 * Uninitialize the log setting
 *
 *@return 	0		SUCCESSED
 *@return	non-NULL	FAILED
 *@ATTENTION			Do call this function before finishing the process.
 **/
void LOG_EXIT();

/**
 * Print the log
 *
 *param[in]	level		The level of the log which you want to print.
 *param[in]	pszFormat	The detail of the log which you want to print.
 *@return       0               SUCCESSED
 *@return       non-NULL        FAILED
 *@ATTENTION                    Do call this function before finishing the proce
ss.
 **/
void COMMLOG(OBS_LOGLEVEL level, const char *pszFormat, ...);
#if defined __GNUC__ || defined LINUX
void itoa(int i, char*string);
#endif
#ifdef WIN32
#define INTLOG(reqTime, rspTime, resultcode, fmt, ...) \
{\
	char strReqTime[256] = {0}; \
	char strRspTime[256] = {0}; \
	\
	sprintf_s(strReqTime, sizeof(strReqTime), "%04d-%02d-%02d %02d:%02d:%02d %03d",reqTime.wYear,reqTime.wMonth,reqTime.wDay,reqTime.wHour,reqTime.wMinute,reqTime.wSecond,reqTime.wMilliseconds); \
	sprintf_s(strRspTime, sizeof(strRspTime), "%04d-%02d-%02d %02d:%02d:%02d %03d",rspTime.wYear,rspTime.wMonth,rspTime.wDay,rspTime.wHour,rspTime.wMinute,rspTime.wSecond,rspTime.wMilliseconds); \
	\
	char strResultCode[256] = {0}; \
	(void)_itoa_s(resultcode,strResultCode, sizeof(strResultCode), 10); \
	strResultCode[255] = '\0';      \
	if(0 == resultcode)      \
	{\
		(void)Log_Interface_Info(PRODUCT, "1", "", __FUNCTION__, "", "", "", strReqTime, strRspTime, strResultCode, fmt,##__VA_ARGS__); \
	}\
	else  \
	{  \
		(void)Log_Interface_Error(PRODUCT, "1", "", __FUNCTION__, "", "", "", strReqTime, strRspTime, strResultCode, fmt,##__VA_ARGS__);  \
	}  \
}
#endif

#if defined __GNUC__ || defined LINUX
#define INTLOG(reqTime, rspTime, resultcode, fmt, ...) \
{\
       char strReqTime[256] = {0};\
	char strRspTime[256] = {0};\
	char strReqSec[32] = {0};\
       char strRspSec[32] = {0}; \
       (void)strftime(strReqTime, sizeof(strReqTime), "%Y-%m-%d %H:%M:%S", &reqTime.stTm);\
	sprintf_s(strReqSec, sizeof(strReqSec), " %03d", (int)(reqTime.tv.tv_usec) / 1000);\
	strReqSec[31] = '\0';\
	strcat_s(strReqTime, sizeof(strRspTime), strReqSec);\
	(void)strftime(strRspTime, sizeof(strRspTime), "%Y-%m-%d %H:%M:%S", &rspTime.stTm);\
	sprintf_s(strRspSec, sizeof(strReqSec), " %03d", (int)(rspTime.tv.tv_usec) / 1000);\
	strRspSec[31] = '\0';\
	strcat_s(strRspTime, sizeof(strRspTime), strRspSec);\
   \
   	char strResultCode[256] = {0}; \
	sprintf_s(strResultCode, sizeof(strResultCode), "%d", resultcode);\
	strResultCode[255] = '\0';      \
	if(0 == resultcode)      \
	{\
		(void)Log_Interface_Info(PRODUCT, "1", "", __FUNCTION__, "", "", "", strReqTime, strRspTime, strResultCode, fmt,##__VA_ARGS__); \
	}\
	else  \
	{  \
		(void)Log_Interface_Error(PRODUCT, "1", "", __FUNCTION__, "", "", "", strReqTime, strRspTime, strResultCode, fmt,##__VA_ARGS__);  \
	}  \
}
#endif



#endif
