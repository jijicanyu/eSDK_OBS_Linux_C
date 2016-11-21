#include "log.h"
#include "securec.h"
#include <stdlib.h>

#define SECTION_PATH	"LogPath"
#define PATH_VALUE		"LogPath"

#ifdef WIN32
# pragma warning (disable:4127)
#endif
//lint -e26 -e31 -e63 -e64 -e78 -e101 -e119 -e129 -e144 -e156 -e438 -e505 -e515 -e516 -e522 -e529 -e530 -e533 -e534 -e546 -e551 -e578 -e601
#if defined __GNUC__ || defined LINUX
int GetModuleFilePath(const char* sModuleName, char* sPath, unsigned int unSize)
{
	int iRet = -1;
	char sLine[1024] = {0};
	FILE *fp = NULL;
	char *pTmpFullDir = NULL;
	char *pTmpModuleDir = NULL;

	fp = fopen ("/proc/self/maps", "r");
	if (NULL == fp)
	{
		return iRet;
	}
	while (0 == feof(fp))
	{
		if (NULL == fgets(sLine, sizeof(sLine), fp))											
		{
			continue;
		}
		pTmpFullDir = strchr(sLine, '/');
		if (NULL == strstr(sLine, "r-xp") ||  NULL == pTmpFullDir || NULL == strstr(sLine, sModuleName))
		{
			continue;
		}
		//
		pTmpModuleDir = strrchr(pTmpFullDir, '/');   
		if (pTmpModuleDir == pTmpFullDir)
		{	
			break;		
		}
		*pTmpModuleDir = '\0';
		if (strlen(pTmpFullDir) >= unSize)					
		{				
			break;	
		}										
		iRet = 0;
		strncpy_s(sPath, unSize, pTmpFullDir, strlen(pTmpFullDir) + 1);		//add sizeof by jwx329074 2016.11.07
		break;																									
	}
	fclose(fp);
	return iRet;
}

void getCurrentPath(char *strPath)
{
	const char separator = '/';
	char buf[1024] = {0};
	int nRet = -1;
	nRet = GetModuleFilePath("libeSDKLogAPI.so", buf, sizeof(buf));
	if(0 != nRet)
	{
		// print log;
		return ;
	}

	strcat_s(buf, sizeof(buf), "/");
	char* pch = strrchr(buf, separator);
	if(NULL == pch)
	{
		return ;
	}
	if(pch == buf)
	{
		return ;
	}
	*pch = '\0';
	strcpy_s(strPath, MAX_MSG_SIZE, buf);  //add sizeof by jwx329074 2016.11.07
	return ;
}
#endif

void GetIniSectionItem(const char* Section, const char* Item, const char* FileName, char* iniValue)
{
	char* tchValue = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == tchValue)
	{
		return;
	}
	memset_s(tchValue, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

	char* linebuf = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == linebuf)
	{
		CHECK_NULL_FREE(tchValue);
		return;
	}
	memset_s(linebuf, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

	char* iniItem = NULL;
	char Sect[30] = {0};
	char posChar = ' ';
	int tempFgetc = 0;
	FILE* inifp = NULL;
	memcpy_s(Sect, sizeof(Sect), "[", sizeof("["));
	strcat_s(Sect, sizeof(Sect), Section);
	strcat_s(Sect, sizeof(Sect), "]");
	inifp = fopen(FileName, "rb");
	if(NULL == inifp)
	{
		CHECK_NULL_FREE(tchValue);
		CHECK_NULL_FREE(linebuf);
		return ;
	}
	while( (tempFgetc = fgetc(inifp)) != EOF) //zwx367245 2016.10.08 ��ת��Ϊ�����Ĳ������ŵ��ַ����������ŵ��ַ�ʱ�������޷��� EOF ������ֵ������char��EOF���Ƚ�
	{
		posChar = (char)tempFgetc;

		if('[' == posChar)
		{
			ungetc(posChar, inifp);
			if(NULL != fgets(linebuf,MAX_MSG_SIZE, inifp))
			{
				if(strstr(linebuf, Sect))
				{
					int temp_fgetc = fgetc(inifp);
					posChar = (char)temp_fgetc;

					while(posChar != '[' && temp_fgetc != EOF)
					{
						ungetc(posChar, inifp);
						if(NULL != fgets(linebuf, MAX_MSG_SIZE, inifp))
						{
							if(strstr(linebuf, Item))
							{
								if((iniItem= strchr(linebuf, '=')) != NULL)
								{
									iniItem++;
									fclose(inifp);
									if((*iniItem) == '\n')
									{
										CHECK_NULL_FREE(tchValue);
										CHECK_NULL_FREE(linebuf);
										return ;
									}
									unsigned int i = 0;
									while (i < strlen(iniItem)) //lint !e574
									{
										if ('\n' == iniItem[i] || '\r' == iniItem[i])
										{
											iniItem[i] = '\0';
											break;
										}
										else
										{
											i++;
										}
									}
									memcpy_s(tchValue, sizeof(char)*MAX_MSG_SIZE, iniItem, strlen(iniItem));
									memcpy_s(iniValue, sizeof(char)*MAX_MSG_SIZE, tchValue, strlen(tchValue));
									CHECK_NULL_FREE(tchValue);
									CHECK_NULL_FREE(linebuf);
									return ;
								}
							}
						}
					}
					if(EOF == fgetc(inifp)) //zwx367245 2016.10.19 avoid comparing char with EOF
					{
						break;
					}
					ungetc(posChar, inifp);
				}
			}
		}
		else
		{
			ungetc(posChar, inifp);
			if(NULL == fgets(linebuf, MAX_MSG_SIZE, inifp))   //zwx367245 2016.10.08 ��fgets�ķ���ֵ���жϣ�����Ϊlinebufʱ�ɹ�������NULLʧ��
			{
				fclose(inifp);

				CHECK_NULL_FREE(tchValue);
				CHECK_NULL_FREE(linebuf);
				return ;
			}
		}
	}
	fclose(inifp);

	CHECK_NULL_FREE(tchValue);
	CHECK_NULL_FREE(linebuf);
	return ;
}
#if defined __GNUC__ || defined LINUX
void itoa(int i, char*string)
{
	int power;
	int j;

	j=i;
	for(power=1; j>=10; j /= 10)
	{
		power*=10;
	}

	for(;power>0;power/=10)
	{
		*string++= '0' + i/power;
		i%=power;
	}

	*string='\0';
}
#endif

int LOG_INIT()
{
	unsigned int logLevel[LOG_CATEGORY] = {INVALID_LOG_LEVEL, 
		INVALID_LOG_LEVEL,
		INVALID_LOG_LEVEL };
	// ��ȡ��־��̬��.so��λ�ã�������־�����ļ�����־��һ��
	// �����൱�ڻ�ȡ����־�����ļ���λ��
	char* buf = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == buf)
	{
		return -1;
	}
	memset_s(buf, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

	char* confPath = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == confPath)
	{
		CHECK_NULL_FREE(buf);
		return -1;
	}
	memset_s(confPath, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

	char* logPath = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == logPath)
	{
		CHECK_NULL_FREE(buf);
		CHECK_NULL_FREE(confPath);
		return -1;
	}
	memset_s(logPath, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

	char* tempLogPath = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == tempLogPath)
	{
		CHECK_NULL_FREE(buf);
		CHECK_NULL_FREE(confPath);
		CHECK_NULL_FREE(logPath);
		return -1;
	}
	memset_s(tempLogPath, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

#if defined __GNUC__ || defined LINUX
	getCurrentPath(buf);

	// �����ļ��ľ���·��
	memcpy_s(confPath, sizeof(char)*MAX_MSG_SIZE, buf, MAX_MSG_SIZE);
	strcat_s(confPath, sizeof(char)*MAX_MSG_SIZE, "/OBS.ini");

	// ���������ļ���ȡ����־����������ļ���·��
	GetIniSectionItem(SECTION_PATH, PATH_VALUE, confPath, tempLogPath);
	tempLogPath[MAX_MSG_SIZE - 1] = '\0';
	memcpy_s(logPath, sizeof(char)*MAX_MSG_SIZE, buf, MAX_MSG_SIZE);

	// Ϊ�˷�ֹ��־�����ļ���·�������ӡ�/��������·���Ƿ����ڴ˼��ϡ�/����
	strcat_s(logPath, sizeof(char)*MAX_MSG_SIZE, "/");
	if(0 != strlen(tempLogPath))
	{	
		// ����������ļ��л�ȡ������·��
		strcat_s(logPath, sizeof(char)*MAX_MSG_SIZE, tempLogPath);
	}
	else
	{
		// ��������ļ���δ��ȡ������·�������������ļ�����Ŀ¼������logs,�����־
		strcat_s(logPath, sizeof(char)*MAX_MSG_SIZE, "logs");
	}
#else
	GetModuleFileNameA(NULL,buf,MAX_MSG_SIZE-1);

	char* currentPath = (char*)malloc(sizeof(char)*MAX_MSG_SIZE);
	if (NULL == currentPath)
	{
		CHECK_NULL_FREE(buf);
		CHECK_NULL_FREE(confPath);
		CHECK_NULL_FREE(logPath);
		CHECK_NULL_FREE(tempLogPath);
		return -1;
	}
	memset_s(currentPath, sizeof(char)*MAX_MSG_SIZE, 0, MAX_MSG_SIZE*sizeof(char));

	memcpy_s(currentPath, sizeof(char)*MAX_MSG_SIZE, buf, MAX_MSG_SIZE);
	//*(strrchr(currentPath, '\\') + 1) = '\0';
	//zwx367245 2016.10.08 ��strrchr�����ķ���ֵ���ж�
	if(NULL != strrchr(currentPath, '\\')){ 
		*(strrchr(currentPath, '\\') + 1) = '\0'; //lint !e613
	}
	memcpy_s(logPath, sizeof(char)*MAX_MSG_SIZE, currentPath, MAX_MSG_SIZE);
	memcpy_s(confPath, sizeof(char)*MAX_MSG_SIZE, currentPath, MAX_MSG_SIZE);
	strcat_s(confPath, sizeof(char)*MAX_MSG_SIZE, "OBS.ini");

	// ���������ļ���ȡ����־����������ļ���·��
	GetIniSectionItem(SECTION_PATH, PATH_VALUE, confPath, tempLogPath);
	tempLogPath[MAX_MSG_SIZE - 1] = '\0';

	// Ϊ�˷�ֹ��־�����ļ���·�������ӡ�\��������·���Ƿ����ڴ˼��ϡ�\����
	//strcat(logPath, "\\");
	if(0 != strlen(tempLogPath))
	{	
		// ����������ļ��л�ȡ������·��
		strcat_s(logPath, sizeof(char)*MAX_MSG_SIZE, tempLogPath);
	}
	else
	{
		// ��������ļ���δ��ȡ������·�������������ļ�����Ŀ¼������logs,�����־
		strcat_s(logPath, sizeof(char)*MAX_MSG_SIZE, "logs");
	}
	CHECK_NULL_FREE(currentPath);

#endif

	int iRet = LogInit(PRODUCT, confPath, logLevel, logPath);
	CHECK_NULL_FREE(buf);
	CHECK_NULL_FREE(confPath);
	CHECK_NULL_FREE(logPath);
	CHECK_NULL_FREE(tempLogPath);

	if(iRet)
	{
		return -1;
	}
	return 0;
}

void LOG_EXIT()
{
	LogFini(PRODUCT);
	return ;
}

void COMMLOG(OBS_LOGLEVEL level, const char *pszFormat, ...)
{
	va_list pszArgp;
	const char *tempFormat = pszFormat;//���ⲿ������м�� by jwx329074 2016.10.10
	if (NULL == tempFormat)
	{
		return;
	}
	va_start(pszArgp, pszFormat);
	char acMsg[MAX_LOG_SIZE] = {0};
	vsnprintf_s(acMsg, sizeof(acMsg), MAX_LOG_SIZE - 1, pszFormat, pszArgp);
	va_end(pszArgp);

	if(level == OBS_LOGDEBUG)
	{
		(void)Log_Run_Debug(PRODUCT,acMsg);
	}
	else if(level == OBS_LOGINFO)
	{
		(void)Log_Run_Info(PRODUCT,acMsg);
	}
	else if(level == OBS_LOGWARN)
	{
		(void)Log_Run_Warn(PRODUCT,acMsg);
	}
	else if(level == OBS_LOGERROR)
	{
		(void)Log_Run_Error(PRODUCT,acMsg);
	}	
}
//lint +e26 +e31 +e63 +e64 +e78 +e101 +e119 +e129 +e144 +e156 +e438 +e505 +e516 +e515 +e522 +e529 +e530 +e533 +e534 +e546 +e551 +e578 +e601


