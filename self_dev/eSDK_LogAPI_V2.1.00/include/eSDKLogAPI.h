#ifndef eSDK_LOG_API_H
#define eSDK_LOG_API_H
// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� LOGMANAGER_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// LOGMANAGER_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�

#ifdef WIN32
	#ifdef eSDK_LOGAPI_EXPORTS
		#define eSDK_LOG_API __declspec(dllexport)
	#else
		#define eSDK_LOG_API __declspec(dllimport)
	#endif
#else
	#define eSDK_LOG_API __attribute__((visibility("default")))
#endif

#ifdef WIN32
	#define _STD_CALL_  __stdcall
#else
	#define _STD_CALL_
#endif


#include "eSDKLogDataType.h"


#ifdef __cplusplus
extern "C"
{
#endif

#if defined ANDROID
	/**
	 *��ʼ��
	 * 
	 *�ú�������android��ʼ������
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in] 	iniInfo		��־�����ļ�����
	 *@param[in] 	logLevel	logLevel[0]�ӿ���־����, logLevel[1]������־����, logLevel[2]������־���𣬲ο�ö��LOGLEVEL
	 *@param[in] 	logPath		��־����·�����磺D:\log\���������Ǿ���·������Ҫʹ��Ĭ����������INVALID_LOG_LEVEL
	 *@return		0	�ɹ�
	 *@return		��0	ʧ�ܣ���ο����󷵻���ö������RetCode��
	 *@attention	androidʹ�ñ�APIǰ�ȳ�ʼ����iniInfoΪ���ַ���ʱ�������setLogPropertyEx������־����
	 *@par			��
	**/
	eSDK_LOG_API int _STD_CALL_ LogInitForAndroid(const char* sdkname, const char* iniInfo, unsigned int logLevel[LOG_CATEGORY], const char* logPath);
#else
	/**
	 *��ʼ��
	 * 
	 *�ú������ڳ�ʼ������
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in] 	iniFile		��־�����ļ�·�������������ļ������磺D:\eSDKClientLogCfg.ini��
	 *@param[in] 	logLevel	logLevel[0]�ӿ���־����, logLevel[1]������־����, logLevel[2]������־���𣬲ο�ö��LOGLEVEL(�ò���Ŀǰû��Ч������־�����������ļ�Ϊ׼)
	 *@param[in] 	logPath		��־����·�����磺D:\log\���������Ǿ���·������Ҫʹ��Ĭ����������INVALID_LOG_LEVEL
	 *@return		0	�ɹ�
	 *@return		��0	ʧ�ܣ���ο����󷵻���ö������RetCode��
	 *@attention	ʹ�ñ�APIǰ�ȳ�ʼ�����ƶ��ˣ�iniFileΪ���ַ���ʱ�������setLogPropertyEx������־����
	 *@par			��
	**/
	eSDK_LOG_API int _STD_CALL_ LogInit(const char* sdkname, const char* iniFile, unsigned int logLevel[LOG_CATEGORY], const char* logPath);
#endif

	/**
	 *ȥ��ʼ��
	 * 
	 *�ú������ڽ��̲�ʹ�ñ�API��ȥ��ʼ������
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@return		0	�ɹ�
	 *@return		��0	ʧ�ܣ���ο����󷵻���ö������RetCode��
	 *@attention	��������ǰ�ȵ��ñ��ӿ�
	 *@par			��
	**/
	eSDK_LOG_API int _STD_CALL_ LogFini(const char* sdkname);

	/**
	 *�ӿ�����־info�ӿ�
	 * 
	 *�ú�������дinterface�µ�info��־
	 *
	 *@param[in]	sdkname			��д�ӿ������Ĳ�Ʒ����UC�Ľӿ���дUC������UC��IVS��TP��FusionSphere�� Storage��
	 *@param[in]	interfaceType	�ӿ����ͣ�ֵΪ1��2������1��ʶΪ����ӿڣ�2��ʶΪ����ӿ�
	 *@param[in]	protocolType	�ӿ����ͣ�ֵΪSOAP��ϸ��ParlayX����Rest��COM��Native��HTTP+XML��SMPP
	 *@param[in]	interfaceName	�ӿ�����
	 *@param[in]	sourceAddr		Դ���豸���ͻ���API��Ϊ��
	 *@param[in]	targetAddr		�޶��豸���ͻ���API��Ϊ��
	 *@param[in]	TransactionID	Ψһ��ʶ�ӿ���Ϣ�������񣬲�����ʱΪ��
	 *@param[in]	reqTime			����ʱ��
	 *@param[in]	RespTime		Ӧ��ʱ��
	 *@param[in]	resultCode		�ӿڷ��ؽ����
	 *@param[in]	params			�������Ӧ��������ʽΪ��paramname=value����,�ؼ�����Ҫ��*�滻
	 *@param[in]	...				ֱ�Ӵ�������ı�������
	 *@attention	����ǰȷ���Ѿ�����LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Interface_Info(
		const char* sdkname,
		const char* interfaceType,
		const char* protocolType,
		const char* interfaceName,
		const char* sourceAddr,
		const char* targetAddr,
		const char* TransactionID,
		const char* reqTime,
		const char* RespTime,
		const char* resultCode,
		const char* params,
		...
		);
	/**
	 *�ӿ�����־error�ӿ�
	 * 
	 *�ú�������дinterface�µ�error��־
	 *
	 *@param[in]	sdkname			��д�ӿ������Ĳ�Ʒ����UC�Ľӿ���дUC������UC��IVS��TP��FusionSphere�� Storage��
	 *@param[in]	interfaceType	�ӿ����ͣ�ֵΪ1��2������1��ʶΪ����ӿڣ�2��ʶΪ����ӿ�
	 *@param[in]	protocolType	�ӿ����ͣ�ֵΪSOAP��ϸ��ParlayX����Rest��COM��Native��HTTP+XML��SMPP
	 *@param[in]	interfaceName	�ӿ�����
	 *@param[in]	sourceAddr		Դ���豸���ͻ���API��Ϊ��
	 *@param[in]	targetAddr		�޶��豸���ͻ���API��Ϊ��
	 *@param[in]	TransactionID	Ψһ��ʶ�ӿ���Ϣ�������񣬲�����ʱΪ��
	 *@param[in]	reqTime			����ʱ��
	 *@param[in]	RespTime		Ӧ��ʱ��
	 *@param[in]	resultCode		�ӿڷ��ؽ����
	 *@param[in]	params			�������Ӧ��������ʽΪ��paramname=%d����,�ؼ�����Ҫ��*�滻
	 *@param[in]	...				ֱ�Ӵ�������ı�������
	 *@attention	����ǰȷ���Ѿ�����LogInit
	 *@par			��
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Interface_Error(
		const char* sdkname,
		const char* interfaceType,
		const char* protocolType,
		const char* interfaceName,
		const char* sourceAddr,
		const char* targetAddr,
		const char* TransactionID,
		const char* reqTime,
		const char* RespTime,
		const char* resultCode,
		const char* params,
		...
		);

	/**
	 *������ӿ�Debug�ӿ�
	 * 
	 *�ú�������дoperate�µ�Debug��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	moduleName		�ڲ�ģ�����ƣ���ʱ��Ϊ��login��config��log��version��
	 *@param[in]	userName			�����û�����
	 *@param[in]	clientFlag			�����ͻ��˱�ʶ��һ��Ϊ�ͻ���IP��
	 *@param[in]	resultCode			��������롣
	 *@param[in]	keyInfo		�ؼ�������Ϣ��
	 *									��ѯ���������Ҫ������ѯ�����ʶ�����ơ�����������ƺ�����ֵ��
	 *									�������������Ҫ�������ö����ʶ�����ơ�����������ƺ�������ֵ�;�ֵ��
	 *									�������������Ҫ���������漰�����ʶ�����ơ�
	 *									ɾ�����������Ҫ����ɾ���漰�����ʶ�����ơ�
	 *@attention	����ǰȷ���Ѿ�����LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Operate_Debug(	
		const char* sdkname,
		const char* moduleName,
		const char* userName,
		const char* clientFlag,
		const char* resultCode,
		const char* keyInfo,
		const char* params,
		...
		);

	/**
	 *������ӿ�Info�ӿ�
	 * 
	 *�ú�������дoperate�µ�Info��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	moduleName		�ڲ�ģ�����ƣ���ʱ��Ϊ��login��config��log��version��
	 *@param[in]	userName			�����û�����
	 *@param[in]	clientFlag			�����ͻ��˱�ʶ��һ��Ϊ�ͻ���IP��
	 *@param[in]	resultCode			��������롣
	 *@param[in]	keyInfo		�ؼ�������Ϣ��
	 *									��ѯ���������Ҫ������ѯ�����ʶ�����ơ�����������ƺ�����ֵ��
	 *									�������������Ҫ�������ö����ʶ�����ơ�����������ƺ�������ֵ�;�ֵ��
	 *									�������������Ҫ���������漰�����ʶ�����ơ�
	 *									ɾ�����������Ҫ����ɾ���漰�����ʶ�����ơ�
	 *@attention	����ǰ�ȵ���LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Operate_Info(
		const char* sdkname,
		const char* moduleName,
		const char* userName,
		const char* clientFlag,
		const char* resultCode,
		const char* keyInfo,
		const char* params,
		...
		);//��������־�ӿ�

	/**
	 *������ӿ�Warn�ӿ�
	 * 
	 *�ú�������дoperate�µ�Warn��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	moduleName		�ڲ�ģ�����ƣ���ʱ��Ϊ��login��config��log��version��
	 *@param[in]	userName			�����û�����
	 *@param[in]	clientFlag			�����ͻ��˱�ʶ��һ��Ϊ�ͻ���IP��
	 *@param[in]	resultCode			��������롣
	 *@param[in]	keyInfo		�ؼ�������Ϣ��
	 *									��ѯ���������Ҫ������ѯ�����ʶ�����ơ�����������ƺ�����ֵ��
	 *									�������������Ҫ�������ö����ʶ�����ơ�����������ƺ�������ֵ�;�ֵ��
	 *									�������������Ҫ���������漰�����ʶ�����ơ�
	 *									ɾ�����������Ҫ����ɾ���漰�����ʶ�����ơ�
	 *@attention	����ǰȷ���Ѿ�����LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Operate_Warn(
		const char* sdkname,
		const char* moduleName,
		const char* userName,
		const char* clientFlag,
		const char* resultCode,
		const char* keyInfo,
		const char* params,
		...
		);//��������־�ӿ�
	/**
	 *������ӿ�Error�ӿ�
	 * 
	 *�ú�������дoperate�µ�Error��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	moduleName		�ڲ�ģ�����ƣ���ʱ��Ϊ��login��config��log��version��
	 *@param[in]	userName			�����û�����
	 *@param[in]	clientFlag			�����ͻ��˱�ʶ��һ��Ϊ�ͻ���IP��
	 *@param[in]	resultCode			��������롣
	 *@param[in]	keyInfo		�ؼ�������Ϣ��
	 *									��ѯ���������Ҫ������ѯ�����ʶ�����ơ�����������ƺ�����ֵ��
	 *									�������������Ҫ�������ö����ʶ�����ơ�����������ƺ�������ֵ�;�ֵ��
	 *									�������������Ҫ���������漰�����ʶ�����ơ�
	 *									ɾ�����������Ҫ����ɾ���漰�����ʶ�����ơ�
	 *@attention	����ǰ�ȵ���LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Operate_Error(
		const char* sdkname,
		const char* moduleName,
		const char* userName,
		const char* clientFlag,
		const char* resultCode,
		const char* keyInfo,
		const char* params,
		...
		);//��������־�ӿ�

	/**
	 *������Debug�ӿ�
	 * 
	 *�ú�������дrun�µ�Debug��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	param 
	 *@attention	����ǰ�ȵ���LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Run_Debug(const char* sdkname, const char* param);//��������־�ӿ�
	/**
	 *������Info�ӿ�
	 * 
	 *�ú�������дrun�µ�Info��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	param 
	 *@attention	����ǰ�ȵ���LogInit
	 *@par			��
	 **/
	eSDK_LOG_API void _STD_CALL_ Log_Run_Info(const char* sdkname, const char* param);//��������־�ӿ�
	/**
	 *������Warn�ӿ�
	 * 
	 *�ú�������дrun�µ�Warn��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	param 
	 *@attention	����ǰ�ȵ���init
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Run_Warn(const char* sdkname, const char* param);//��������־�ӿ�
	/**
	 *������Error�ӿ�
	 * 
	 *�ú�������дrun�µ�Error��־
	 *
	 *@param[in] 	sdkname		ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in]	param 
	 *@attention	����ǰ�ȵ���LogInit
	 *@par			��
	**/
	eSDK_LOG_API void _STD_CALL_ Log_Run_Error(const char* sdkname, const char* param);//��������־�ӿ�

// �ƶ���ISV��ʼ���ӿ� modify by cwx298983 2015.12.16 Start
#if defined(ANDROID) || defined(TARGET_MAC_OS) || defined(TARGET_OS_IPHONE)

	/**
	 *������־����
	 * 
	 *��ʼ��ʱiniFile��iniInfoΪ�գ�����ô˺���������־����
	 *
	 *@param[in] 	sdkname				ʹ����־ģ��Ĳ�Ʒ���֣�ͬ�����е�Ψһ��ʾ
	 *@param[in] 	logSize				logSize[0]�ӿ���־��С��logSize[1]������־��С��logSize[2]������־��С
	 *@param[in] 	logNum				logNum[0]�ӿ���־������logNum[1]������־������logNum[2]������־����
	 *@attention	����ǰ�ȵ���LogInit
	 *@par			��
	**/
	eSDK_LOG_API int _STD_CALL_ setLogPropertyEx(const char* sdkname, unsigned int logSize[LOG_CATEGORY], unsigned int logNum[LOG_CATEGORY]);

#endif
// �ƶ���ISV��ʼ���ӿ� modify by cwx298983 2015.12.16 End

#ifdef __cplusplus
}
#endif 

#endif

