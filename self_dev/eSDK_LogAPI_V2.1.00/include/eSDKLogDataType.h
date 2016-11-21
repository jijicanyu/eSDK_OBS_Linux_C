#ifndef DATA_TYPE_H_
#define DATA_TYPE_H_

//�ӿڷ��ش�����
enum RetCode
{
	RET_SUCCESS				=	0,
	RET_FAILED				=	1,
	RET_NotInit				=	2,
	RET_INVALID_PARA		=	3,
	RET_NULL_POINTER		=	4,
}; 

// ��־����
enum LogLevel
{
	DEBUG_LEVEL				=	0,
	INFO_LEVEL				=	1,
	WARN_LEVEL				=	2,
	ERROR_LEVEL				=	3
};

// ��־����
enum LogCategory
{
	LOG_CATEGORY_INTERFACE	= 0,
	LOG_CATEGORY_OPERATION	= 1,
	LOG_CATEGORY_RUN		= 2
};

#define LOG_CATEGORY		3
#define LOG_LEVELS          4

// �Ƿ���־����
#define INVALID_LOG_LEVEL	((unsigned int)(-1))
#define INVALID_LOG_PATH	("")

/**
	*wifi����״̬
	* 
	*���ݸûص����������wifi����״̬
	*@return		0	δ����
	*@return		��0	����
	*@attention	��wifi״̬���ϴ���־������Ҫʵ�ָýӿ�
	*@par			��
**/
typedef int (*WifiInfoCallBack)();

#endif

