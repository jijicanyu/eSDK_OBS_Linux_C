## eSDK\_OBS\_API\_C  ##
OBS（Object Storage Service）即华为对象存储服务，是一个基于对象的海量存储服务，为客户提供海量、安全、高可靠、低成本的数据存储能力。客户可以通过REST API接口或者基于web浏览器的云管理平台界面和安装到PC的客户端对数据进行管理和使用。

OBS SDK支持OceanStor存储系统和对象存储服务OBS的业务能力开放。第三方应用程序直接调用OBS SDK中的接口即可实现获取OBS系统的业务能力。

## 版本更新 ##
eSDK OBS最新版本v2.1.00

## 开发环境 ##

- 操作系统： Linux SUSE11
- gcc 4.3以上版本

## 文件指引 ##

- src文件夹：eSDK_OBS_API_C源码
- sample文件夹：eSDK_OBS_API_C的代码样例
- doc：eSDK_OBS_API_C的接口参考、开发指南
- third_party:eSDK_OBS_API_C中使用的第三方库
- self_dev:eSDK_OBS_API_C中使用的自研库


## 入门指导 ##
编译SDK工程：

- 首先需要编译第三方开源库，依次调用third_party文件夹下的build_zlib.sh、build_openssl.sh、build_libssh2.sh、build_curl.sh、build_pcre.sh、build_libxml2.sh和build_getopt9.sh脚本，完成第三方开源库编译。
- 然后调用src文件夹下的build.sh脚本编译SDK，在src会生成OBS_API文件夹，include文件夹为SDK的头文件，lib文件夹为SDK的lib及所需要的.so文件。
- 最后build文件夹即可进行二次开发。在工程中引用lib库，然后生成的程序再使用bin的动态库即可。

编译Sample Code：

- 在sample目录下执行make完成demo编译并生成demo文件s3，然后即可使用命令行执行demo程序。



###初始化SDK###
要体验OBS系统的能力，首先要进行SDK初始化系统,以下代码演示如何初始化SDK

    编写代码
		S3Status status = S3StatusOK;
		// 域名或者IP
		const char *hostname = “xxx.xxxx.xxx”;

		// 初始化不成功获取失败原因    
    	if ((status = S3_initialize("s3", S3_INIT_ALL, hostname, AuthorizationV4, "china")) != S3StatusOK) 
		{
        	fprintf(stderr, "Failed to initialize libs3: %s\n", 
            S3_get_status_name(status));
        	exit(-1);
    	}

## 获取帮助 ##

在开发过程中，您有任何问题均可以至[DevCenter](https://devcenter.huawei.com)中提单跟踪。也可以在[华为开发者社区](http://bbs.csdn.net/forums/hwucdeveloper)中查找或提问。另外，华为技术支持热线电话：400-822-9999（转二次开发）