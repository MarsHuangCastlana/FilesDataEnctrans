#include <iostream>
#include <string>
#include "ClientOP.h"
using namespace std;

int usage(string s);
int main()
{
	// 创建客户端操作类对象
	ClientOP op("clientSecKey.json");
	while (1)
	{
		int sel = usage(op.getClientId());
		switch (sel)
		{
		case 1:
			// 秘钥协商
			op.seckeyAgree();
			break;
		case 2:
			// 秘钥校验
			op.seckeyCheck();
			break;
		case 3:
			// 秘钥注销
			op.seckeyZhuXiao();
			break;
		case 4:
			// 数据发送
			op.sendData();
			break;
		case 5:
			// 数据接收
			op.recvData();
			break;
		case 6:
			//存储目录获取
			op.getStorageDir();
			break;
		case 0:
			// 退出系统
			cout << "客户端退出, bye,byte..." << endl;
			return 0;
		default:
			break;
		}
	}
	
	return 0;
}

int usage()
{
	int nSel = -1;
	printf("\n  /*************************************************************/");
	printf("\n  /*************************************************************/");
	printf("\n  /*     1.密钥协商                                            */");
	printf("\n  /*     2.密钥校验                                            */");
	printf("\n  /*     3.密钥注销                                            */");
	printf("\n  /*     4.上传文件                                            */");
	printf("\n  /*     5.下载文件                                            */");
	printf("\n  /*     6.获取存储目录                                        */");
	printf("\n  /*     0.退出系统                                            */");
	printf("\n  /*************************************************************/");
	printf("\n  /*************************************************************/");
	printf("\n\n  选择<%s>:",s.c_str());

	scanf("%d", &nSel);
	while (getchar() != '\n');

	return nSel;
}
