#pragma once
#include <string>
#include <time.h>
#include "SecKeyShm.h"
#include "AesCrypto.h"
using namespace std;

struct ClientInfo
{
	string ServerID;
	string ClientID;
	string ip;
	unsigned short port;
};

class ClientOP
{
public:
	ClientOP(string jsonFile);
	~ClientOP();

	// 秘钥协商
	bool seckeyAgree();

	//密匙效验
	bool seckeyCheck();

	// 秘钥注销
	bool seckeyZhuXiao();

	//存储目录获取
	bool getStorageDir();

	//文件数据发送
	bool sendData();

	//文件数据接收
	bool recvData();


private:
	ClientInfo m_info;
	SecKeyShm* m_shm;
};

