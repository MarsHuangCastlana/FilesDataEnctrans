#pragma once
#include <map>
#include <vector>
#include <chrono>
#include "TcpServer.h"
#include "Message.pb.h"
#include "mysql.h"
#include "SecKeyShm.h"
#include "AesCrypto.h"
#include "ThreadPool.h"
// 处理客户端请求
class ServerOP
{
public:
	enum KeyLen {Len16=16, Len24=24, Len32=32};
	ServerOP(string json);
	// 启动服务器
	void startServer();
	// 线程工作函数 -> 推荐使用
	static void* working(void* arg, TcpSocket* tcp);
	// 友元破坏了类的封装
	friend void* workHard(void* arg);
	// 秘钥协商
	string seckeyAgree(RequestMsg* reqMsg);
	//密匙效验
	string seckeyCheck(RequestMsg* reqMsg);
	//密匙撤销
	string seckeyZhuXiao(RequestMsg* reqMsg);
	//存储目录信息发送
	string dirInfoSend(RequestMsg* reqMsg);
	//数据接受
	string dataAccept(RequestMsg* reqMsg);
	//数据发送
	string dataSend(RequestMsg* reqMsg);
	//客户端用户名验证
	string userCheck(RequestMsg* reqMsg);

	~ServerOP();

private:
	string getRandKey(KeyLen len);

private:
	string m_serverID;	// 当前服务器的ID
	string m_dbHost;
	string m_dbUser;
	string m_dbPwd;
	string m_dbdatabase;
	unsigned int m_dbPort;
	unsigned short m_port;
	map<pthread_t, TcpSocket*> m_list;
	TcpServer *m_server = NULL;
	// 创建数据库实例对象
	mysql m_mysql;
	SecKeyShm* m_shm;
	ThreadPool* m_threadPool;
};

void* workHard(void* arg);

