#pragma once
#include <iostream>
#include <string.h>
#include <time.h>
#include <string>
#include <mysql/mysql.h>
#include "SeckKeyNodeInfo.h"


class mysql
{
public:
	mysql();
	~mysql();

	// 初始化环境连接数据库
	bool connectDB(std::string host, std::string user, std::string passwd, std::string database, int port=3306);
	// 得到keyID -> 根据实际业务需求封装的小函数
	int getKeyID();
	bool updataKeyID(int keyID);
	int getclientId();
	bool updataclientId(int keyID);
	bool deleteKeyID(int keyID);
	bool writeSecKey(NodeSecKeyInfo* pNode);
	void closeDB();

private:
	// 获取当前时间, 并格式化为字符串
	std::string getCurTime();

private:
	MYSQL* m_mysql;
};
