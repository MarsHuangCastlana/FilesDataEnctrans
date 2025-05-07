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

	// ��ʼ�������������ݿ�
	bool connectDB(std::string host, std::string user, std::string passwd, std::string database, int port=3306);
	// �õ�keyID -> ����ʵ��ҵ�������װ��С����
	int getKeyID();
	bool updataKeyID(int keyID);
	int getclientId();
	bool updataclientId(int keyID);
	bool deleteKeyID(int keyID);
	bool writeSecKey(NodeSecKeyInfo* pNode);
	void closeDB();

private:
	// ��ȡ��ǰʱ��, ����ʽ��Ϊ�ַ���
	std::string getCurTime();

private:
	MYSQL* m_mysql;
};
