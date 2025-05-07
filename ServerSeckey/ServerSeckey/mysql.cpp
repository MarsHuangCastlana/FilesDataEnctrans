#include "mysql.h"

using namespace std;


mysql::mysql()
{
	m_mysql = NULL;
}

mysql::~mysql()
{
	if (m_mysql) {
		mysql_close(m_mysql);
	}
}

bool mysql::connectDB(std::string host, std::string user, std::string passwd, std::string database, int port)
{
	//初始化数据库
	m_mysql = mysql_init(NULL);
	if (!m_mysql) {
		std::cerr << "mysql_init() failed" << std::endl;
		return false;
	}
	//设置编码
	mysql_options(m_mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	//连接
	if (!mysql_real_connect(m_mysql, host.c_str(), user.c_str(), passwd.c_str(), database.c_str(), port, NULL, 0)) {
		//如果连接失败打印，mysql_error可以获取错误原因
		fprintf(stderr, "Failed to connect to database. Error: %s\n", mysql_error(m_mysql));
		return false;
	}
	cout << "Successfully connected to database..." << endl;
	return true;
}


int mysql::getKeyID()
{
	// 查询数据库
	// for update: 临时对数据表加锁
	string sql = "select * from KEYSN for update";
	//执行sql，参数分布是(数据库连接指针, sql语句)
	if (mysql_query(m_mysql, sql.c_str())) {
		//如果执行失败就打印
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//获取结果集
	MYSQL_RES* resSet = mysql_store_result(m_mysql);
	if (!resSet) {
		//如果结果集为空就打印
		fprintf(stderr, "Failed to mysql_store_result. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//获取结果集的第一行数据
	MYSQL_ROW row = mysql_fetch_row(resSet);
	if (!row) {
		//如果结果集为空就打印
		fprintf(stderr, "Failed to mysql_fetch_row. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//获取第一行的第一列数据
	int keyID = atoi(row[0]);
	//提交事务
	if (mysql_commit(m_mysql)) {
		//如果提交失败就打印
		fprintf(stderr, "Failed to mysql_commit. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//关闭结果集
	mysql_free_result(resSet);
	return keyID;

}


// 秘钥ID在插入的时候回自动更新, 也可以手动更新
bool mysql::updataKeyID(int keyID)
{
	// 设置自动提交
	mysql_autocommit(m_mysql, true);

	// 更新数据库
	string sql = "update KEYSN set ikeysn = " + to_string(keyID);
	//执行sql，参数分布是(数据库连接指针, sql语句)
	if (mysql_query(m_mysql, sql.c_str())) {
		//如果执行失败就打印
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}


	return true;
}

int mysql::getclientId()
{
	// 查询数据库
	// for update: 临时对数据表加锁
	string sql = "select * from clients for update";
	//执行sql，参数分布是(数据库连接指针, sql语句)
	if (mysql_query(m_mysql, sql.c_str())) {
		//如果执行失败就打印
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//获取结果集
	MYSQL_RES* resSet = mysql_store_result(m_mysql);
	if (!resSet) {
		//如果结果集为空就打印
		fprintf(stderr, "Failed to mysql_store_result. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//获取结果集的第一行数据
	MYSQL_ROW row = mysql_fetch_row(resSet);
	if (!row) {
		//如果结果集为空就打印
		fprintf(stderr, "Failed to mysql_fetch_row. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//获取第一行的第一列数据
	int keyID = atoi(row[0]);
	//提交事务
	if (mysql_commit(m_mysql)) {
		//如果提交失败就打印
		fprintf(stderr, "Failed to mysql_commit. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//关闭结果集
	mysql_free_result(resSet);
	return keyID;
}

bool mysql::updataclientId(int keyID)
{
	// 设置自动提交
	mysql_autocommit(m_mysql, true);

	// 更新数据库
	string sql = "update clients set ikeysn = " + to_string(keyID);
	//执行sql，参数分布是(数据库连接指针, sql语句)
	if (mysql_query(m_mysql, sql.c_str())) {
		//如果执行失败就打印
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}
	return true;
}

bool mysql::deleteKeyID(int keyID)
{
	// 设置自动提交
	mysql_autocommit(m_mysql, true);

	// 更新数据库
	string sql = "DELETE FROM SECKEYINFO WHERE keyid = " + to_string(keyID);
	//执行sql，参数分布是(数据库连接指针, sql语句)
	if (mysql_query(m_mysql, sql.c_str())) {
		//如果执行失败就打印
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}


	return true;
}


// 将生成的秘钥写入数据库
// 更新秘钥编号
bool mysql::writeSecKey(NodeSecKeyInfo* pNode)
{
	// 组织待插入的sql语句
	char sql[1024] = { 0 };
	sprintf(sql, "insert into SECKEYINFO(clientid, serverid, keyid, createtime, state, seckey) \
					values ('%s', '%s', %d, STR_TO_DATE('%s', '%%Y-%%m-%%d %%H:%%i:%%S') , %d, '%s') ",
		pNode->clientID, pNode->serverID, pNode->seckeyID,
		getCurTime().data(), pNode->status, pNode->seckey);
	
	// 设置自动提交
	mysql_autocommit(m_mysql, true);
	// 执行sql
	if (mysql_query(m_mysql, sql)) {
		// 如果执行失败就打印
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}
	return true;
}

void mysql::closeDB()
{
	// 关闭数据库连接
	mysql_close(m_mysql);
	cout << "数据库连接关闭..." << endl;
}



std::string mysql::getCurTime()
{
	time_t timep;
	time(&timep);
	char tmp[64];
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&timep));

	return tmp;
}