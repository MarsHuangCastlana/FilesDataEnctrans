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
	//��ʼ�����ݿ�
	m_mysql = mysql_init(NULL);
	if (!m_mysql) {
		std::cerr << "mysql_init() failed" << std::endl;
		return false;
	}
	//���ñ���
	mysql_options(m_mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	//����
	if (!mysql_real_connect(m_mysql, host.c_str(), user.c_str(), passwd.c_str(), database.c_str(), port, NULL, 0)) {
		//�������ʧ�ܴ�ӡ��mysql_error���Ի�ȡ����ԭ��
		fprintf(stderr, "Failed to connect to database. Error: %s\n", mysql_error(m_mysql));
		return false;
	}
	cout << "Successfully connected to database..." << endl;
	return true;
}


int mysql::getKeyID()
{
	// ��ѯ���ݿ�
	// for update: ��ʱ�����ݱ����
	string sql = "select * from KEYSN for update";
	//ִ��sql�������ֲ���(���ݿ�����ָ��, sql���)
	if (mysql_query(m_mysql, sql.c_str())) {
		//���ִ��ʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//��ȡ�����
	MYSQL_RES* resSet = mysql_store_result(m_mysql);
	if (!resSet) {
		//��������Ϊ�վʹ�ӡ
		fprintf(stderr, "Failed to mysql_store_result. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//��ȡ������ĵ�һ������
	MYSQL_ROW row = mysql_fetch_row(resSet);
	if (!row) {
		//��������Ϊ�վʹ�ӡ
		fprintf(stderr, "Failed to mysql_fetch_row. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//��ȡ��һ�еĵ�һ������
	int keyID = atoi(row[0]);
	//�ύ����
	if (mysql_commit(m_mysql)) {
		//����ύʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_commit. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//�رս����
	mysql_free_result(resSet);
	return keyID;

}


// ��ԿID�ڲ����ʱ����Զ�����, Ҳ�����ֶ�����
bool mysql::updataKeyID(int keyID)
{
	// �����Զ��ύ
	mysql_autocommit(m_mysql, true);

	// �������ݿ�
	string sql = "update KEYSN set ikeysn = " + to_string(keyID);
	//ִ��sql�������ֲ���(���ݿ�����ָ��, sql���)
	if (mysql_query(m_mysql, sql.c_str())) {
		//���ִ��ʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}


	return true;
}

int mysql::getclientId()
{
	// ��ѯ���ݿ�
	// for update: ��ʱ�����ݱ����
	string sql = "select * from clients for update";
	//ִ��sql�������ֲ���(���ݿ�����ָ��, sql���)
	if (mysql_query(m_mysql, sql.c_str())) {
		//���ִ��ʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//��ȡ�����
	MYSQL_RES* resSet = mysql_store_result(m_mysql);
	if (!resSet) {
		//��������Ϊ�վʹ�ӡ
		fprintf(stderr, "Failed to mysql_store_result. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//��ȡ������ĵ�һ������
	MYSQL_ROW row = mysql_fetch_row(resSet);
	if (!row) {
		//��������Ϊ�վʹ�ӡ
		fprintf(stderr, "Failed to mysql_fetch_row. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//��ȡ��һ�еĵ�һ������
	int keyID = atoi(row[0]);
	//�ύ����
	if (mysql_commit(m_mysql)) {
		//����ύʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_commit. Error: %s\n", mysql_error(m_mysql));
		return -1;
	}
	//�رս����
	mysql_free_result(resSet);
	return keyID;
}

bool mysql::updataclientId(int keyID)
{
	// �����Զ��ύ
	mysql_autocommit(m_mysql, true);

	// �������ݿ�
	string sql = "update clients set ikeysn = " + to_string(keyID);
	//ִ��sql�������ֲ���(���ݿ�����ָ��, sql���)
	if (mysql_query(m_mysql, sql.c_str())) {
		//���ִ��ʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}
	return true;
}

bool mysql::deleteKeyID(int keyID)
{
	// �����Զ��ύ
	mysql_autocommit(m_mysql, true);

	// �������ݿ�
	string sql = "DELETE FROM SECKEYINFO WHERE keyid = " + to_string(keyID);
	//ִ��sql�������ֲ���(���ݿ�����ָ��, sql���)
	if (mysql_query(m_mysql, sql.c_str())) {
		//���ִ��ʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}


	return true;
}


// �����ɵ���Կд�����ݿ�
// ������Կ���
bool mysql::writeSecKey(NodeSecKeyInfo* pNode)
{
	// ��֯�������sql���
	char sql[1024] = { 0 };
	sprintf(sql, "insert into SECKEYINFO(clientid, serverid, keyid, createtime, state, seckey) \
					values ('%s', '%s', %d, STR_TO_DATE('%s', '%%Y-%%m-%%d %%H:%%i:%%S') , %d, '%s') ",
		pNode->clientID, pNode->serverID, pNode->seckeyID,
		getCurTime().data(), pNode->status, pNode->seckey);
	
	// �����Զ��ύ
	mysql_autocommit(m_mysql, true);
	// ִ��sql
	if (mysql_query(m_mysql, sql)) {
		// ���ִ��ʧ�ܾʹ�ӡ
		fprintf(stderr, "Failed to mysql_query. Error: %s\n", mysql_error(m_mysql));
		return false;
	}
	return true;
}

void mysql::closeDB()
{
	// �ر����ݿ�����
	mysql_close(m_mysql);
	cout << "���ݿ����ӹر�..." << endl;
}



std::string mysql::getCurTime()
{
	time_t timep;
	time(&timep);
	char tmp[64];
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&timep));

	return tmp;
}