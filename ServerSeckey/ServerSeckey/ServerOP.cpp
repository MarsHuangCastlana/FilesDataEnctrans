#include "ServerOP.h"
#include "TcpSocket.h"
#include "RequestFactory.h"
#include "RequestCodec.h"
#include "RespondCodec.h"
#include "RespondFactory.h"
#include "RsaCrypto.h"
#include <string>
#include <iostream>
#include <fstream>
#include <json/json.h>
#include <unistd.h>
#include "Hash.h"
#include <filesystem>
namespace fs = std::filesystem;
using namespace std;
using namespace Json;

/*
	{
		"Port":9898
	}
*/
ServerOP::ServerOP(string json)
{
	std::string folder_name = "ser_filestorage";  // 目标文件夹名
	fs::path dir_path = fs::current_path() / folder_name;  // 组合当前目录路径

	try {
		if (!fs::exists(dir_path)) {
			fs::create_directory(dir_path);  // 创建单层目录
			std::cout << "目录已创建: " << dir_path << std::endl;
		}
	}
	catch (const fs::filesystem_error& e) {
		std::cerr << "目录创建操作失败: " << e.what() << std::endl;
	}
	// 解析json文件, 读文件 -> Value
	ifstream ifs(json);
	Reader r;
	Value root;
	r.parse(ifs, root);
	// 将root中的键值对value值取出
	m_port = root["port"].asInt();
	m_serverID = root["serverID"].asString();
	// 数据库相关的信息
	m_dbHost=root["dbHost"].asString();
	m_dbUser = root["dbUser"].asString();
	m_dbPwd = root["dbPasswd"].asString();
	m_dbdatabase = root["dbdatabase"].asString();
	m_dbPort = root["dboort"].asInt();

	// 实例化一个连接mysql数据的对象
	m_mysql.connectDB(m_dbHost, m_dbUser, m_dbPwd, m_dbdatabase, m_dbPort);

	// 实例化共享内存对象
	// 从配置文件中读 key/pathname
	string shmKey = root["shmkey"].asString();
	int maxNode = root["maxnode"].asInt();
	// 客户端存储的秘钥只有一个
	m_shm = new SecKeyShm(shmKey, maxNode);

	m_threadPool = new ThreadPool();

}


void ServerOP::startServer()
{
	m_server = new TcpServer;
	m_server->setListen(m_port);
	while (1)
	{
		cout << "等待客户端连接..." << endl;
		TcpSocket* tcp = m_server->acceptConn();
		if (tcp == NULL)
		{
			continue;
		}
		cout << "与客户端连接成功..." << endl;
		// 通信
		//pthread_t tid;
		//// 这个回调可以是类的静态函数, 类的友元函数, 普通的函数
		//// 友元的类的朋友, 但是不属于这个类
		//// 友元函数可以访问当前类的私有成员
		//pthread_create(&tid, NULL, working, this);
		////pthread_create(&tid, NULL, workHard, this);
		//m_list.insert(make_pair(tid, tcp));
		m_threadPool->enqueue(working, this, tcp);
	}
}

void * ServerOP::working(void * arg, TcpSocket* tcp)
{
	sleep(1);
	string data = string();
	// 通过参数将传递的this对象转换
	ServerOP* op = (ServerOP*)arg;
	//// 从op中将通信的套接字对象取出
	//TcpSocket* tcp = op->m_list[pthread_self()];
	// 1. 接收客户端数据 -> 编码
	string msg = tcp->recvMsg();
	// 2. 反序列化 -> 得到原始数据 RequestMsg 类型
	CodecFactory* fac = new RequestFactory(msg);
	Codec* c = fac->createCodec();
	RequestMsg* req = (RequestMsg*)c->decodeMsg();
	// 3. 取出数据
	// 判断客户端是什么请求
	switch (req->cmdtype())
	{
	case 1:
		// 秘钥协商
		data = op->seckeyAgree(req);
		break;
	case 2:
		// 秘钥校验
		data = op->seckeyCheck(req);
		break;
	case 3:
		// 密匙撤销
		data = op->seckeyZhuXiao(req);
		break;
	case 4:
		// 接收
		data = op->dataAccept(req);
		break;
	case 5:
		// 发送
		data = op->dataSend(req);
		break;
	case 6:
		// 目录信息
		data = op->dirInfoSend(req);
		break;
	case 7:
		data = op->userCheck(req);
		break;
	default:
		break;
	}

	// 释放资源
	delete fac;
	delete c;
	// tcp对象如何处理
	tcp->sendMsg(data);
	tcp->disConnect();
	op->m_list.erase(pthread_self());
	delete tcp;

	return NULL;
}

string ServerOP::seckeyAgree(RequestMsg* reqMsg)
{
	// 0. 对签名进行校验 -> 公钥解密 -> 得到公钥
	// 将收到的公钥数据写入本地磁盘
	ofstream ofs("public.pem");
	ofs << reqMsg->data();
	ofs.close();
	// 创建非对称加密对象
	RespondInfo info;
	RsaCrypto rsa("public.pem", false);

	// 创建哈希对象
	Hash sha(T_SHA1);
	sha.addData(reqMsg->data());
	bool bl = rsa.rsaVerify(sha.result(), reqMsg->sign());
	if (bl == false)
	{
		cout << "签名校验失败..." << endl;
		info.status = false;
	}
	else
	{
		cout << "签名校验成功..." << endl;
		// 1. 生成随机字符串
		//   对称加密的秘钥, 使用对称加密算法 aes, 秘钥长度: 16, 24, 32byte
		string key = getRandKey(Len16);
		cout << "对称加密的秘钥key: " << key << endl;
		// 2. 通过公钥加密
		string seckey = rsa.rsaPubKeyEncrypt(key);

		// 3. 初始化回复的数据
		info.clientID = reqMsg->clientid();
		info.data = seckey;
		info.serverID = m_serverID;
		info.status = true;	

		// 将生成的新秘钥写入到数据库中 -> 操作 SECKEYINFO
		NodeSecKeyInfo node;
		strcpy(node.clientID, reqMsg->clientid().data());
		strcpy(node.serverID, reqMsg->serverid().data());
		strcpy(node.seckey, key.data());
		node.seckeyID = m_mysql.getKeyID();	// 秘钥的ID
		info.seckeyID = node.seckeyID;
		node.status = 1;

		// 初始化node变量
		bool bl = m_mysql.writeSecKey(&node);
		if(bl)
		{
			// 成功
			m_mysql.updataKeyID(node.seckeyID + 1);
			// 写共享内存
			m_shm->shmWrite(&node);
		}
		else
		{
			// 失败
			info.status = false;
		}
	}

	// 4. 序列化
	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();
	// 5. 发送数据
	return encMsg;
}

string ServerOP::seckeyCheck(RequestMsg* reqMsg)
{
	// 读公钥文件
	ifstream ifs("public.pem");
	stringstream str;
	str << ifs.rdbuf();
	ifs.close();

	// 创建非对称加密对象
	RespondInfo info;
	RsaCrypto rsa("public.pem", false);

	cout << "收到客户端请求: " << reqMsg->cmdtype() << endl;
	// 创建哈希对象
	Hash sha(T_SHA1);
	sha.addData(str.str());
	bool bl = rsa.rsaVerify(sha.result(), reqMsg->sign());
	if (bl == false)
	{
		cout << "签名校验失败..." << endl;
		info.status = false;
	}
	else
	{
		cout << "签名校验成功..." << endl;
		// 1. 读取共享内存中的密钥
		NodeSecKeyInfo node = m_shm->shmRead(reqMsg->clientid(), reqMsg->serverid());
		if (node.status) {
			string key = string(node.seckey);
			cout << "对称加密的秘钥key: " << key << endl;

			Hash sha256(T_SHA256);
			sha256.addData(key);
			string key256 = sha256.result();

			if (strcmp(key256.data(), reqMsg->data().data()) == 0) {
				cout << "秘钥校验成功..." << endl;
				info.status = true;
			}

		}else{
			cout << "秘钥不可用..." << endl;
			info.status = false;
		}

		// 3. 初始化回复的数据
		info.clientID = reqMsg->clientid();
		info.data = "";
		info.serverID = m_serverID;
		info.seckeyID=node.seckeyID;

	}

	// 4. 序列化
	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();
	// 5. 发送数据
	return encMsg;
}

string ServerOP::seckeyZhuXiao(RequestMsg* reqMsg)
{
	// 读公钥文件
	ifstream ifs("public.pem");
	stringstream str;
	str << ifs.rdbuf();
	ifs.close();

	// 创建非对称加密对象
	RespondInfo info;
	RsaCrypto rsa("public.pem", false);

	cout << "收到客户端请求: " << reqMsg->cmdtype() << endl;
	// 创建哈希对象
	Hash sha(T_SHA1);
	sha.addData(str.str());
	bool bl = rsa.rsaVerify(sha.result(), reqMsg->sign());
	if (bl == false)
	{
		cout << "签名校验失败..." << endl;
		info.status = true;
	}
	else
	{
		cout << "签名校验成功..." << endl;
		// 1. 读取共享内存中的密钥
		NodeSecKeyInfo node = m_shm->shmRead(reqMsg->clientid(), reqMsg->serverid());
		if (node.status) {
			string key = string(node.seckey);
			cout << "对称加密的秘钥key: " << key << endl;

			Hash sha256(T_SHA256);
			sha256.addData(key);
			string key256 = sha256.result();

			if (strcmp(key256.data(), reqMsg->data().data()) == 0) {
				cout << "秘钥校验成功..." << endl;
				info.status = false;
				// 将更改的秘钥写入到数据库中 -> 操作 SECKEYINFO
				NodeSecKeyInfo nnode;
				strcpy(nnode.clientID, reqMsg->clientid().data());
				strcpy(nnode.serverID, reqMsg->serverid().data());
				strcpy(nnode.seckey, key.data());
				nnode.seckeyID = node.seckeyID;// 秘钥的ID
				info.seckeyID = node.seckeyID;
				nnode.status = 0;

				// 初始化node变量
				bool b = m_mysql.deleteKeyID(node.seckeyID);
				if (b)
				{
					// 写共享内存
					m_shm->shmWrite(&nnode);
				}
				else
				{
					// 失败
					info.status = true;
				}
			}

		}
		else {
			cout << "秘钥不可用..." << endl;
			info.status = false;
		}

		// 3. 初始化回复的数据
		info.clientID = reqMsg->clientid();
		info.data = "";
		info.serverID = m_serverID;
	}

	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node2 = m_shm->shmRead(reqMsg->clientid(), reqMsg->serverid());
	cout << node2.status << endl;

	// 4. 序列化
	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();
	// 5. 发送数据
	return encMsg;
}

string ServerOP::dirInfoSend(RequestMsg* reqMsg)
{
	// 读公钥文件
	ifstream ifs("public.pem");
	stringstream str;
	str << ifs.rdbuf();
	ifs.close();

	// 创建非对称加密对象
	RespondInfo info;
	RsaCrypto rsa("public.pem", false);

	cout << "收到客户端请求: " << reqMsg->cmdtype() << endl;
	// 创建哈希对象
	Hash sha(T_SHA1);
	sha.addData(str.str());
	bool bl = rsa.rsaVerify(sha.result(), reqMsg->sign());
	if (bl == false)
	{
		cout << "签名校验失败..." << endl;
		info.status = false;
	}
	else
	{
		cout << "签名校验成功..." << endl;
		// 1. 读取共享内存中的密钥
		NodeSecKeyInfo node = m_shm->shmRead(reqMsg->clientid(), reqMsg->serverid());
		if (node.status) {
			string key = string(node.seckey);
			//cout << "6对称加密的秘钥: " << key << endl;
			info.seckeyID=node.seckeyID;
			// 读取文件列表
			AesCrypto aes(key);
			string fileList = "";
			fs::path dir_path = fs::current_path() / "ser_filestorage";  // 组合当前目录路径
			for (const auto& entry : fs::directory_iterator(dir_path)) {
				if (entry.is_regular_file()) {
					fileList += entry.path().filename().string() + " ";
				}
			}
			if (fileList.size() > 0) {
				info.status = true;
				info.data = aes.aesCBCEncrypt(fileList);
			}
			else {
				info.status = true;
				info.data = aes.aesCBCEncrypt("文件列表为空...");
			}
		}
		else {
			cout << "秘钥不可用..." << endl;
			info.status = false;
		}

		// 3. 初始化回复的数据
		info.clientID = reqMsg->clientid();
		info.serverID = m_serverID;
	}

	// 4. 序列化
	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();
	// 5. 发送数据
	return encMsg;
}

string ServerOP::dataAccept(RequestMsg* reqMsg)
{
	clock_t start, end;
	start = clock();  // 记录开始时间

	// 读公钥文件
	ifstream ifs("public.pem");
	stringstream str;
	str << ifs.rdbuf();
	ifs.close();

	// 创建非对称加密对象
	RespondInfo info;
	RsaCrypto rsa("public.pem", false);

	//cout << "收到客户端请求: " << reqMsg->cmdtype() << endl;
	// 创建哈希对象
	Hash sha(T_SHA1);
	sha.addData(str.str());
	bool bl = rsa.rsaVerify(sha.result(), reqMsg->sign());
	if (bl == false)
	{
		cout << "签名校验失败..." << endl;
		info.status = false;
	}
	else
	{
		cout << "签名校验成功..." << endl;
		// 1. 读取共享内存中的密钥
		NodeSecKeyInfo node = m_shm->shmRead(reqMsg->clientid(), reqMsg->serverid());
		if (node.status) {
			string key = string(node.seckey);
			//cout << "1对称加密的秘钥: " << key << endl;
			info.seckeyID=node.seckeyID;
			// 接收数据
			AesCrypto aes(key);

			if (reqMsg->data().size() > 0) {
				//cout << "接收的数据: " << endl;
				string data = aes.aesCBCDecrypt(reqMsg->data());
				//cout << data << endl;

				// 保存文件
				size_t pos = data.find_first_of(" ");
				if (pos != std::string::npos) {
					//std::cout << "指定字符集合中任意字符首次出现的位置是: " << pos << std::endl;
				}

				string fileName = data.substr(0, pos);
				data.erase(0, pos + 1);

				std::string folder_name = "ser_filestorage";  // 目标文件夹名
				fs::path dir_path = fs::current_path() / folder_name;  // 组合当前目录路径
				string filePath = dir_path.string() + "/" + fileName;
				ofstream ofs(filePath, ios::out | ios::binary);
				ofs.write(data.data(), data.size());
				ofs.close();
				info.data = "接收成功...";
				info.status = true;
			}
			else {
				info.data = "数据为空...";
				info.status = false;
			}
		}
		else {
			cout << "秘钥不可用..." << endl;
			info.data = "秘钥不可用...";
			info.status = false;
		}

		// 3. 初始化回复的数据
		info.clientID = reqMsg->clientid();
		info.serverID = m_serverID;
	}

	// 4. 序列化
	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();

	end = clock();  // 记录结束时间
	double duration = (double)(end - start) / CLOCKS_PER_SEC;
	std::cout << "程序运行时间：" << duration << " 秒" << std::endl;


	// 5. 发送数据
	return encMsg;
}

string ServerOP::dataSend(RequestMsg* reqMsg)
{
	clock_t start, end;
	start = clock();  // 记录开始时间

	// 读公钥文件
	ifstream ifs("public.pem");
	stringstream str;
	str << ifs.rdbuf();
	ifs.close();

	// 创建非对称加密对象
	RespondInfo info;
	RsaCrypto rsa("public.pem", false);

	//cout << "收到客户端请求: " << reqMsg->cmdtype() << endl;
	// 创建哈希对象
	Hash sha(T_SHA1);
	sha.addData(str.str());
	bool bl = rsa.rsaVerify(sha.result(), reqMsg->sign());
	if (bl == false)
	{
		cout << "签名校验失败..." << endl;
		info.data = "签名校验失败...";
		info.status = false;
	}
	else
	{
		cout << "签名校验成功..." << endl;
		// 1. 读取共享内存中的密钥
		NodeSecKeyInfo node = m_shm->shmRead(reqMsg->clientid(), reqMsg->serverid());
		if (node.status) {
			string key = string(node.seckey);
			//cout << "5对称加密的秘钥: " << key << endl;
			info.seckeyID=node.seckeyID;
			// 发送数据
			AesCrypto aes(key);
			string fileName = aes.aesCBCDecrypt(reqMsg->data());
			cout << "接受到的文件名: " << fileName << endl;
			// 读取文件
			fs::path dir_path = fs::current_path() / "ser_filestorage";  // 组合当前目录路径
			string filePath = dir_path.string() + "/" + fileName;
			ifstream ifss(filePath, ios::in | ios::binary);

			if (!ifss.is_open())
			{
				cout << "文件打开失败..." << endl;
				info.data = "文件打开失败/无此文件...";
				info.status = false;
				return string();
			}
			else {
				ifss.seekg(0, ios::end);
				int length = ifss.tellg();
				ifss.seekg(0, ios::beg);
				char* buffer = new char[length];
				ifss.read(buffer, length);
				ifss.close();

				info.data = aes.aesCBCEncrypt(string(buffer, ifss.gcount()));
				info.status = true;

				delete[] buffer;
				cout << "文件读取成功..." << endl;
				cout << "文件大小: " << length << "字节" << endl;
			}

		}
		else {
			cout << "秘钥不可用..." << endl;
			info.data = "秘钥不可用...";
			info.status = false;
		}

		// 3. 初始化回复的数据
		info.clientID = reqMsg->clientid();
		info.serverID = m_serverID;
	}

	// 4. 序列化
	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();

	end = clock();  // 记录结束时间
	double duration = (double)(end - start) / CLOCKS_PER_SEC;
	std::cout << "程序运行时间：" << duration << " 秒" << std::endl;


	// 5. 发送数据
	return encMsg;
}

string ServerOP::userCheck(RequestMsg* reqMsg)
{
	RespondInfo info;
	info.status = true;
	info.clientID = "";
	info.serverID = "";
	info.data = "";
	info.seckeyID = m_mysql.getclientId();
	m_mysql.updataclientId(m_mysql.getclientId() + 1);

	CodecFactory* fac = new RespondFactory(&info);
	Codec* c = fac->createCodec();
	string encMsg = c->encodeMsg();

	return encMsg;
}

ServerOP::~ServerOP()
{
	if (m_server)
	{
		delete m_server;
	}
	m_shm->delShm();
	delete m_shm;
}

// 要求: 字符串中包含: a-z, A-Z, 0-9, 特殊字符
string ServerOP::getRandKey(KeyLen len)
{
	// 设置随机数数种子 => 根据时间
	srand(time(NULL));
	int flag = 0;
	string randStr = string();
	char *cs = "~!@#$%^&*()_+}{|>?<;[]";
	for (int i = 0; i < len; ++i)
	{
		flag = rand() % 4;	// 4中字符类型
		switch (flag)
		{
		case 0:	// a-z
			randStr.append(1, 'a' + rand() % 26);
			break;
		case 1: // A-Z
			randStr.append(1, 'A' + rand() % 26);
			break;
		case 2: // 0-9
			randStr.append(1, '0' + rand() % 10);
			break;
		case 3: // 特殊字符
			randStr.append(1, cs[rand() % strlen(cs)]);
			break;
		default:
			break;
		}
	}
	return randStr;
}


void* workHard(void * arg)
{
	sleep(1);
	string data = string();
	// 通过参数将传递的this对象转换
	ServerOP* op = (ServerOP*)arg;
	// 从op中将通信的套接字对象取出
	TcpSocket* tcp = op->m_list[pthread_self()];
	// 1. 接收客户端数据 -> 编码
	string msg = tcp->recvMsg();
	// 2. 反序列化 -> 得到原始数据 RequestMsg 类型
	CodecFactory* fac = new RequestFactory(msg);
	Codec* c = fac->createCodec();
	RequestMsg* req = (RequestMsg*)c->decodeMsg();
	// 3. 取出数据
	// 判断客户端是什么请求
	switch (req->cmdtype())
	{
	case 1:
		// 秘钥协商
		data = op->seckeyAgree(req);
		break;
	case 2:
		// 秘钥校验
		data = op->seckeyCheck(req);
		break;
	case 3:
		// 密匙撤销
		data = op->seckeyZhuXiao(req);
		break;
	case 4:
		// 接收
		data = op->dataAccept(req);
		break;
	case 5:
		// 发送
		data = op->dataSend(req);
		break;
	case 6:
		// 目录信息
		data = op->dirInfoSend(req);
		break;
	case 7:
		// 用户注册
		data = op->userCheck(req);
		break;
	default:
		break;
	}

	// 释放资源
	delete fac;
	delete c;
	// tcp对象如何处理
	tcp->sendMsg(data);
	tcp->disConnect();
	op->m_list.erase(pthread_self());
	delete tcp;

	return NULL;
}
