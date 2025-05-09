#include "ClientOP.h"
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include "RequestFactory.h"
#include "RequestCodec.h"
#include "RsaCrypto.h"
#include "TcpSocket.h"
#include "RespondFactory.h"
#include "RespondCodec.h"
#include "Message.pb.h"
#include "Hash.h"
#include <filesystem>
namespace fs = std::filesystem;
using namespace std;
using namespace Json;

ClientOP::ClientOP(string jsonFile)
{
	std::string folder_name = "ser_filesget";  // 目标文件夹名
	fs::path dir_path = fs::current_path().parent_path() / folder_name;  // 组合当前目录路径

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
	ifstream ifs(jsonFile);
	Reader r;
	Value root;
	r.parse(ifs, root);
	// 将root中的键值对value值取出
	m_info.ServerID = root["serverID"].asString();
	m_info.ip = root["serverIP"].asString();
	m_info.port = root["serverPort"].asInt();

	if (root.isMember("clientID") && root["clientID"].asString().empty()) {
		cout << "请输入clientID: " << endl;
		string clientIDtmp;
		std::cin >> clientIDtmp;
		if (clientIDtmp.empty() || clientIDtmp.length() > 32) {
			std::cout << "clientID不能为空且长度不能超过32" << std::endl;
			return;
		}
		else {
			// 1. 初始化序列化数据
			// 序列化的类对象 -> 工厂类创建
			RequestInfo reqInfo;
			reqInfo.clientID = "";
			reqInfo.serverID = "";
			reqInfo.cmd = 7;	// 秘钥协商
			reqInfo.data = "";	// 非对称加密的公钥
			reqInfo.sign = "";
			CodecFactory* factory = new RequestFactory(&reqInfo);
			Codec* c = factory->createCodec();
			// 得到序列化之后的数据, 可以将其发送给服务器端
			string encstr = c->encodeMsg();
			// 释放资源
			delete factory;
			delete c;
			// 套接字通信, 当前是客户端, 连接服务器
			TcpSocket* tcp = new TcpSocket;
			// 连接服务器
			int ret = tcp->connectToHost(m_info.ip, m_info.port);
			if (ret != 0)
			{
				cout << "连接服务器失败..." << endl;
				return;
			}
			// 发送序列化的数据
			tcp->sendMsg(encstr);
			// 等待服务器回复
			string msg = tcp->recvMsg();
			// 解析服务器数据 -> 解码(反序列化)
			// 数据还原到 RespondMsg
			factory = new RespondFactory(msg);
			c = factory->createCodec();
			RespondMsg* resData = (RespondMsg*)c->decodeMsg();

			delete factory;
			delete c;
			// 这是一个短连接, 通信完成, 断开连接
			tcp->disConnect();
			delete tcp;
			clientIDtmp += std::to_string(resData->seckeyid());
		}

		root["clientID"] = clientIDtmp;
		// 保存到文件
		std::ofstream file(jsonFile);
		if (file.is_open()) {
			Json::StreamWriterBuilder writer;
			std::unique_ptr<Json::StreamWriter> json_writer(writer.newStreamWriter());
			json_writer->write(root, &file);
			file.close();
		}
		else {
			std::cerr << "json保存文件失败！" << std::endl;
			return;
		}
	}

	m_info.ClientID = root["clientID"].asString();

	// 实例化共享内存对象
	// 从配置文件中读 key/pathname
	string shmKey = root["shmKey"].asString();
	int maxNode = root["maxNode"].asInt();
	// 客户端存储的秘钥只有一个
	m_shm = new SecKeyShm(shmKey, maxNode);
}

ClientOP::~ClientOP()
{
	delete m_shm;
}

bool ClientOP::seckeyAgree()
{
	// 0. 生成密钥对, 将公钥字符串读出
	RsaCrypto rsa;
	// 生成密钥对
	rsa.generateRsakey(1024);
	// 读公钥文件
	ifstream ifs("public.pem");
	stringstream str;
	str << ifs.rdbuf();
	ifs.close();
	// 1. 初始化序列化数据
	// 序列化的类对象 -> 工厂类创建
	RequestInfo reqInfo;
	reqInfo.clientID = m_info.ClientID;
	reqInfo.serverID = m_info.ServerID;
	reqInfo.cmd = 1;	// 秘钥协商
	reqInfo.data = str.str();	// 非对称加密的公钥
	// 创建哈希对象
	Hash sha1(T_SHA1);
	sha1.addData(str.str());
	reqInfo.sign = rsa.rsaSign(sha1.result());	// 公钥的的哈希值签名
	cout << "签名完成..." << endl;
	CodecFactory* factory = new RequestFactory(&reqInfo);
	Codec* c =  factory->createCodec();
	// 得到序列化之后的数据, 可以将其发送给服务器端
	string encstr = c->encodeMsg();
	// 释放资源
	delete factory;
	delete c;

	// 套接字通信, 当前是客户端, 连接服务器
	TcpSocket* tcp = new TcpSocket;
	// 连接服务器
	int ret = tcp->connectToHost(m_info.ip, m_info.port);
	if (ret != 0)
	{
		cout << "连接服务器失败..." << endl;
		return false;
	}
	cout << "连接服务器成功..." << endl;
	// 发送序列化的数据
	tcp->sendMsg(encstr);
	// 等待服务器回复
	string msg = tcp->recvMsg();

	// 解析服务器数据 -> 解码(反序列化)
	// 数据还原到 RespondMsg
	factory = new RespondFactory(msg);
	c = factory->createCodec();
	RespondMsg* resData = (RespondMsg*)c->decodeMsg();
	cout << "服务器回复: " << resData->status() << endl;
	// 判断状态
	if (!resData->status())
	{
		cout << "秘钥协商失败" << endl;
		return false;
	}
	// 将得到的密文解密
	string key = rsa.rsaPriKeyDecrypt(resData->data());
	cout << "对称加密的秘钥key: " << key << endl;
	// 秘钥写入共享内存中
	NodeSecKeyInfo info;
	strcpy(info.clientID, m_info.ClientID.data());
	strcpy(info.serverID, m_info.ServerID.data());
	strcpy(info.seckey, key.data());
	info.seckeyID = resData->seckeyid();
	info.status = true;
	m_shm->shmWrite(&info);

	delete factory;
	delete c;
	// 这是一个短连接, 通信完成, 断开连接
	tcp->disConnect();
	delete tcp;

	return true;
}

bool ClientOP::seckeyCheck()
{
	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node = m_shm->shmRead(m_info.ClientID, m_info.ServerID);
	if (node.status == false)
	{
		cout << "密匙不可用..." << endl;
		return false;
	}
	else {
		string key = string(node.seckey);
		cout << "对称加密的秘钥key: " << key << endl;

		// 1. 初始化序列化数据
		// 序列化的类对象 -> 工厂类创建
		RequestInfo reqInfo;
		reqInfo.clientID = m_info.ClientID;
		reqInfo.serverID = m_info.ServerID;
		reqInfo.cmd = 2;	// 秘钥效验

		Hash sha256(T_SHA256);
		sha256.addData(key);
		reqInfo.data = sha256.result();	// 对称加密的秘钥的哈希值

		RsaCrypto rsa("private.pem", true);
		// 读公钥文件
		ifstream ifs("public.pem");
		stringstream str;
		str << ifs.rdbuf();
		ifs.close();
		// 创建哈希对象
		Hash sha1(T_SHA1);
		sha1.addData(str.str());
		reqInfo.sign = rsa.rsaSign(sha1.result());	// 公钥的的哈希值签名
		cout << "签名完成..." << endl;
		CodecFactory* factory = new RequestFactory(&reqInfo);
		Codec* c = factory->createCodec();
		// 得到序列化之后的数据, 可以将其发送给服务器端
		string encstr = c->encodeMsg();
		// 释放资源
		delete factory;
		delete c;

		// 套接字通信, 当前是客户端, 连接服务器
		TcpSocket* tcp = new TcpSocket;
		// 连接服务器
		int ret = tcp->connectToHost(m_info.ip, m_info.port);
		if (ret != 0)
		{
			cout << "连接服务器失败..." << endl;
			return false;
		}
		cout << "连接服务器成功..." << endl;
		// 发送序列化的数据
		tcp->sendMsg(encstr);
		// 等待服务器回复
		string msg = tcp->recvMsg();

		// 解析服务器数据 -> 解码(反序列化)
		// 数据还原到 RespondMsg
		factory = new RespondFactory(msg);
		c = factory->createCodec();
		RespondMsg* resData = (RespondMsg*)c->decodeMsg();
		cout << "服务器回复: " << resData->status() << endl;
		
		delete factory;
		delete c;
		// 这是一个短连接, 通信完成, 断开连接
		tcp->disConnect();
		delete tcp;

		// 判断状态
		if (!resData->status())
		{
			cout << "秘钥效验失败" << endl;
			return false;
		}
		// 秘钥效验成功
		cout << "秘钥效验成功" << endl;
		
	}

	return true;
}

bool  ClientOP::seckeyZhuXiao()
{
	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node = m_shm->shmRead(m_info.ClientID, m_info.ServerID);
	cout <<node.status<<endl;
	if (!node.status)
	{
		cout << "密匙不可用..." << endl;
		return false;
	}
	else {
		string key = string(node.seckey);
		cout << "对称加密的秘钥key: " << key << endl;

		// 1. 初始化序列化数据
		// 序列化的类对象 -> 工厂类创建
		RequestInfo reqInfo;
		reqInfo.clientID = m_info.ClientID;
		reqInfo.serverID = m_info.ServerID;
		reqInfo.cmd = 3;	// 秘钥撤销

		Hash sha256(T_SHA256);
		sha256.addData(key);
		reqInfo.data = sha256.result();	// 对称加密的秘钥的哈希值

		RsaCrypto rsa("private.pem", true);
		// 读公钥文件
		ifstream ifs("public.pem");
		stringstream str;
		str << ifs.rdbuf();
		ifs.close();
		// 创建哈希对象
		Hash sha1(T_SHA1);
		sha1.addData(str.str());
		reqInfo.sign = rsa.rsaSign(sha1.result());	// 公钥的的哈希值签名
		cout << "签名完成..." << endl;
		CodecFactory* factory = new RequestFactory(&reqInfo);
		Codec* c = factory->createCodec();
		// 得到序列化之后的数据, 可以将其发送给服务器端
		string encstr = c->encodeMsg();
		// 释放资源
		delete factory;
		delete c;

		// 套接字通信, 当前是客户端, 连接服务器
		TcpSocket* tcp = new TcpSocket;
		// 连接服务器
		int ret = tcp->connectToHost(m_info.ip, m_info.port);
		if (ret != 0)
		{
			cout << "连接服务器失败..." << endl;
			return false;
		}
		cout << "连接服务器成功..." << endl;
		// 发送序列化的数据
		tcp->sendMsg(encstr);
		// 等待服务器回复
		string msg = tcp->recvMsg();

		// 解析服务器数据 -> 解码(反序列化)
		// 数据还原到 RespondMsg
		factory = new RespondFactory(msg);
		c = factory->createCodec();
		RespondMsg* resData = (RespondMsg*)c->decodeMsg();
		cout << "服务器回复: " << resData->status() << endl;

		delete factory;
		delete c;
		// 这是一个短连接, 通信完成, 断开连接
		tcp->disConnect();
		delete tcp;

		// 判断状态
		if (resData->status())
		{
			cout << "秘钥撤销失败" << endl;
			return false;
		}
		// 秘钥效验成功
		cout << "秘钥撤销成功" << endl;
		// 秘钥写入共享内存中
		NodeSecKeyInfo info;
		strcpy(info.clientID, m_info.ClientID.data());
		strcpy(info.serverID, m_info.ServerID.data());
		strcpy(info.seckey, key.data());
		info.seckeyID = resData->seckeyid();
		info.status = false;
		m_shm->shmWrite(&info);
	}

	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node2 = m_shm->shmRead(m_info.ClientID, m_info.ServerID);
	cout << node2.status << endl;

	return true;
}

bool ClientOP::getStorageDir()
{
	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node = m_shm->shmRead(m_info.ClientID, m_info.ServerID);
	if (!node.status)
	{
		cout << "密匙不可用..." << endl;
		return false;
	}
	else {
		string key = string(node.seckey);
		//cout << "对称加密的秘钥key: " << key << endl;

		// 1. 初始化序列化数据
		// 序列化的类对象 -> 工厂类创建
		RequestInfo reqInfo;
		reqInfo.clientID = m_info.ClientID;
		reqInfo.serverID = m_info.ServerID;
		reqInfo.cmd = 6;	// 获取存储目录
		reqInfo.data = "";

		RsaCrypto rsa("private.pem", true);
		// 读公钥文件
		ifstream ifs("public.pem");
		stringstream str;
		str << ifs.rdbuf();
		ifs.close();
		// 创建哈希对象
		Hash sha1(T_SHA1);
		sha1.addData(str.str());
		reqInfo.sign = rsa.rsaSign(sha1.result());	// 公钥的的哈希值签名
		cout << "签名完成..." << endl;
		CodecFactory* factory = new RequestFactory(&reqInfo);
		Codec* c = factory->createCodec();
		// 得到序列化之后的数据, 可以将其发送给服务器端
		string encstr = c->encodeMsg();
		// 释放资源
		delete factory;
		delete c;

		// 套接字通信, 当前是客户端, 连接服务器
		TcpSocket* tcp = new TcpSocket;
		// 连接服务器
		int ret = tcp->connectToHost(m_info.ip, m_info.port);
		if (ret != 0)
		{
			cout << "连接服务器失败..." << endl;
			return false;
		}
		cout << "连接服务器成功..." << endl;
		// 发送序列化的数据
		tcp->sendMsg(encstr);
		// 等待服务器回复
		string msg = tcp->recvMsg();

		// 解析服务器数据 -> 解码(反序列化)
		// 数据还原到 RespondMsg
		factory = new RespondFactory(msg);
		c = factory->createCodec();
		RespondMsg* resData = (RespondMsg*)c->decodeMsg();
		// 判断状态
		if (!resData->status())
		{
			cout << "获取存储目录失败" << endl;
			return false;
		}
		// 获取存储目录成功
		cout << "获取存储目录成功" << endl;
		AesCrypto aes(key);
		cout << "存储目录: " << aes.aesCBCDecrypt(resData->data()) << endl;

		delete factory;
		delete c;
		// 这是一个短连接, 通信完成, 断开连接
		tcp->disConnect();
		delete tcp;
	}
	return true;
}

bool ClientOP::sendData()
{
	// 获取开始时间点
	clock_t start, end;
	start = clock();  // 记录开始时间

	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node = m_shm->shmRead(m_info.ClientID, m_info.ServerID);
	if (!node.status)
	{
		cout << "密匙不可用..." << endl;
		return false;
	}
	else {
		string key = string(node.seckey);
		//cout << "对称加密的秘钥: " << key << endl;
		AesCrypto aes(key);

		// 1. 初始化序列化数据
		// 序列化的类对象 -> 工厂类创建
		RequestInfo reqInfo;
		reqInfo.clientID = m_info.ClientID;
		reqInfo.serverID = m_info.ServerID;
		reqInfo.cmd = 4;	// 发送消息

		cout << "请输入要发送的（路径）文件名: ";
		string fileName;
		cin >> fileName;
		ifstream ifss(fileName, ios::binary);

		if (fileName.size() > 0) {
			size_t pos = fileName.find_last_of("/");
			if (pos != std::string::npos) {
				cout << "文件名: " << fileName.substr(pos + 1) << endl;
				fileName = fileName.substr(pos + 1);
			}else {
				cout << "文件名: " << fileName << endl;
			}
			fileName += " ";
		}
		else {
			cout << "输入为空..." << endl;
			return false;
		}

		string fileData;
		fileData += fileName;
		if (!ifss.is_open())
		{
			cout << "文件打开失败..." << endl;
			return false;
		}
		else {
			ifss.seekg(0, ios::end);
			int length = ifss.tellg();
			ifss.seekg(0, ios::beg);
			char* buffer = new char[length];
			ifss.read(buffer, length);
			ifss.close();

			fileData += string(buffer, ifss.gcount());

			reqInfo.data = aes.aesCBCEncrypt(fileData);
			delete[] buffer;
			cout << "文件读取成功..." << endl;
			cout << "文件大小: " << length << "字节" << endl;
		}


		RsaCrypto rsa("private.pem", true);
		// 读公钥文件
		ifstream ifs("public.pem");
		stringstream str;
		str << ifs.rdbuf();
		ifs.close();
		// 创建哈希对象
		Hash sha1(T_SHA1);
		sha1.addData(str.str());
		reqInfo.sign = rsa.rsaSign(sha1.result());	// 公钥的的哈希值签名
		cout << "签名完成..." << endl;

		CodecFactory* factory = new RequestFactory(&reqInfo);
		Codec* c = factory->createCodec();
		// 得到序列化之后的数据, 可以将其发送给服务器端
		string encstr = c->encodeMsg();
		// 释放资源
		delete factory;
		delete c;

		// 套接字通信, 当前是客户端, 连接服务器
		TcpSocket* tcp = new TcpSocket;
		// 连接服务器
		int ret = tcp->connectToHost(m_info.ip, m_info.port);
		if (ret != 0)
		{
			cout << "连接服务器失败..." << endl;
			return false;
		}
		cout << "连接服务器成功..." << endl;
		// 发送序列化的数据
		tcp->sendMsg(encstr);
		// 等待服务器回复
		string msg = tcp->recvMsg();

		// 解析服务器数据 -> 解码(反序列化)
		// 数据还原到 RespondMsg
		factory = new RespondFactory(msg);
		c = factory->createCodec();
		RespondMsg* resData = (RespondMsg*)c->decodeMsg();
		cout << "服务器回复: " << resData->status() << "<:>" << resData->data() << endl;

		delete factory;
		delete c;
		// 这是一个短连接, 通信完成, 断开连接
		tcp->disConnect();
		delete tcp;

		// 判断状态
		if (!resData->status())
		{
			cout << "数据发送失败" << endl;
			return false;
		}
		// 上传文件成功
		cout << "数据发送成功" << endl;
	}

	end = clock();  // 记录结束时间
	double duration = (double)(end - start) / CLOCKS_PER_SEC;
	std::cout << "程序运行时间：" << duration << " 秒" << std::endl;
	return true;	
}

bool ClientOP::recvData()
{
	clock_t start, end;
	start = clock();  // 记录开始时间

	// 1. 读取共享内存中的密钥
	NodeSecKeyInfo node = m_shm->shmRead(m_info.ClientID, m_info.ServerID);
	if (!node.status)
	{
		cout << "密匙不可用..." << endl;
	}
	else {
		string key = string(node.seckey);
		cout << "5对称加密的秘钥: " << key << endl;

		// 1. 初始化序列化数据
		// 序列化的类对象 -> 工厂类创建
		RequestInfo reqInfo;
		reqInfo.clientID = m_info.ClientID;
		reqInfo.serverID = m_info.ServerID;
		reqInfo.cmd = 5;	// 接收消息	

		AesCrypto aes(key);
		cout << "请输入要下载的文件名:" << endl;
		string fileName;
		cin >> fileName;
		if (fileName.size() > 0) {
			reqInfo.data = aes.aesCBCEncrypt(fileName);
		}
		else {
			cout << "输入为空..." << endl;
			return false;
		}

		RsaCrypto rsa("private.pem", true);
		// 读公钥文件
		ifstream ifs("public.pem");
		stringstream str;
		str << ifs.rdbuf();
		ifs.close();
		// 创建哈希对象
		Hash sha1(T_SHA1);
		sha1.addData(str.str());
		reqInfo.sign = rsa.rsaSign(sha1.result());	// 公钥的的哈希值签名
		cout << "签名完成..." << endl;

		CodecFactory* factory = new RequestFactory(&reqInfo);
		Codec* c = factory->createCodec();
		// 得到序列化之后的数据, 可以将其发送给服务器端
		string encstr = c->encodeMsg();
		// 释放资源
		delete factory;	
		delete c;

		// 套接字通信, 当前是客户端, 连接服务器
		TcpSocket* tcp = new TcpSocket;
		// 连接服务器
		int ret = tcp->connectToHost(m_info.ip, m_info.port);
		if (ret != 0)
		{
			cout << "连接服务器失败..." << endl;
			return false;
		}
		cout << "连接服务器成功..." << endl;
		// 发送序列化的数据
		tcp->sendMsg(encstr);
		// 等待服务器回复
		string msg = tcp->recvMsg();

		// 解析服务器数据 -> 解码(反序列化)
		// 数据还原到 RespondMsg
		factory = new RespondFactory(msg);
		c = factory->createCodec();
		RespondMsg* resDatas = (RespondMsg*)c->decodeMsg();

		// 判断状态
		if (!resDatas->status())
		{
			cout << "文件下载失败" << endl;
			cout << "服务器回复: " << resDatas->data() << endl;
			return false;
		}

		string Data;
		Data = aes.aesCBCDecrypt(resDatas->data());

		delete factory;
		delete c;
		// 这是一个短连接, 通信完成, 断开连接
		tcp->disConnect();
		delete tcp;


		// 保存文件

		std::string folder_name = "ser_filesget";  // 目标文件夹名
		fs::path dir_path = fs::current_path().parent_path() / folder_name;  // 组合当前目录路径
		string filePath = dir_path.string() + "/" + fileName;
		ofstream ofs(filePath, ios::out | ios::binary);
		ofs.write(Data.data(), Data.size());
		ofs.close();
		//数据接受成功
		cout << "文件下载成功" << endl;

	}

	end = clock();  // 记录结束时间
	double duration = (double)(end - start) / CLOCKS_PER_SEC;
	std::cout << "程序运行时间：" << duration << " 秒" << std::endl;

	return true;
}

string ClientOP::getClientId()
{
	return m_info.ClientID;
}

