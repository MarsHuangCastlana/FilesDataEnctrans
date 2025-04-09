#pragma once
#include <string>
#include <string.h>
#include <stdexcept>
#include <vector>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
using namespace std;

class AesCrypto
{
public:
	// 可使用 16byte, 24byte, 32byte 的秘钥
	AesCrypto(string key);
	~AesCrypto();
	// 加密
	string aesCBCEncrypt(string text);
	// 解密
	string aesCBCDecrypt(string encStr);

private:
	// base64编码
	string toBase64(const char* str, int len);
	// base64解码
	vector<unsigned char> fromBase64(string str);

private:
	AES_KEY m_encKey;
	AES_KEY m_decKey;
	string m_key;	// 秘钥
};

