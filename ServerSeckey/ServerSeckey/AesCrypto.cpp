#include "AesCrypto.h"
#include <iostream>

AesCrypto::AesCrypto(string key)
{
	if (key.size() == 16 || key.size() == 24 || key.size() == 32)
	{
		const unsigned char* aesKey = (const unsigned char*)key.data();
		AES_set_encrypt_key(aesKey, key.size() * 8, &m_encKey);
		AES_set_decrypt_key(aesKey, key.size() * 8, &m_decKey);
		m_key = key;
	}
}

AesCrypto::~AesCrypto()
{
}

string AesCrypto::aesCBCEncrypt(string text)
{
	if (text.empty()) {
		throw std::invalid_argument("Empty plaintext");
	}

	// 生成随机 IV
	unsigned char iv[AES_BLOCK_SIZE];
	RAND_bytes(iv, sizeof(iv));

	// PKCS7 填充
	size_t pad_len = AES_BLOCK_SIZE - (text.size() % AES_BLOCK_SIZE);
	std::string padded_data = text;
	padded_data.append(pad_len, static_cast<char>(pad_len));

	// 加密
	std::string ciphertext(reinterpret_cast<char*>(iv), sizeof(iv)); // 添加 IV 到密文头部
	ciphertext.resize(ciphertext.size() + padded_data.size());

	AES_cbc_encrypt(
		reinterpret_cast<const unsigned char*>(padded_data.data()),
		reinterpret_cast<unsigned char*>(&ciphertext[AES_BLOCK_SIZE]), // 跳过 IV 部分
		padded_data.size(),
		&m_encKey,
		iv,
		AES_ENCRYPT
	);

	return toBase64(ciphertext.data(), ciphertext.size());
}

string AesCrypto::aesCBCDecrypt(string encStr)
{
	if (encStr.empty()) {
		throw std::invalid_argument("Empty ciphertext");
	}

	// 解码
	std::vector<unsigned char> decoded = fromBase64(encStr);
	if (decoded.empty()) {
		throw std::invalid_argument("Invalid ciphertext");
	}

	string anc;
	anc.assign(decoded.begin(), decoded.end()); 

	if (anc.size() < AES_BLOCK_SIZE || (anc.size() % AES_BLOCK_SIZE) != 0) {
		throw std::invalid_argument("Invalid ciphertext");
	}

	// 提取 IV
	unsigned char iv[AES_BLOCK_SIZE];
	memcpy(iv, anc.data(), AES_BLOCK_SIZE);

	// 解密
	std::string decrypted_data;
	decrypted_data.resize(anc.size() - AES_BLOCK_SIZE);

	AES_cbc_encrypt(
		reinterpret_cast<const unsigned char*>(anc.data() + AES_BLOCK_SIZE),
		reinterpret_cast<unsigned char*>(&decrypted_data[0]),
		decrypted_data.size(),
		&m_decKey,
		iv,
		AES_DECRYPT
	);

	// 去除 PKCS7 填充
	size_t pad_len = static_cast<unsigned char>(decrypted_data.back());
	if (pad_len > AES_BLOCK_SIZE) {
		throw std::runtime_error("Invalid padding");
	}
	decrypted_data.resize(decrypted_data.size() - pad_len);

	return decrypted_data;
}



string AesCrypto::toBase64(const char* str, int len)
{
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* mem = BIO_new(BIO_s_mem());

	// 禁用换行符
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	// 正确链接 BIO 链：b64 -> mem
	BIO_push(b64, mem);

	// 写入数据并刷新
	BIO_write(b64, str, len);
	BIO_flush(b64);

	// 获取编码结果
	BUF_MEM* memPtr;
	BIO_get_mem_ptr(mem, &memPtr);  // 注意从 mem BIO 获取

	std::string result(memPtr->data, memPtr->length);

	// 释放资源
	BIO_free_all(b64);
	return result;
}

vector<unsigned char> AesCrypto::fromBase64(string str)
{
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* mem = BIO_new_mem_buf(str.data(), str.size());

	// 禁用换行符
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	// 链接 BIO 链：b64 -> mem
	BIO_push(b64, mem);

	// 计算解码后最大可能长度
	int maxlen = 3 * (str.size() / 4) + 2;
	std::vector<unsigned char> decoded(maxlen);

	// 读取解码数据
	int actuallen = BIO_read(b64, decoded.data(), maxlen);
	if (actuallen <= 0) {
		decoded.clear();
	}
	else {
		decoded.resize(actuallen);
	}

	// 释放资源
	BIO_free_all(b64);
	return decoded;
}
