#include "TcpServer.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

TcpServer::TcpServer()
{
}

TcpServer::~TcpServer()
{
	closefd();
}

int TcpServer::setListen(unsigned short port)
{
	std::lock_guard<std::mutex> lock(m_mutex); // 自动加锁

	int ret = 0;
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// 创建监听的套接字
	m_lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (m_lfd == -1)
	{
		ret = errno;
		return ret;
	}

	int on = 1;
	// 设置端口复用
	ret = setsockopt(m_lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (ret == -1)
	{
		ret = errno;
		return ret;
	}

	// 监听的套接字绑定本地IP和端口
	ret = bind(m_lfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if (ret == -1)
	{
		ret = errno;
		return ret;
	}

	ret = listen(m_lfd, 128);
	if (ret == -1)
	{
		ret = errno;
		return ret;
	}

	return ret;
}

TcpSocket* TcpServer::acceptConn(int wait_seconds)
{
	std::unique_lock<std::mutex> lock(m_mutex); // 手动加锁

	if (m_lfd == -1) { // 检查套接字有效性
		return nullptr;
	}

	int ret;
	if (wait_seconds > 0)
	{
		fd_set accept_fdset;
		struct timeval timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(m_lfd, &accept_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do
		{
			// 检测读集合
			ret = select(m_lfd + 1, &accept_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);	// 被信号中断, 再次进入循环
		if (ret <= 0)
		{
			return NULL;
		}
	}

	// 一但检测出 有select事件发生，表示对等方完成了三次握手，客户端有新连接建立
	// 此时再调用accept将不会堵塞
	struct sockaddr_in addrCli;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int connfd = accept(m_lfd, (struct sockaddr*)&addrCli, &addrlen); //返回已连接套接字
	if (connfd == -1)
	{
		return NULL;
	}

	lock.unlock(); // 操作完成后立即解锁

	return (connfd == -1) ? nullptr : new TcpSocket(connfd);
}

void TcpServer::closefd()
{
	std::lock_guard<std::mutex> lock(m_mutex); // 自动加锁

	if (m_lfd != -1) {
		close(m_lfd);
		m_lfd = -1; // 标记为无效状态
	}
}