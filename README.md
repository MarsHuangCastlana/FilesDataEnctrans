这是基于Linux平台的文件加密传输平台，可以实现文件的加密传输。可执行文件在bin目录里。
1. 运行服务端程序需要在Linux系统安装MySQL数据库，使用命令"mysql -u root -p < um.sql"数据库内生成用户数据库以及表。
2. 运行客户端程序请修改配置文件clientSecKey.json的serverIP,将其修改为服务端程序所在主机的IP地址。
3. 其它可根据源文件自行修改编译。编译源文件需要安装Protobuf v3.20.3、jsoncpp、OpenSSL 1.1.1w,服务端需要安装Mysql数据库的客户端。
