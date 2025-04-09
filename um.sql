

-- 02 创建用户及授权
CREATE USER 'SECMNG'@'%' IDENTIFIED BY 'SECMNG';
GRANT ALL PRIVILEGES ON *.* TO 'SECMNG'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

-- 创建数据库并指定字符集
CREATE DATABASE SECMNG DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE SECMNG;

-- 创建网点密钥表
CREATE TABLE SECKEYINFO(
    clientid    CHAR(64),
    serverid    CHAR(64),
    keyid       INT(9) AUTO_INCREMENT PRIMARY KEY,
    createtime  DATE,
    state       INT(4),
    seckey      VARCHAR(512)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IX_SECKEYINFO_clientid ON SECKEYINFO(clientid);

-- 创建KEYSN表
CREATE TABLE KEYSN(
    ikeysn INT(16) PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO KEYSN(ikeysn) VALUES (1);


-- 04 创建新用户并授权
CREATE USER 'SECMNGADMIN'@'%' IDENTIFIED BY '123456';
GRANT SELECT, INSERT, UPDATE, DELETE ON SECMNG.* TO 'SECMNGADMIN'@'%';
FLUSH PRIVILEGES;
