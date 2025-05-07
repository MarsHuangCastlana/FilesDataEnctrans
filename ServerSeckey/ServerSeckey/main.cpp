#include <cstdio>
#include "ServerOP.h"

int main()
{
	ServerOP op("serverSecKey.json");
	op.startServer();

    return 0;
}