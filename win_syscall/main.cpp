// win_syscall.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "syscall.hpp"

int main()
{
	if (syscall::initialize())
	{
		auto status = syscall::NtClose(nullptr);
		printf("0x%X", status);
		getchar();
	}
}

