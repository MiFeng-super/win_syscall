#pragma once
#include "syscall_def.h"

namespace syscall
{
	inline BOOL		isInitialize		 = FALSE;
	inline BOOL		isArch64			 = FALSE;
	inline BOOL		isWow64				 = FALSE;
	inline BOOL		isWow64FsRedirection = FALSE;
	inline HANDLE	hHeap				 = nullptr;

	namespace detail
	{
		namespace AnyCall
		{
			template <typename T, typename... Args>
			T cd_call(uintptr_t address, Args... args)
			{
				typedef T(__cdecl* Func)(Args...);
				auto func = (Func)address;
				return func(std::forward<Args>(args)...);
			}

			template <typename T, typename... Args>
			T std_call(uintptr_t address, Args... args)
			{
				typedef T(__stdcall* Func)(Args...);
				auto func = (Func)address;
				return func(std::forward<Args>(args)...);
			}

			template <typename T, typename C, typename... Args>
			T this_call(C* This, uintptr_t address, Args... args)
			{
				typedef T(__thiscall* Func)(PVOID, Args...);
				auto func = (Func)address;
				return func(This, std::forward<Args>(args)...);
			}
		};

		void* getProcAddress(const char* dllName, const char* funcName)
		{
			auto hModule = LoadLibraryA(dllName);
			if (hModule)
			{
				return GetProcAddress(hModule, funcName);
			}
			return nullptr;
		}

		void getSystemInfo(LPSYSTEM_INFO lpSystemInfo) 
		{
			static auto func = (decltype(&GetSystemInfo))getProcAddress("kernel32.dll", "GetNativeSystemInfo");
			if (func)
			{
				func(lpSystemInfo);
			}
			else
			{
				::GetSystemInfo(lpSystemInfo);
			}
		}

		bool disableWow64FsRedirection(PVOID& value) 
		{
			static auto func = (decltype(&::Wow64DisableWow64FsRedirection))
				getProcAddress("kernel32.dll", "Wow64DisableWow64FsRedirection");
			if (func)
			{
				return func(&value);
			}
			return false;
		}

		bool revertWow64FsRedirection(PVOID& value)
		{
			static auto func = (decltype(&::Wow64DisableWow64FsRedirection))
				getProcAddress("kernel32.dll", "Wow64RevertWow64FsRedirection");
			if (func)
			{
				return func(&value);
			}
			return false;
		}

		uint32_t v2f(uint8_t* file, uint32_t va)
		{
			auto dosHeader = (IMAGE_DOS_HEADER*)file;
			auto ntHeader  = (IMAGE_NT_HEADERS*)(dosHeader->e_lfanew + file);
			auto section   = IMAGE_FIRST_SECTION(ntHeader);

			for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++)
			{
				if (section->VirtualAddress <= va && va < (section->VirtualAddress + section->Misc.VirtualSize))
				{
					return (va - section->VirtualAddress) + section->PointerToRawData;
				}
			}

			return 0;
		}

#pragma warning(push)
#pragma warning(disable: 4244)
		template <typename T, typename... Args>
		T nativeCall(uintptr_t func, Args... args)
		{
			if (syscall::isArch64)
			{
#ifdef _WIN64
				return AnyCall::std_call<T>(func, args...);
#else
				return X64Call(func, sizeof...(Args), (DWORD64)args...);
#endif
			}
			else
			{
				return AnyCall::cd_call<T>(func, args...);
			}
		}
#pragma warning(pop)

		uint32_t getSSDTIndex(uint8_t* file, uint32_t h)
		{
			uint8_t* func = nullptr;

			if (syscall::isArch64 && syscall::isWow64FsRedirection)
			{
				auto dosHeader	 = (IMAGE_DOS_HEADER*)file;
				auto ntHeader	 = (IMAGE_NT_HEADERS64*)(dosHeader->e_lfanew + file);
				auto exportDir	 = (IMAGE_EXPORT_DIRECTORY*)(file + v2f(file, ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
				auto nameDir	 = (uint32_t*)(file + v2f(file, exportDir->AddressOfNames));
				auto nameOrdinal = (uint16_t*)(file + v2f(file, exportDir->AddressOfNameOrdinals));
				auto funcDir	 = (uint32_t*)(file + v2f(file, exportDir->AddressOfFunctions));

				for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
				{
					auto funcName = (const char*)(file + v2f(file, nameDir[i]));

					if (h == hash_dynamic(funcName))
					{
						func = (file + v2f(file, funcDir[nameOrdinal[i]]));
						break;
					}
				}
			}
			else
			{
				auto dosHeader	 = (IMAGE_DOS_HEADER*)file;
				auto ntHeader	 = (IMAGE_NT_HEADERS*)(dosHeader->e_lfanew + file);
				auto exportDir	 = (IMAGE_EXPORT_DIRECTORY*)(file + v2f(file, ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
				auto nameDir	 = (uint32_t*)(file + v2f(file, exportDir->AddressOfNames));
				auto nameOrdinal = (uint16_t*)(file + v2f(file, exportDir->AddressOfNameOrdinals));
				auto funcDir	 = (uint32_t*)(file + v2f(file, exportDir->AddressOfFunctions));

				for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
				{
					auto funcName = (const char*)(file + v2f(file, nameDir[i]));

					if (h == hash_dynamic(funcName))
					{
						func = (file + v2f(file, funcDir[nameOrdinal[i]]));
						break;
					}
				}
			}

			if (func)
			{
				int count = 0;
				while (count < 10)
				{
					if (*func == 0xB8)		// mov eax, xxxx
					{
						return *(uint32_t*)(func + 1);
					}

					func++;
					count++;
				}
			}

			return -1;
		}

		uintptr_t getFunction(uint8_t* file, uint32_t h)
		{
			auto index = getSSDTIndex(file, h);
			if (index != -1)
			{
				if (syscall::isArch64)
				{
					unsigned char sysCall64[] = 
					{
						0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,xxx
						0x4C, 0x8B, 0xD1,           // mov r10,rcx
						0x0F, 0x05,                 // syscall
						0xC3                        // retn
					};

					*(uint32_t*)&sysCall64[1] = index;

					auto func = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(sysCall64));
					if (func)
					{
						memcpy(func, sysCall64, sizeof(sysCall64));
						return (uintptr_t)func;
					}
				}
				else
				{
					unsigned char sysCall32[] = 
					{
						0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,xxx
						0xE8, 0x1, 0x0, 0x0, 0x0,   // call sysentry
						0xC3,						// retn
						// sysenter:
						0x8B, 0xD4,                 // mov edx,esp
						0x0F, 0x34,                 // sysenter
						0xC3                        // retn
					};

					*(uint32_t*)&sysCall32[1] = index;

					auto func = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(sysCall32));
					if (func)
					{
						memcpy(func, sysCall32, sizeof(sysCall32));
						return (uintptr_t)func;
					}
				}
			}
			return 0;
		}
	}

	SYSCALL_DEF_INFO_BEGIN()
	{
		SYSCALL_DEF_INFO(NtClose),
		SYSCALL_DEF_INFO(NtQueryInformationProcess)
	};

	SYSCALL_DEF_FUNC(NtClose);
	SYSCALL_DEF_FUNC(NtQueryInformationProcess);

	bool initialize() 
	{
		if (!isInitialize)
		{
			SYSTEM_INFO si;
			detail::getSystemInfo(&si);

			isArch64 = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
				|| si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64;

			IsWow64Process(GetCurrentProcess(), &isWow64);

			isWow64FsRedirection = isArch64 && isWow64;

			hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
			if (!hHeap)
			{
				return false;
			}

			PVOID value = nullptr;
			char sysDir[MAX_PATH] = { 0 };
			GetSystemDirectoryA(sysDir, MAX_PATH);
			strcat_s(sysDir, "\\ntdll.dll");

			if (isWow64FsRedirection)
			{
				detail::disableWow64FsRedirection(value);
			}

			auto hFile = CreateFileA(sysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				return false;
			}

			auto size   = GetFileSize(hFile, nullptr);
			auto buffer = new uint8_t[size];

			DWORD dwRead = 0;
			BOOL  res = ReadFile(hFile, buffer, size, &dwRead, nullptr);

			if (res && dwRead)
			{
				for (auto& info : funcInfo)
				{
					info.second = detail::getFunction(buffer, info.first);
				}
			}

			CloseHandle(hFile);
			delete[] buffer;

			if (isWow64FsRedirection)
			{
				detail::revertWow64FsRedirection(value);
			}

			isInitialize = TRUE;
		}
		return isInitialize;
	}
}