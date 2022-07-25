#pragma once

#include <mutex>
#include <tuple>
#include <Windows.h>

typedef LONG NTSTATUS;

#define SYSCALL_DEF_INFO_BEGIN() \
inline std::pair<uint32_t, uintptr_t> funcInfo[] = 

#define SYSCALL_DEF_INFO(name) \
{hash_const("" #name ""), 0}

#define SYSCALL_DEF_FUNC(name) \
template <typename... Args> \
NTSTATUS name (Args... args) \
{   \
	for (const auto& info : syscall::funcInfo)\
	{\
		if (info.first == hash_const("" #name ""))\
		{\
			if (info.second)\
			{\
				return detail::nativeCall<NTSTATUS>(info.second, args...); \
			}\
		}\
	}\
	return 0xC0000001L;\
}


#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm

union reg64
{
	DWORD64 v;
	DWORD dw[2];
};


struct hash_const
{
	uint32_t result;
	template <uint32_t len>
	constexpr __forceinline hash_const(const char(&e)[len]) : hash_const(e, std::make_index_sequence<len - 1>()) {}
	template <uint32_t len>
	constexpr __forceinline hash_const(const wchar_t(&e)[len]) : hash_const(e, std::make_index_sequence<len - 1>()) {}
	template <typename T, uint32_t len>
	constexpr __forceinline hash_const(const T(&e)[len]) : hash_const(e, std::make_index_sequence<len>()) {}
	template <typename T, uint32_t... ids>
	constexpr __forceinline hash_const(const T e, std::index_sequence<ids...>) : hash_const(0, e[ids]...) {}
	template <typename T, typename... T_>
	constexpr __forceinline hash_const(uint32_t result_, const T elem, const T_... elems) : hash_const(((result_ >> 13) | (result_ << 19)) + elem, elems...) {}
	constexpr __forceinline hash_const(uint32_t result_) : result(result_) {}
	operator uint32_t () { return result; }
};

struct hash_dynamic
{
	uint32_t result;

	template <typename T, typename = std::enable_if_t<std::is_same_v<T, char> | std::is_same_v<T, wchar_t>>>
	hash_dynamic(const T* str)
		: result(0)
	{
		while (*str)
		{
			result = ((result >> 13) | (result << 19)) + *str;
			str++;
		}
	}
	template <typename T>
	hash_dynamic(const T* elems, size_t size)
		: result(0)
	{
		for (size_t i = 0; i < size; i++)
		{
			result = ((result >> 13) | (result << 19)) + elems[i];
		}
	}
	operator uint32_t () { return result; }
};


#pragma warning(push)
#pragma warning(disable : 4409)
DWORD64 __cdecl X64Call(unsigned __int64 func, int argC, ...)
{
#ifndef _WIN64
	va_list args;
	va_start(args, argC);
	reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rax = { 0 };

	reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

	// conversion to QWORD for easier use in inline assembly
	reg64 _argC = { (DWORD64)argC };
	DWORD back_esp = 0;
	WORD back_fs = 0;

	__asm
	{
		;// reset FS segment, to properly handle RFG
		mov    back_fs, fs
		mov    eax, 0x2B
		mov    fs, ax

		;// keep original esp in back_esp variable
		mov    back_esp, esp

		;// align esp to 0x10, without aligned stack some syscalls may return errors !
		;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
		;// requires 0x10 alignment), it will be further adjusted according to the
		;// number of arguments above 4
		and esp, 0xFFFFFFF0

		X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		;// fill first four arguments
		REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
		REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
		push   _r8.v;// push    qword ptr [_r8]
		X64_Pop(_R8); ;// pop     r8
		push   _r9.v;// push    qword ptr [_r9]
		X64_Pop(_R9); ;// pop     r9
		;//
		REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
		;// 
		;// final stack adjustment, according to the    ;//
		;// number of arguments above 4                 ;// 
		test   al, 1;// test    al, 1
		jnz    _no_adjust;// jnz     _no_adjust
		sub    esp, 8;// sub     rsp, 8
	_no_adjust:;//
		;// 
		push   edi;// push    rdi
		REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
		;// 
		;// put rest of arguments on the stack          ;// 
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
		;// 
	_ls:;// 
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		push   dword ptr[edi];// push    qword ptr [rdi]
		REX_W sub    edi, 8;// sub     rdi, 8
		REX_W sub    eax, 1;// sub     rax, 1
		jmp    _ls;// jmp     _ls
	_ls_e:;// 
		;// 
		;// create stack space for spilling registers   ;// 
		REX_W sub    esp, 0x20;// sub     rsp, 20h
		;// 
		call   func;// call    qword ptr [func]
		;// 
		;// cleanup stack                               ;// 
		REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
		REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
		;// 
		pop    edi;// pop     rdi
		;// 
// set return value                             ;// 
		REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

		X64_End();

		mov    ax, ds
		mov    ss, ax
		mov    esp, back_esp

		;// restore FS segment
		mov    ax, back_fs
		mov    fs, ax
	}
	return _rax.v;
#endif // _WIN32
	return 0;
}
#pragma warning(pop)