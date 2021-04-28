
#include <ntddk.h>
#include "func.h"
#define LINKNAME L"\\DosDevices\\EXAMPLE"
#define DEVNAME L"\\Device\\EXAMPLE"

/*
整体思路:
首先修改代码中对变量的引用改为对自己设置的变量的引用
再改掉kdpstub前几个字节直接jmp到kdptrap
再inlinehook 掉ioallocatemdl
最后隐藏kdcom模块

*/

//各种io控制码全是缓冲模式， 每个控制码对应一个应用层程序对驱动的一种操作
#define IOCTL_EXAMPLE \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)

NTSTATUS DriverDefaultDisPatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PIO_STACK_LOCATION pIrpStack;
	NTSTATUS status = STATUS_SUCCESS;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


PETHREAD eThread = 0;
NTSTATUS DriverControlIo(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PIO_STACK_LOCATION pIrpStack;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG uControlCode;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uControlCode)
	{
	case IOCTL_EXAMPLE:
	{

	}


	default:
		break;
	}


	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
VOID UnLoadDriver(PDRIVER_OBJECT pDriverObject)
{
	//PDEVICE_OBJECT pDevObj;
	//UNICODE_STRING sysLinkName;
	//KIRQL irql;
	//LARGE_INTEGER my_interval;
	//my_interval.QuadPart = 1000000000;
	//KdPrint(("[MyProtect_Unload] ==>\n"));

	//recoveryVar();
	//irql = WPOFFx64();

	//*((ULONGLONG*)KiDebugRoutineAddr) = KdpStubAddr;
	//memcpy((void*)KdpStubAddr, KdpStubHead5, 5);
	//WPONx64(irql);
	//UnhookIoAllocateMdl();
//	RtlInitUnicodeString(&sysLinkName, LINKNAME);
	//IoDeleteSymbolicLink(&sysLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	//	KdPrint(("delete device! unload!\n"));

}






NTSTATUS HookKdpTrap(
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException) {
	
	
	if (!_stricmp((char *)(PsGetProcessImageFileName(PsGetCurrentProcess())), "TASLogin.exe"))
	{

		return STATUS_SUCCESS;
	}
	//return STATUS_SUCCESS;
	return ((_OriginalKdpTrap)OriginalKdpTrap)(TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChanceException);
}

NTSTATUS bypass_debug()
{


	ULONGLONG ulAddr, ulAddr2, ulAddr3, uladdr4, KeUpdateRunTimeAddr, KeUpdateSystemTimeAddr, KdPollBreakInAddr;
	ULONG opCodeNum;
	UNICODE_STRING uniKeUpdateRunTime;
	UNICODE_STRING uniKeUpdateSystemTime;
	UNICODE_STRING uniKdPollBreakIn;
	KIRQL irql;

	/*
	第一处的KdDebuggerEnabled

	fffff800`03eed9b3 e838a1feff      call    nt!KeAccumulateTicks (fffff800`03ed7af0)
	fffff800`03eed9b8 84c0            test    al,al
	fffff800`03eed9ba 7414            je      nt!KeUpdateRunTime+0xd0 (fffff800`03eed9d0)
	fffff800`03eed9bc 803d2dd21e0000  cmp     byte ptr [nt!KdDebuggerEnabled (fffff800`040dabf0)],0

	*/
	unsigned char featureCode[6] = "\x84\xC0\x74\x14\x80\x3D";
	UCHAR featureCode2[6] = "\x33\xC0\x4C\x89\x1D";
	ULONG featLenth = 6;
	ULONG featLenth2 = 5;
	ULONG KdDisableDebuggerWithLockOffset;
	ULONGLONG KdDisableDebuggerWithLockAddr;
	UCHAR jmp_code[] = "\xE9\xff\xFF\xFF\xFF";


	//得到原内核的KeUpdateRunTime地址
	//writeOurVar();
	RtlInitUnicodeString(&uniKeUpdateRunTime, L"KeUpdateRunTime");			//字符串初始化
	RtlInitUnicodeString(&uniKeUpdateSystemTime, L"KeUpdateSystemTime");
	RtlInitUnicodeString(&uniKdPollBreakIn, L"KdPollBreakIn");
	KeUpdateRunTimeAddr = (ULONGLONG)MmGetSystemRoutineAddress(&uniKeUpdateRunTime);			//取 KeUpdateRunTime 函数地址
	KeUpdateSystemTimeAddr = (ULONGLONG)MmGetSystemRoutineAddress(&uniKeUpdateSystemTime);
	KdPollBreakInAddr = (ULONGLONG)MmGetSystemRoutineAddress(&uniKdPollBreakIn);
	ulAddr = ScanFeatureCode(featureCode, featLenth, KeUpdateRunTimeAddr);
	if (ulAddr != 0)
	{
		//KdPrint(("搜索KeUpdateRunTime地址:%p\r\n", ulAddr));
		//KdPrint(("KeBugCheckEx 为%p", KeBugCheckEx));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//KdPrint(("操作码:%p", (ULONGLONG)&((UCHAR*)KeBugCheckEx)[0] - 7 - (ulAddr - 2)));
		//opCodeNum = (ULONG)((ULONGLONG)&((UCHAR*)KeBugCheckEx)[0] - 7 - (ulAddr - 2));

		irql = WPOFFx64();
		*((PUCHAR)ulAddr + 5) = 0x74;
		//*((ULONG*)ulAddr) = opCodeNum;


		//	KdPrint(("搜索KeUpdateRunTime完成！"));
	}
	else {
		//	KdPrint(("搜索KeUpdateRunTime失败********************"));
		return 0;
	}



	

	/*第2处的KdPitchDebugger
	fffff800`03ef3a1e 807b2000        cmp     byte ptr [rbx+20h],0
	fffff800`03ef3a22 0f840306fdff    je      nt! ?? ::FNODOBFM::`string'+0x5d6c (fffff800`03ec402b)
	fffff800`03ef3a28 c6430601        mov     byte ptr [rbx+6],1
	fffff800`03ef3a2c e965ffffff      jmp     nt!KeUpdateRunTime+0x96 (fffff800`03ef3996)
.text:000000014007EE91 80 3D 72 63 16 00 00                          cmp     cs:KdPitchDebugger, 0
特征码:\xC6\x43\x06\x01\xE9\x65\xFF\xFF\xFF
*/


	ulAddr = ScanFeatureCode("\xC6\x43\x06\x01\xE9\x65\xFF\xFF\xFF", 9, KeUpdateRunTimeAddr);
	if (ulAddr != 0)
	{
		//KdPrint(("第2处的KdPitchDebugger地址:%p\r\n", ulAddr + 2));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//opCodeNum = calcJmpCodeNum(ulAddr, 7, (ULONGLONG)KeBugCheckEx + 1);
		
		//KdPrint(("操作码:%p", opCodeNum));
		//irql = WPOFFx64();
		*((PUCHAR)ulAddr + 7) = 0x74;
		//*((ULONG*)(ulAddr + 2)) = opCodeNum;
		//WPONx64(irql);

	//	KdPrint(("第2处的KdPitchDebugger完成！"));
	}
	else {
		//KdPrint(("搜索第2处的KdPitchDebugger失败********************"));
		return 0;
	}





	/*
	第3处的KdDebuggerEnabled
	.text:000000014007A452 0F B7 54 24 20                                movzx   edx, [rsp+0F8h+var_D8]
.text:000000014007A457
.text:000000014007A457                               loc_14007A457:                          ; CODE XREF: KeUpdateSystemTime-4072Fj
.text:000000014007A457 41 8B FF                                      mov     edi, r15d
.text:000000014007A45A 4C 8B C3                                      mov     r8, rbx
.text:000000014007A45D
.text:000000014007A45D                               loc_14007A45D:                          ; CODE XREF: KeUpdateSystemTime-40837j
.text:000000014007A45D 38 1D 4D 77 1F 00                             cmp     cs:KdDebuggerEnabled, bl
特征码:0FB7542420418BFF4C8BC3
	*/
	ulAddr = ScanFeatureCode("\x0F\xB7\x54\x24\x20\x41\x8B\xFF\x4C\x8B\xC3", 11, KeUpdateSystemTimeAddr);
	if (ulAddr != 0)
	{
		//KdPrint(("第3处的KdDebuggerEnabled地址:%p\r\n", ulAddr + 2));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//opCodeNum = calcJmpCodeNum(ulAddr, 6, (ULONGLONG)KeBugCheckEx + 2);
		*((PUCHAR)ulAddr + 6) = 0x75;
		//KdPrint(("操作码:%p", opCodeNum));
		//	irql = WPOFFx64();

		//*((ULONG*)(ulAddr + 2)) = opCodeNum;
		//	WPONx64(irql);

		//KdPrint(("第3处的KdDebuggerEnabled完成！"));
	}
	else {
		//KdPrint(("搜索第3处的KdDebuggerEnabled失败********************"));
		return 0;
	}


	/*
	第4处的KdDebuggerEnabled
.text:000000014007A5F2 E8 69 E4 FF FF                                call    KeAccumulateTicks
.text:000000014007A5F7 84 C0                                         test    al, al
.text:000000014007A5F9 74 14                                         jz      short loc_14007A60F
.text:000000014007A5FB 80 3D AE 75 1F 00 00                          cmp     cs:KdDebuggerEnabled, 0
特征码:\xE8\x69\xE4\xFF\xFF\x84\xC0\x74\x14

fffff800`03ef1eb2 e839bcfeff      call    nt!KeAccumulateTicks (fffff800`03eddaf0)
fffff800`03ef1eb7 84c0            test    al,al
fffff800`03ef1eb9 7414            je      nt!KeUpdateSystemTime+0x38f (fffff800`03ef1ecf)
fffff800`03ef1ebb 803d2eed1e0000  cmp     byte ptr [nt!KdDebuggerEnabled (fffff800`040e0bf0)],0


	*/
	ulAddr = ScanFeatureCode("\x84\xC0\x74\x14", 4, KeUpdateSystemTimeAddr);
	if (ulAddr != 0)
	{
		//KdPrint(("第4处的KdDebuggerEnabled:%p\r\n", ulAddr + 2));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//opCodeNum = calcJmpCodeNum(ulAddr, 7, (ULONGLONG)KeBugCheckEx + 3);

		//KdPrint(("操作码:%p", opCodeNum));
		//irql = WPOFFx64();
		*((PUCHAR)ulAddr + 7) = 0x75;
		//*((ULONG*)(ulAddr + 2)) = opCodeNum;
		//WPONx64(irql);

		//KdPrint(("第4处的KdDebuggerEnabled完成！"));
	}
	else {
		//	KdPrint(("搜索第4处的KdDebuggerEnabled失败********************"));
		return 0;
	}



	/*
	第5处的KdPitchDebugger
	.text:000000014007A66D 44 88 7F 06                                   mov     [rdi+6], r15b
.text:000000014007A671 E9 61 FF FF FF                                jmp     loc_14007A5D7
.text:000000014007A676                               ; ---------------------------------------------------------------------------
.text:000000014007A676
.text:000000014007A676                               loc_14007A676:                          ; CODE XREF: KeUpdateSystemTime+38Dj
.text:000000014007A676 80 3D 8D AB 16 00 00                          cmp     cs:KdPitchDebugger, 0


	特征码:44887F06E961FFFFFF
	*/

	ulAddr = ScanFeatureCode("\x44\x88\x7F\x06\xE9\x61\xFF\xFF\xFF", 9, KeUpdateSystemTimeAddr);
	if (ulAddr != 0)
	{
		//	KdPrint(("第5处的KdPitchDebugger地址:%p\r\n", ulAddr + 2));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//opCodeNum = calcJmpCodeNum(ulAddr, 7, (ULONGLONG)KeBugCheckEx + 4);
		*((PUCHAR)ulAddr + 7) = 0x74;
		//KdPrint(("操作码:%p", opCodeNum));
		//DbgBreakPoint();
	//	irql = WPOFFx64();
	//	KdPrint(("irql is %d\n", irql));
		//*((ULONG*)(ulAddr + 2)) = opCodeNum;
		//	WPONx64(irql);
	//	KdPrint(("irql is %d\n", irql));
		//KdPrint(("第5处的KdPitchDebugger完成！"));
	}
	else {
		//KdPrint(("搜索第5处的KdPitchDebugger失败********************"));
		return 0;
	}




	ulAddr = KdPollBreakInAddr + 5 + 2;
	//bug还是故意的
	//KdPrint(("第6处的KdPitchDebugger地址:%p\r\n", ulAddr + 2));
	//计算公式:目标地址=当前地址+操作数+指令长度
	//opCodeNum = calcJmpCodeNum(ulAddr, 7, (ULONGLONG)KeBugCheckEx + 5);
	//DbgBreakPoint();
	//KdPrint(("操作码:%p", opCodeNum));
	//irql = WPOFFx64();
	*((PUCHAR)ulAddr + 8) = 0x84;
	//*((ULONG*)(ulAddr + 2)) = opCodeNum;
	//WPONx64(irql);
	//KdPrint(("第6处的KdPitchDebugger完成！"));




	/*
		第7处的KdDebuggerEnabled
		.text:000000014007EEC4 48 89 74 24 68                               mov     [rsp+48h+arg_18], rsi
	.text:000000014007EEC9 40 32 F6                                      xor     sil, sil
	.text:000000014007EECC 40 38 35 DD 2C 1F 00                          cmp     cs:KdDebuggerEnabled, sil


		特征码:\x48\x89\x74\x24\x68\x40\x32\xF6
		*/

	ulAddr = ScanFeatureCode("\x48\x89\x74\x24\x68\x40\x32\xF6", 8, KdPollBreakInAddr);
	if (ulAddr != 0)
	{
		//	KdPrint(("第7处的KdDebuggerEnabled地址:%p\r\n", ulAddr + 3));
	
		//opCodeNum = calcJmpCodeNum(ulAddr, 7, (ULONGLONG)KeBugCheckEx + 6);
		//DbgBreakPoint();
	//	KdPrint(("操作码:%p", opCodeNum));
		//	irql = WPOFFx64();
		*((PUCHAR)ulAddr + 8) = 0x85;
		//*((ULONG*)(ulAddr + 3)) = opCodeNum;
		WPONx64(irql);

		//	KdPrint(("第7处的KdDebuggerEnabled完成！"));
	}
	else {
		//	KdPrint(("搜索第7处的KdDebuggerEnabled失败********************"));
		return 0;
	}







	//DbgBreakPoint();
	//定位 KiDebugRoutine
	//先定位 KdDisableDebugger(导出的),再定位KdDisableDebuggerWithLock
	//在KdDisableDebuggerWithLock里面搜索特征码找到
	/*
	KdDisableDebugger proc near
	mov     cl, 1
	jmp     KdDisableDebuggerWithLock

	.text:000000014013D308 4C 8D 1D B1 18 00 00                          lea     r11, KdpStub
	.text:000000014013D30F 33 C0                                         xor     eax, eax
	.text:000000014013D311 4C 89 1D E8 F0 16 00                          mov     cs:KiDebugRoutine, r11
	E8 F0 16 00是偏移,特征码是:33C04C891D
	*/
	//为了处理向上跳转,通用于向下跳转
	KdDisableDebuggerWithLockOffset = *((ULONG*)((UCHAR*)(KdDisableDebugger)+3));

	KdDisableDebuggerWithLockAddr = calcJmpAddr((ULONGLONG)(KdDisableDebugger)+2, 5, KdDisableDebuggerWithLockOffset);


	ulAddr2 = ScanFeatureCode(featureCode2, featLenth2, KdDisableDebuggerWithLockAddr);
	if (ulAddr2 != 0)
	{
		//KdPrint(("搜索02地址:%p\r\n", ulAddr2));
		//KdPrint(("KeBugCheckEx 为%p",KeBugCheckEx));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//KdPrint(("操作码:%p",(ULONGLONG)KdDisableDebugger-7-(ulAddr2-3) ));
		opCodeNum = *((ULONG*)(ulAddr2));
	//	KdPrint(("操作码2:%x", opCodeNum));

		KiDebugRoutineAddr = calcJmpAddr(ulAddr2 - 3, 7, opCodeNum);
//		KdPrint(("KiDebugRoutineAddr地址:%p\r\n", KiDebugRoutineAddr));

		//KdPrint(("搜索KiDebugRoutineAddr完成********************"));
	}
	else {
		//KdPrint(("搜索KiDebugRoutineAddr失败********************"));
		return 0;
	}
	/*
	KdDisableDebugger proc near
	mov     cl, 1
	jmp     KdDisableDebuggerWithLock

	.text:000000014013D308 4C 8D 1D B1 18 00 00                          lea     r11, KdpStub
	.text:000000014013D30F 33 C0                                         xor     eax, eax
	fffff800`03f4abc8 4c 8d 1d 61 23 00 00  lea     r11,[nt!KdpStub (fffff800`03f4cf30)]
	fffff800`03f4abcf 33c0            xor     eax,eax
	*/
	ulAddr3 = ScanFeatureCode((UCHAR*)"\x33\xC0", 2, KdDisableDebuggerWithLockAddr);
	if (ulAddr3 != 0)
	{
		//KdPrint(("搜索KdpStubAddr地址:%p\r\n", ulAddr3));
		opCodeNum = *((ULONG*)(ulAddr3 - 6));
		//KdPrint(("操作码KdpStubAddr:%x", opCodeNum));
		KdpStubAddr = calcJmpAddr(ulAddr3 - 9, 7, opCodeNum);
	//	KdPrint(("KdpStubAddr地址:%p\r\n", KdpStubAddr));
		/*
KdpTrap在KdpStub被引用
000000014013EC4D 8A 44 24 68                                   mov     al, [rsp+38h+arg_28]
.text:000000014013EC51 4C 8B CB                                      mov     r9, rbx
.text:000000014013EC54 4C 8B C7                                      mov     r8, rdi
.text:000000014013EC57 88 44 24 28                                   mov     [rsp+38h+var_10], al
.text:000000014013EC5B 8A 44 24 60                                   mov     al, [rsp+38h+arg_20]
.text:000000014013EC5F 48 8B D6                                      mov     rdx, rsi
.text:000000014013EC62 48 8B CD                                      mov     rcx, rbp
.text:000000014013EC65 88 44 24 20                                   mov     [rsp+38h+var_18], al
.text:000000014013EC69 E8 A2 D3 3B 00                                call    KdpTrap
*/
	
		uladdr4 = ScanFeatureCode((UCHAR*)"\x8A\x44\x24\x60\x48\x8B\xD6\x48\x8B\xCD\x88\x44\x24\x20\xE8", 15, KdpStubAddr);
		if (ulAddr3 != 0)
		{
		
			opCodeNum = *((ULONG*)(uladdr4));
			
			//	KdpTrapAddr = uladdr4-1+5+opCodeNum;
			KdpTrapAddr = calcJmpAddr(uladdr4 - 1, 5, opCodeNum);
		
		}
		else
		{
			
			return 0;
		}

	}
	else {
		
		return 0;
	}

	memcpy(KdpStubHead5, (void*)KdpStubAddr, 5);//备份前5字节
	opCodeNum = calcJmpCodeNum(KdpStubAddr, 5, KdpTrapAddr);
	memcpy(jmp_code + 1, &opCodeNum, 4);

	irql = WPOFFx64();
	memcpy((void*)KdpStubAddr, jmp_code, 5);
	SharedUserData->KdDebuggerEnabled = FALSE;//Set SharedUserData
	*(PLONG64)KiDebugRoutineAddr = KdpStubAddr;// KiDebugRoutine -> Kdpstub
	WPONx64(irql);
	//HookIoAllocateMdl();
 pslp_head_n_byte = HookKernelApi((PVOID)KdpTrapAddr, (PVOID)HookKdpTrap, &OriginalKdpTrap, &pslp_patch_size);
	//*(PUCHAR)KdDebuggerEnabled = 0;
	//*(PUCHAR)g_KdPitchDebuggeraddr = 1;
	//*(PUCHAR)KdEnteredDebugger = 0;
	//*(PUCHAR)KdDebuggerNotPresent = 1;
	//KdPrint(("KdDebuggerNotPresent 内容位：%x", *(PUCHAR)KdDebuggerNotPresent));
	
	
	return 1;
}
KDPC dpc;
KTIMER timer;
PDRIVER_OBJECT g_DriverObject;

VOID DpcRoutine(PKDPC pDpc,
	PVOID DeferredContext,
	PVOID SysArg1,
	PVOID SysArg2)
{
	KIRQL irql;
	LARGE_INTEGER li = RtlConvertLongToLargeInteger(-10 * 1000 * 1000);
	irql = WPOFFx64();
	*(PUCHAR)KdDebuggerEnabled = 0;
	*(PUCHAR)g_KdPitchDebuggeraddr = 1;
	*(PUCHAR)KdDebuggerNotPresent = 1;
	*(PUCHAR)KdEnteredDebugger = 0;
	WPONx64(irql);
	
	KeSetTimer(&timer, li, &dpc);
}
ULONGLONG CalcOffsetAddr(ULONGLONG pCurrentAddr, ULONG opcodeLength, ULONGLONG Offset)
{
	ULONGLONG high8byte;
	ULONGLONG low8byte;
	high8byte = pCurrentAddr & 0xffffffff00000000;
	low8byte = pCurrentAddr & 0x00000000ffffffff;
	low8byte = (low8byte + opcodeLength + Offset) & 0x00000000ffffffff;
	return high8byte + low8byte;
}
NTSTATUS GetKdPitchDebuggerAddr()
{
	ULONG opcode;
	UNICODE_STRING UniKdPollBreakIn;
	ULONGLONG KdPitchDebuggeraddr;

	RtlInitUnicodeString(&UniKdPollBreakIn, L"KdPollBreakIn");

	ULONGLONG pKdPollBreakIn = (ULONGLONG)MmGetSystemRoutineAddress(&UniKdPollBreakIn);

	ULONGLONG uladdr = pKdPollBreakIn + 2 + 5 + 2;
	opcode = *((ULONG*)(uladdr));
	g_KdPitchDebuggeraddr = CalcOffsetAddr(pKdPollBreakIn + 2 + 5, 7, opcode);
	//KdPrint(("KdPitchDebuggeraddr 地址：%p", KdPitchDebuggeraddr));

	return STATUS_SUCCESS;

}
VOID HookkdpTrapsol()
{
	ULONG KdDisableDebuggerWithLockOffset;
	ULONGLONG KdDisableDebuggerWithLockAddr;
	UCHAR featureCode2[6] = "\x33\xC0\x4C\x89\x1D";
	ULONG featLenth2 = 5;
	ULONG opCodeNum;
	ULONGLONG ulAddr2, ulAddr3, uladdr4;
	UCHAR jmp_code[] = "\xE9\xff\xFF\xFF\xFF";
	KIRQL irql;
	KdDisableDebuggerWithLockOffset = *((ULONG*)((UCHAR*)(KdDisableDebugger)+3));
	
	KdDisableDebuggerWithLockAddr = calcJmpAddr((ULONGLONG)(KdDisableDebugger)+2, 5, KdDisableDebuggerWithLockOffset);
	ulAddr2 = ScanFeatureCode(featureCode2, featLenth2, KdDisableDebuggerWithLockAddr);
	if (ulAddr2 != 0)
	{
		//KdPrint(("搜索02地址:%p\r\n", ulAddr2));
		//KdPrint(("KeBugCheckEx 为%p",KeBugCheckEx));
		//计算公式:目标地址=当前地址+操作数+指令长度
		//KdPrint(("操作码:%p",(ULONGLONG)KdDisableDebugger-7-(ulAddr2-3) ));
		opCodeNum = *((ULONG*)(ulAddr2));
		//	KdPrint(("操作码2:%x", opCodeNum));

		KiDebugRoutineAddr = calcJmpAddr(ulAddr2 - 3, 7, opCodeNum);
		//		KdPrint(("KiDebugRoutineAddr地址:%p\r\n", KiDebugRoutineAddr));

				//KdPrint(("搜索KiDebugRoutineAddr完成********************"));
	}
	else {
		//KdPrint(("搜索KiDebugRoutineAddr失败********************"));
		return 0;
	}
	/*
	KdDisableDebugger proc near
	mov     cl, 1
	jmp     KdDisableDebuggerWithLock

	.text:000000014013D308 4C 8D 1D B1 18 00 00                          lea     r11, KdpStub
	.text:000000014013D30F 33 C0                                         xor     eax, eax
	fffff800`03f4abc8 4c 8d 1d 61 23 00 00  lea     r11,[nt!KdpStub (fffff800`03f4cf30)]
	fffff800`03f4abcf 33c0            xor     eax,eax
	*/
	ulAddr3 = ScanFeatureCode((UCHAR*)"\x33\xC0", 2, KdDisableDebuggerWithLockAddr);
	if (ulAddr3 != 0)
	{
		//KdPrint(("搜索KdpStubAddr地址:%p\r\n", ulAddr3));
		opCodeNum = *((ULONG*)(ulAddr3 - 6));
		//KdPrint(("操作码KdpStubAddr:%x", opCodeNum));
		KdpStubAddr = calcJmpAddr(ulAddr3 - 9, 7, opCodeNum);
		//	KdPrint(("KdpStubAddr地址:%p\r\n", KdpStubAddr));
			/*
	KdpTrap在KdpStub被引用
	000000014013EC4D 8A 44 24 68                                   mov     al, [rsp+38h+arg_28]
	.text:000000014013EC51 4C 8B CB                                      mov     r9, rbx
	.text:000000014013EC54 4C 8B C7                                      mov     r8, rdi
	.text:000000014013EC57 88 44 24 28                                   mov     [rsp+38h+var_10], al
	.text:000000014013EC5B 8A 44 24 60                                   mov     al, [rsp+38h+arg_20]
	.text:000000014013EC5F 48 8B D6                                      mov     rdx, rsi
	.text:000000014013EC62 48 8B CD                                      mov     rcx, rbp
	.text:000000014013EC65 88 44 24 20                                   mov     [rsp+38h+var_18], al
	.text:000000014013EC69 E8 A2 D3 3B 00                                call    KdpTrap
	*/

		uladdr4 = ScanFeatureCode((UCHAR*)"\x8A\x44\x24\x60\x48\x8B\xD6\x48\x8B\xCD\x88\x44\x24\x20\xE8", 15, KdpStubAddr);
		if (ulAddr3 != 0)
		{

			opCodeNum = *((ULONG*)(uladdr4));

			//	KdpTrapAddr = uladdr4-1+5+opCodeNum;
			KdpTrapAddr = calcJmpAddr(uladdr4 - 1, 5, opCodeNum);

		}
		else
		{

			return 0;
		}

	}
	else {

		return 0;
	}
	pslp_head_n_byte = HookKernelApi((PVOID)KdpTrapAddr, (PVOID)HookKdpTrap, &OriginalKdpTrap, &pslp_patch_size);
	memcpy(KdpStubHead5, (void*)KdpStubAddr, 5);//备份前5字节
	opCodeNum = calcJmpCodeNum(KdpStubAddr, 5, KdpTrapAddr);
	memcpy(jmp_code + 1, &opCodeNum, 4);

	irql = WPOFFx64();
	memcpy((void*)KdpStubAddr, jmp_code, 5);
	SharedUserData->KdDebuggerEnabled = FALSE;//Set SharedUserData
	*(PLONG64)KiDebugRoutineAddr = KdpStubAddr;// KiDebugRoutine -> Kdpstub

	WPONx64(irql);
}
//KdSendPacket

ULONG64 moduleAddr_0;//kdcom 基址
ULONG64 modulesize_0;//kdcom 大小
					 /*
					 PKLDR_DATA_TABLE_ENTRY链表结构 Blink=后一个 Flink前一个
					 DllBase  基址
					 BaseDllName   内核名字  ntoskrnl.exe
					 FullDllName  完整路径名字 c:\windows\system32\ntkrnlmp.exe
					 */
#define KdpSendWaitContinueOffset 0x50371A
#define kdpDebugOffset 0x5004F0
#define KdpSymbolOffset 0x500942
#define KeBugCheck2Offset 0x168B11
VOID removeKdDebuggerNotPresent()
{

	ULONG64 moduleAddr_1;
	ULONG64 modulesize_1;
	FindKrlModule(&moduleAddr_0, &modulesize_0, "kdcom.dll");
	FindKrlModule(&moduleAddr_1, &modulesize_1, "ntoskrnl.exe");
	//ULONG offset = (ULONG)((ULONG64)KeBugCheckEx + 7 - (ULONG64)moduleAddr_1 - 0x50371A) - 0x7;
KIRQL irql;
	irql = WPOFFx64();
	
	*((PUCHAR)moduleAddr_0 + 0x1313) = 0x90;//mov [rax],1
	*((PUCHAR)moduleAddr_0 + 0x1314) = 0x90;
	*((PUCHAR)moduleAddr_0 + 0x1315) = 0x90;


//	__debugbreak();
	//KdPrint(("%x\n", offset));
	//*((PUCHAR)moduleAddr_1 + 0x50371A ) = 0x40;// cmp dil,0 
	//KdpSendWaitContinue
	
	*((PUCHAR)moduleAddr_1 + KdpSendWaitContinueOffset + 0x01) = 0x80;
	*((PUCHAR)moduleAddr_1 + KdpSendWaitContinueOffset + 0x02)=0xff;
	
	*((PUCHAR)moduleAddr_1 + KdpSendWaitContinueOffset + 0x03) = 0x00;
	*((PUCHAR)moduleAddr_1 + KdpSendWaitContinueOffset + 0x04) = 0x90;
	*((PUCHAR)moduleAddr_1 + KdpSendWaitContinueOffset + 0x05) = 0x90;
	*((PUCHAR)moduleAddr_1 + KdpSendWaitContinueOffset + 0x06) = 0x90;
	//50 04F0 kdprint
	/*
	*((PUCHAR)moduleAddr_1 + kdpDebugOffset + 0x01) = 0x80;// cmp dil,0
	*((PUCHAR)moduleAddr_1 + kdpDebugOffset + 0x02) = 0xff;
	*((PUCHAR)moduleAddr_1 + kdpDebugOffset + 0x03) = 0x00;
	*((PUCHAR)moduleAddr_1 + kdpDebugOffset + 0x04) = 0x90;
	*((PUCHAR)moduleAddr_1 + kdpDebugOffset + 0x05) = 0x90;
	*((PUCHAR)moduleAddr_1 + kdpDebugOffset + 0x06) = 0x90;
	*/
	//KdpSymbol 50 0942
	/*
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x00) = 0x41;// cmp r9b,0
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x01) = 0x80;
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x02) = 0xf9;
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x03) = 0x00;
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x04) = 0x90;
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x05) = 0x90;
	*((PUCHAR)moduleAddr_1 + KdpSymbolOffset + 0x06) = 0x90;
	*/
	//16 8B11 KeBugCheck2

	/*
	*((PUCHAR)moduleAddr_1 + KeBugCheck2Offset + 0x01) = 0x80;
	*((PUCHAR)moduleAddr_1 + KeBugCheck2Offset + 0x02) = 0xfd;
	*((PUCHAR)moduleAddr_1 + KeBugCheck2Offset + 0x03) = 0x00;
	*((PUCHAR)moduleAddr_1 + KeBugCheck2Offset + 0x04) = 0x90;
	*((PUCHAR)moduleAddr_1 + KeBugCheck2Offset + 0x05) = 0x90;
	*((PUCHAR)moduleAddr_1 + KeBugCheck2Offset + 0x06) = 0x90;
		*/
	WPONx64(irql);
	//KdDebuggerNotPresent;
	
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING pPath)
{

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING devName;
	UNICODE_STRING linkName;
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING ustrEventName;
	UNICODE_STRING ustrEventName_2;
	ULONG i;
	g_DriverObject = DriverObject;
	DriverObject->DriverUnload = UnLoadDriver;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DriverDefaultDisPatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlIo;


	RtlInitUnicodeString(&devName, DEVNAME);
	RtlInitUnicodeString(&linkName, LINKNAME);
	status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, 0, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		//KdPrint(("IoCreateDevice error\n"));
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	KdPrint(("IoCreateDevice success\n"));
	//设置I/O读写方式
	DriverObject->Flags |= DO_BUFFERED_IO;

	//创建符号链接	
	status = IoCreateSymbolicLink(&linkName, &devName);
	if (!NT_SUCCESS(status))
	{
		//KdPrint(("IoCreateSymbolicLink error\n"));
		IoDeleteDevice(pDevObj);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	//KdPrint(("IoCreateSymbolicLink success\n"));
	DriverObject->Flags &= ~DO_DEVICE_INITIALIZING;
	pDriverObject = DriverObject;
	//__debugbreak();
	LDE_init();
	//pslp_head_n_byte = HookKernelApi((PVOID)KdpTrapAddr, (PVOID)HookKdpTrap, &OriginalKdpTrap, &pslp_patch_size);
	GetKdPitchDebuggerAddr();
	bypass_debug();
	//HookkdpTrapsol();
	

	removeKdDebuggerNotPresent();
	HideDriver();
	
	LARGE_INTEGER firstTime = RtlConvertLongToLargeInteger(-10 * 1000 * 3000);
	
 KeInitializeDpc(&dpc, DpcRoutine, NULL); // 初始化KDPC对象并设置回调函数
	KeInitializeTimer(&timer); // 初始化定时器对象
	KeSetTimer(&timer, firstTime, &dpc); // 设置定时器间隔并开始计时

	

	return STATUS_SUCCESS;
}


