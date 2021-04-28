#include <ntddk.h>
#include "LDE64x64.h"
//typedef KTRAP_FRAME *PKEXCEPTION_FRAME;
#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p) ExFreePool(_p)
#define PAGEDCODE code_seg("PAGE")   
#define LOCKEDCODE code_seg()   
#define INITCODE code_seg("INIT")   
#define PAGEDDATA data_seg("PAGE")   
#define LOCKEDDATA data_seg()   
#define INITDATA data_seg("INIT")
typedef NTSTATUS(*_OriginalKdpTrap)(IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException
	);
PVOID OriginalKdpTrap;
ULONGLONG g_KdPitchDebuggeraddr;
ULONG GetPatchSize(PUCHAR Address)
{
	ULONG LenCount = 0, Len = 0;
	while (LenCount <= 14)	//������Ҫ14�ֽ�
	{
		Len = LDE(Address, 64);
		Address = Address + Len;
		LenCount = LenCount + Len;
	}
	return LenCount;
}


//KdpStub ������ַ�����洢
ULONGLONG KdpStubAddr;

//KdpTrap ������ַ�����洢
ULONGLONG KdpTrapAddr;
ULONGLONG KiDebugRoutineAddr;


//KdDebuggerEnabled�����洢
BOOLEAN gKdDebuggerEnabled = TRUE;
BOOLEAN gKdDebuggerNotPresent = FALSE;
//KdPitchDebugger�����洢
BOOLEAN gKdPitchDebugger = FALSE;

//KiDebugRoutine�����洢
ULONGLONG gKiDebugRoutine = 0;
extern PVOID  KdEnteredDebugger;
//ULONGLONG pKdEnteredDebugger=(ULONGLONG)KdEnteredDebugger;

//������������� KeBugCheckEx
//UCHAR* KeBugCheckAddr=(UCHAR*)KeBugCheckEx;
UCHAR oldvalue[2];
UCHAR KdpStubHead5[5];
ULONG OldTpVal;
//ULONGLONG jmpCode = (ULONGLONG)((char*)KeBugCheckEx + 10);//����15�ֽڲ�������

ULONG pslp_patch_size = 0;		//IoAllocateMdl���޸���N�ֽ�
PUCHAR pslp_head_n_byte = NULL;	//IoAllocateMdl��ǰN�ֽ�����
PVOID ori_pslp = NULL;			//IoAllocateMdl��ԭ����

NTKERNELAPI
UCHAR *
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

typedef PMDL(__fastcall *_MyIoAllocateMdl)(
	__in_opt PVOID  VirtualAddress,
	__in ULONG  Length,
	__in BOOLEAN  SecondaryBuffer,
	__in BOOLEAN  ChargeQuota,
	__inout_opt PIRP  Irp  OPTIONAL);
_MyIoAllocateMdl IoAllocateMdlAddr = NULL;
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
ULONGLONG calcJmpAddr(ULONGLONG curAddr, ULONGLONG codeLength, ULONG codenum)
{
	ULONGLONG high8bit;
	ULONGLONG low8bit;
	high8bit = curAddr & 0xffffffff00000000;
	low8bit = curAddr & 0x00000000ffffffff;
	low8bit = (low8bit + codeLength + codenum) & 0x00000000ffffffff;
	return low8bit + high8bit;

}
ULONG calcJmpCodeNum(ULONGLONG curAddr, ULONGLONG codeLength, ULONGLONG targetAddr)
{
	ULONGLONG high8bit;
	ULONGLONG low8bit;
	ULONG result;
	result = (targetAddr - curAddr - codeLength) & 0x00000000ffffffff;
	return result;
}
ULONGLONG ScanFeatureCode(unsigned char* szFeatureCode, ULONG featLength, ULONGLONG startAddr)
{
	ULONGLONG result = 0;
	ULONGLONG i;
	for (i = startAddr; i < startAddr + 2014; i++)
	{
		if (RtlEqualMemory(szFeatureCode, (void*)i, featLength))
		{
			//�ҵ���
			result = i + featLength;
			break;
		}

	}
	return result;
}


//���룺��HOOK������ַ����������ַ������ԭʼ������ַ��ָ�룬���ղ������ȵ�ָ�룻���أ�ԭ��ͷN�ֽڵ�����
PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID *Original_ApiAddress, OUT ULONG *PatchSize)
{
	KIRQL irql;
	UINT64 tmpv;
	PVOID head_n_byte, ori_func;
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmp_code_orifunc[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	//How many bytes shoule be patch
	*PatchSize = GetPatchSize((PUCHAR)ApiAddress);
	//step 1: Read current data
	head_n_byte = kmalloc(*PatchSize);
	irql = WPOFFx64();
	memcpy(head_n_byte, ApiAddress, *PatchSize);
	WPONx64(irql);

	//step 2: Create ori function
	ori_func = kmalloc(*PatchSize + 14);	//ԭʼ������+��ת������

	RtlFillMemory(ori_func, *PatchSize + 14, 0x90);

	tmpv = (ULONG64)ApiAddress + *PatchSize;	//��ת��û���򲹶����Ǹ��ֽ�
	memcpy(jmp_code_orifunc + 6, &tmpv, 8);
	memcpy((PUCHAR)ori_func, head_n_byte, *PatchSize);
	memcpy((PUCHAR)ori_func + *PatchSize, jmp_code_orifunc, 14);
	*Original_ApiAddress = ori_func;
	//step 3: fill jmp code
	tmpv = (UINT64)Proxy_ApiAddress;
	memcpy(jmp_code + 6, &tmpv, 8);
	//step 4: Fill NOP and hook
	irql = WPOFFx64();
	RtlFillMemory(ApiAddress, *PatchSize, 0x90);
	memcpy(ApiAddress, jmp_code, 14);
	WPONx64(irql);
	//return ori code
	return head_n_byte;
}
//���룺��HOOK������ַ��ԭʼ���ݣ���������
VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize)
{
	KIRQL irql;
	irql = WPOFFx64();
	memcpy(ApiAddress, OriCode, PatchSize);
	WPONx64(irql);
}
ULONGLONG process;
PMDL MyIoAllocateMdl(
	__in_opt PVOID  VirtualAddress,
	__in ULONG  Length,
	__in BOOLEAN  SecondaryBuffer,
	__in BOOLEAN  ChargeQuota,
	__inout_opt PIRP  Irp  OPTIONAL)
{

	if (KdEnteredDebugger == VirtualAddress)
	{
		process = (ULONGLONG)PsGetCurrentProcess();
		KdPrint(("KdDebuggerNotPresent addr is %p\nprocess name :%s\n", KdEnteredDebugger, (PUCHAR)(process + 0x2e0)));
		VirtualAddress = (PVOID)((ULONGLONG)KdEnteredDebugger + 0x20);  //+0x20  ����������������λ��
		//DbgBreakPoint();
	}
	return ((_MyIoAllocateMdl)ori_pslp)(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);



}

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG Unknow1;
	ULONG Unknow2;
	ULONG Unknow3;
	ULONG Unknow4;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;//�ں����Լ��ص�ģ��ĸ���
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64 InLoadOrderLinks;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT  __Undefined5;
	ULONG64 __Undefined6;
	ULONG   CheckSum;
	ULONG   __padding1;
	ULONG   TimeDateStamp;
	ULONG   __padding2;
}KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN ULONG	SystemInformationClass,
	OUT PVOID	SystemInformation,
	IN ULONG	Length,
	OUT PULONG	ReturnLength
);



//ȡ��ģ���ַ�ʹ�С����
#pragma LOCKEDCODE
ULONG64 FindKrlModule(__out ULONG64 *ulSysModuleBase, __out  ULONG64 *ulSize, __in  PCHAR modulename_0)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		//�����ڴ�
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return 0;
		//��ѯģ����Ϣ
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			//��ѯʧ�����˳�
			kfree(pBuffer);
			return 0;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	//���ģ���������
	ModuleCount = pSystemModuleInformation->Count;
	//�������е�ģ��
	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].Base) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName;
			//L"" ������ַ���UNICODESTRING ���ǿ��ַ���wchar_t���ַ�  ""�ַ�
			if (strstr(pDrvName, modulename_0))
			{

				*ulSysModuleBase = (ULONG64)pSystemModuleInformation->Module[i].Base;
				*ulSize = (ULONG64)pSystemModuleInformation->Module[i].Size;

				break;
			}

		}
	}
	kfree(pBuffer);
	return 0;
}

PDRIVER_OBJECT pDriverObject;



ULONG64 moduleAddr_0;//kdcom ��ַ
ULONG64 modulesize_0;//kdcom ��С
VOID HideDriver()
{
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	PKLDR_DATA_TABLE_ENTRY firstentry;

	KIRQL OldIrql;
	firstentry = entry;
	FindKrlModule(&moduleAddr_0, &modulesize_0, "kdcom.dll");
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if (entry->DllBase == moduleAddr_0)
		{

			OldIrql = KeRaiseIrqlToDpcLevel();
			((LIST_ENTRY64*)(entry->InLoadOrderLinks.Flink))->Blink = entry->InLoadOrderLinks.Blink;
			((LIST_ENTRY64*)(entry->InLoadOrderLinks.Blink))->Flink = entry->InLoadOrderLinks.Flink;
			entry->InLoadOrderLinks.Flink = 0;
			entry->InLoadOrderLinks.Blink = 0;
			KeLowerIrql(OldIrql);
			DbgPrint("Remove LIST_ENTRY64 OK!");
			break;
		}
		//kprintf("%llx\t%wZ\t%wZ",entry->DllBase,entry->BaseDllName,entry->FullDllName);
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
}

