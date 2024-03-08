#include<ntifs.h>
#include"APC.h"
#include"function.h"


#define drv_device L"\\Device\\injdrv"
#define drv_dos_device L"\\DosDevices\\injdrv"
#define drv  L"\\Driver\\injdrv"
#define FILE_DEVICE_BLACKBONE           0x8005

#define GetModelBaseadder  CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define ReadWriteMemory  CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ALL_ACCESS) //读写内存
#define Get_Right_ACCESS  CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ALL_ACCESS) //句柄表提权
#define IOCTL_BLACKBONE_GRANT_ACCESS   (ULONG)CTL_CODE(FILE_DEVICE_BLACKBONE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)//句柄表提权  参数不一样
#define IOCTL_BLACKBONE_INJECT_DLL  (ULONG)CTL_CODE(FILE_DEVICE_BLACKBONE, 0x80B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)//注入
#define IOCTL_BLACKBONE_ALLOCATE_FREE_MEMORY  (ULONG)CTL_CODE(FILE_DEVICE_BLACKBONE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)//分配内存
#define IOCTL_BLACKBONE_PROTECT_MEMORY  (ULONG)CTL_CODE(FILE_DEVICE_BLACKBONE, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)//修改内存属性

#define RtlEqualMemory(Destination,Source,Length) (!memcmp((Destination),(Source),(Length)))
#define RtlMoveMemory(Destination,Source,Length) memmove((Destination),(Source),(Length))
#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
#define RtlFillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))

DYNAMIC_DATA dynData;

NTSTATUS InitializeDevice(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(drv_device);
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(drv_dos_device);
	PDEVICE_OBJECT deviceObject = NULL;
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice  失败:%08x\n", status);
		return status;
	}
	DriverObject->Flags |= DO_BUFFERED_IO;
	status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		DbgPrint("IoCreateSymbolicLink 失败:%08x\n", status);
		return status;
	}
	return status;
}

NTSTATUS ioctl_create(PDEVICE_OBJECT device, PIRP irp) 
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ioctl_close(PDEVICE_OBJECT device, PIRP irp) 
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS unload_driver(PDRIVER_OBJECT driver) 
{
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(drv_dos_device);
	PDEVICE_OBJECT  DeleteDeviceObject = NULL;
	IoDeleteSymbolicLink(&dosDeviceName);
	DeleteDeviceObject = driver->DeviceObject;
	IoDeleteDevice(DeleteDeviceObject);
	DbgPrint("驱动卸载成功\n");
}

NTSTATUS io_device_control(PDEVICE_OBJECT device, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0;
	ULONG outputBufferLength = 0;
	ULONG ioControlCode = 0;
	ULONG IoControlCode = 0;


	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	switch (IoControlCode)
	{
		case ReadWriteMemory://读写内存
		{
			if (inputBufferLength >= sizeof(COPY_MEMORY) && ioBuffer)
				Irp->IoStatus.Status = BBCopyMemory((PCOPY_MEMORY)ioBuffer);
			else
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		break;
		case GetModelBaseadder://获取模块
		{
			//DbgBreakPoint();
			if (inputBufferLength >= sizeof(PGET_PROCESSMODE) && ioBuffer&& outputBufferLength >= sizeof(ALLOCATE_FREE_MEMORY_RESULT))
			{

				ALLOCATE_FREE_MEMORY_RESULT result = { 0 };
				Irp->IoStatus.Status = BBGetUserModule((PGET_PROCESSMODE)ioBuffer, &result);
				if (NT_SUCCESS(Irp->IoStatus.Status))
				{
					RtlCopyMemory(ioBuffer, &result, sizeof(result));
					Irp->IoStatus.Information = sizeof(result);
				}
			}
			else
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		break;
		case IOCTL_BLACKBONE_GRANT_ACCESS://句柄提权
		{
			if (inputBufferLength >= sizeof(HANDLE_GRANT_ACCESS) && ioBuffer)
				Irp->IoStatus.Status = BBGrantAccess((PHANDLE_GRANT_ACCESS)ioBuffer);
			else
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		break;
		case Get_Right_ACCESS://测试
		{
	/*		DbgBreakPoint();*/
			if (inputBufferLength >= sizeof(HANDLE_Right_ACCESS) && ioBuffer)
				Irp->IoStatus.Status = BBGrantAccessTest((PHANDLE_Right_ACCESS)ioBuffer);
			else
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;

		}
		break;
		case IOCTL_BLACKBONE_ALLOCATE_FREE_MEMORY://释放内存
		{
			if (inputBufferLength >= sizeof(ALLOCATE_FREE_MEMORY) &&
				outputBufferLength >= sizeof(ALLOCATE_FREE_MEMORY_RESULT) &&
				ioBuffer)
			{
				ALLOCATE_FREE_MEMORY_RESULT result = { 0 };	
				Irp->IoStatus.Status = BBAllocateFreeMemory((PALLOCATE_FREE_MEMORY)ioBuffer, &result);
				if (NT_SUCCESS(Irp->IoStatus.Status))
				{
					RtlCopyMemory(ioBuffer, &result, sizeof(result));
					Irp->IoStatus.Information = sizeof(result);
				}
			}
			else
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		break;
		case IOCTL_BLACKBONE_PROTECT_MEMORY://修改内存属性
		{
			if (inputBufferLength >= sizeof(PROTECT_MEMORY) && ioBuffer)
				Irp->IoStatus.Status = BBProtectMemory((PPROTECT_MEMORY)ioBuffer);
			else
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		break;
	default:
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		break;
	}


	//
	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  driverObject, PUNICODE_STRING registryPath) {

	NTSTATUS status;

	status = InitializeDevice(driverObject);
	if (!NT_SUCCESS(status))
		DbgPrint("InitializeDevice 创建失败\n");
	SpoofHDD();
	//status = BBInitDynamicData(&dynData);
	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrint("不支持次系统\n");
	//	return status;
	//}
	driverObject->MajorFunction[IRP_MJ_CREATE] = ioctl_create;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = ioctl_close;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = io_device_control;
	driverObject->DriverUnload = unload_driver;


	return STATUS_SUCCESS;
}

