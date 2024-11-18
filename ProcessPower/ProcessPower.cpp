#include <ntddk.h>
#include "ProcessPowerCommon.h"

// Step 1: Create a driver entry point
// Step 2: Create a driver unload routine
// Step 3: Create a device object
// Step 4: Create a device object unload routine
// Step 5: Create a device object create/close routine
// Step 6: Create a device object device control routine
// Step 7: Create a Symbolic Link
// Step 8: Create ProcessPowerCreateClose
// Step 9: Create ProcessPowerDeviceControl

//NTSTATUS is a status code that is returned by functions in the Windows API
void ProcessPowerUnload(PDRIVER_OBJECT);

//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
NTSTATUS ProcessPowerCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS ProcessPowerDeviceControl(PDEVICE_OBJECT, PIRP);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	KdPrint(("ProcessPower: DriverEntry\n"));
	KdPrint(("Registry path: %wZ\n", RegistryPath));

	DriverObject->DriverUnload = ProcessPowerUnload;

	RTL_OSVERSIONINFOW vi = { sizeof(vi) };
	NTSTATUS status = RtlGetVersion(&vi);
	
	//Checking if the function RtlGetVersion failed (status)
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RtlGetVersion failed: %08X\n", status));
		return status;
	}

	KdPrint(("Windows version: %u.%u.%u\n", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber));

	//Setting the major function pointers to the functions that will be called when the IRP_MJ_CREATE, IRP_MJ_CLOSE, and IRP_MJ_DEVICE_CONTROL requests are received
	//IRP_MJ_CREATE and IRP_MJ_CLOSE are used for opening and closing the device (opening and closing handles to the device)
	//IRP_MJ_DEVICE_CONTROL is used for sending IOCTLs to the device

	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessPowerCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessPowerCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcessPowerDeviceControl;

	//UNICODE_STRING is a structure that contains a pointer to a string and the length of the string and is at compile time
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\ProcessPower");

	//RtlInitUnicodeString is a macro that initializes a unicode string
	//RtlInitUnicodeString(&devName, L"\\Device\\ProcessPower");

	//First Parameter Driver Object pointing to the Device Object
	//Second Parameter Device extension size is how many bytes I would like to allocate for the device object beyond the size of the device object itself
	//Third parameter is the name of the device object
	//Fourth parameter is the type of device object (can use unknown for generic device objects)
	//Fifth parameter is the characteristics of the device object
	//Sixth parameter is exclusive (if set to true, only one handle can be opened to the device object at a time) -
	// whether I can allow mre than one file object pointing to my device or not, some device like the serial port should be exclusive
	//Seventh parameter is the address of the device object pointer

	PDEVICE_OBJECT DeviceObject;
	status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	//Checking if the function IoCreateDevice failed (status)
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed in IoCreateDevice (0x%X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\ProcessPower");
	status = IoCreateSymbolicLink(&symLink, &devName);

	//Checking if the function IoCreateSymbolicLink failed (status)
	if (!NT_SUCCESS(status))
	{
		//If the symbolic link fails,delete the device object as to not keep on restarting to delete the device object instead
		IoDeleteDevice(DeviceObject);
		KdPrint(("Failed in IoCreateSymbolicLink (0x%X)\n", status));
		return status;
	}

	return STATUS_SUCCESS;
};

//All the device objects are stored as a linked list on the driver object, 
// therefore the first device object is piointed to by the field DeviceObject (a more elegant solutuion rather than using 
// a global variable to store the device object -- PDEVICE_OBJECT DeviceObject;)

//The reason to use this solution, the problem will be that the driver will not load properly, hence I will have to restart the system
void ProcessPowerUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("ProcessPower: Unload\n"));
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\ProcessPower");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
};

//IRP is an I/O Request Packet, which is a data structure that describes an I/O request
NTSTATUS ProcessPowerCreateClose(PDEVICE_OBJECT, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

NTSTATUS ProcessPowerDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	auto& dic = stack->Parameters.DeviceIoControl;
	ULONG len = 0;

	//Checking if the IOCTL code is equal to IOCTL_OPEN_PROCESS
	switch (dic.IoControlCode) {
		case IOCTL_OPEN_PROCESS:
			//Checking if the input buffer and output buffer are not null
			if(dic.Type3InputBuffer == nullptr || Irp->UserBuffer == nullptr){
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (dic.InputBufferLength < sizeof(ProcessPowerInput) || dic.OutputBufferLength < sizeof(ProcessPowerOutput)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			 
			auto input = (ProcessPowerInput*)dic.Type3InputBuffer;
			auto output = (ProcessPowerOutput*)Irp->UserBuffer;

			OBJECT_ATTRIBUTES attr;
			InitializeObjectAttributes(&attr, nullptr, 0, nullptr, nullptr);
			CLIENT_ID cid = { 0 };
			cid.UniqueProcess = UlongToHandle(input->processId);

			status = ZwOpenProcess(&output->hProcess, PROCESS_ALL_ACCESS, &attr, &cid);
			
			if (NT_SUCCESS(status)) {
				len = sizeof(output);
			}
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, 0);
	return status;
}

//I checked if the device object was created using the winObj tool from sysinternals by checking the "devices tab"