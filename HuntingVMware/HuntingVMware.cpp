#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <Wincrypt.h>

#define BUFFER_SIZE 500

#pragma comment(lib, "crypt32.lib")

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define MY_STRING_TYPE (CERT_OID_NAME_STR)

// LPCWSTR subKey , LPCWSTR pValue => char* resutl

void VMwareIncCheck(LPCWSTR DsubKey, LPCWSTR DpValue){
	HKEY hKey = HKEY_LOCAL_MACHINE;
	LPCWSTR subKey = DsubKey;
	DWORD options = 0;
	REGSAM samDesired = KEY_READ;

	HKEY OpenResult;

	LPCWSTR pValue = DpValue;
	DWORD flags = RRF_RT_ANY;

	//Allocationg memory for a DWORD value.
	DWORD dataType;
	WCHAR value[255];
	PVOID pvData = value;
	DWORD size = sizeof(value);

	LONG err = RegOpenKeyEx(hKey, subKey, options, samDesired, &OpenResult);
	if (err != ERROR_SUCCESS) {
		wprintf(L"The %s subkey could not be opened. Error code: %x\n", subKey, err);
	}
	else
	{
		//wprintf(L"Subkey opened!\n");
		err = RegGetValue(OpenResult, NULL, pValue, flags, &dataType, pvData, &size);
		if (err != ERROR_SUCCESS) {
			wprintf(L"Error getting value. Code: %x\n", err);
		}
		else
		{
			switch (dataType) {
			case REG_DWORD:
				wprintf(L"Value data: %x\n", *(DWORD*)pvData);
				break;
			case REG_SZ:
				//wprintf(L"Value data: %s\n", (PWSTR)pvData);
				char result[BUFFER_SIZE] = "";
				size_t i;
				char* pMBBuffer = (char*)malloc(BUFFER_SIZE);
				const wchar_t* pWCBuffer = (const wchar_t*)pvData;
				wcstombs_s(&i, pMBBuffer, (size_t)BUFFER_SIZE, pWCBuffer, (size_t)BUFFER_SIZE - 1);
				//printf("%s\n", pMBBuffer);
				if (!strcmp(pMBBuffer, "VMware, Inc.")) {
					//printf("[+] HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS registry key \"BIOSVendor\" = \"VMware, Inc.\"");
					strcpy_s(result, BUFFER_SIZE, "\"HKLM\\");
					wcstombs_s(&i, pMBBuffer, (size_t)BUFFER_SIZE, subKey, (size_t)BUFFER_SIZE - 1);
					//printf("pMBBUffer : %s\n", pMBBuffer);
					strcat_s(result, BUFFER_SIZE, pMBBuffer);
					strcat_s(result, BUFFER_SIZE, "\" key , the value \"");
					wcstombs_s(&i, pMBBuffer, (size_t)BUFFER_SIZE, pValue, (size_t)BUFFER_SIZE - 1);
					strcat_s(result, BUFFER_SIZE, pMBBuffer);
					strcat_s(result, BUFFER_SIZE, "\" contains \"VMware, Inc.\"");
					printf("[+] in %s\n", result);
				}

				break;
			}
		}
		RegCloseKey(OpenResult);
	}
}


int main() {
	WIN32_FIND_DATAW FData;
	printf("\n\nLet's Hunt for VMware Artifacts : \n\n");

	printf("[**] In C:\\Windows\\System32 :\n\n");

	if (FindFirstFileW(L"C:\\Windows\\System32\\vm3dc003.dll", &FData))
		printf("[+] Found C:\\Windows\\System32\\vm3dc003.dll\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\VMWSU.dll", &FData))
		printf("[+] Found C:\\Windows\\System32\\VMWSU.dll\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\vm3dservice.exe", &FData))
		printf("[+] Found C:\\Windows\\System32\\vm3dservice.exe\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\vm3ddevapi64.dll", &FData))
		printf("[+] Found C:\\Windows\\System32\\vm3ddevapi64.dll\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\vm3ddevapi64-debug.dll", &FData))
		printf("[+] Found C:\\Windows\\System32\\vm3ddevapi64-debug.dll\n\n");

	printf("[**] In C:\\Windows\\System32\\DriverStore :\n\n");

	if (FindFirstFileW(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dc003.dll", &FData))
		printf("[+] Found C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dc003.dll\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dgl64.dll", &FData))
		printf("[+] Found C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dgl64.dll\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dmp.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dmp.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dmp_loader.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dmp_loader.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dmp_debug.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_e3eb5e2a70444b3f\\vm3dmp_debug.sys\n");

	printf("\n\n[***] In C:\\Windows\\System32\\drivers :\n\n");

	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vm3dmp.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vm3dmp.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vm3dmp_loader.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vm3dmp_loader.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vm3dmp-debug.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vm3dmp-debug.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vm3dmp-stats.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vm3dmp-stats.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vmusbmouse.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vmusbmouse.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vmmemctl.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vmmemctl.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vmmemctl.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vmmemctl.sys\n");
	if (FindFirstFileW(L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys", &FData))
		printf("[+] Found C:\\Windows\\System32\\drivers\\vmrawdsk.sys\n");
	//...
	printf("\n\n[+++] Let's Hunt for VMware registry keys : \n\n");

	printf("[**] In HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services :\n\n");

	HKEY hkResult;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vm3dmp", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS) 
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vm3dmp\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vm3dmp_loader", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vm3dmp_loader\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vm3dmp-debug", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vm3dmp-debug\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vm3dmp-stats", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vm3dmp-stats\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vm3dservice", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vm3dservice\n");

	printf("\n\n[**] In HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS :\n\n");

	LPCWSTR subKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
	LPCWSTR pValue = L"BIOSVendor";

	VMwareIncCheck(subKey, pValue);

	printf("\n\n[**] In HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation :\n\n");

	LPCWSTR subKey2 = L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
	LPCWSTR pValue2 = L"SystemManufacturer";

	VMwareIncCheck(subKey2, pValue2);
	printf("\n\n\n");
	return 0;
	
}