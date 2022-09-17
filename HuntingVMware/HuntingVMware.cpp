#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <string.h>
#include <Wincrypt.h>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>

using namespace std;
#define BUFFER_SIZE 500

#pragma comment(lib, "crypt32.lib")

#include <Iphlpapi.h>
#include <Assert.h>
#pragma comment(lib, "iphlpapi.lib")

char* getMAC();

int Error(const char* msg) {
	printf("%s (%u)", msg, GetLastError());
	return -1;
}
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

char* get3MAC() {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);
	char* mac3 = (char*)malloc(9);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return NULL; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return NULL;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// technically should look at pAdapterInfo->AddressLength
			//   and not assume it is 6.
			
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("[+] the MAC Address :  %s\n" ,mac_addr);
			sprintf(mac3, "%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2]);
			
			// print them all, return the last one.
			// return mac_addr;

			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
	return mac3; // caller must free.
}


void VMwareMACCheck() {
	// Looking for a MAC address starting with 00:05:69, 00:0C:29, 00:1C:14 or 00:50:56
	char* mac3 = get3MAC();
	if (!strcmp(mac3, "00:05:69") || !strcmp(mac3, "00:0C:29") || !strcmp(mac3, "00:1C:14") || !strcmp(mac3, "00:50:56"))
		printf("[+] VMware MAC address detected starting with %s\n", mac3);
	free(mac3);
}

string exec(string command) {
	char buffer[128];
	string result = "";

	// Open pipe to file
	FILE* pipe = _popen(command.c_str(), "r");
	if (!pipe) {
		return "popen failed!";
	}

	// read till end of process:
	while (!feof(pipe)) {

		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}

	_pclose(pipe);
	return result;
}

void VMserialNumber() {
	string dir = exec("wmic bios get serialnumber");
	
	if (dir.find("VMware") != string::npos) {
		cout << "\n[+] Found : " << dir;;
	}
}

int main() {
	printf("\n\n[***]Let's Hunt for VMware Running Processes : \n\n");

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot)
		return Error("Failed in CreateToolhelp32Snapshot\n");

	PROCESSENTRY32 PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &PE32))
		return Error("Failed in Process32First\n");

	while (Process32Next(hSnapshot, &PE32)) {

				//printf("ImageName : %ws\n", PE32.szExeFile);
		size_t i;
		char* pMBBuffer = (char*)malloc(BUFFER_SIZE);
		const wchar_t* pWCBuffer = PE32.szExeFile;
		wcstombs_s(&i, pMBBuffer, (size_t)BUFFER_SIZE, pWCBuffer, (size_t)BUFFER_SIZE - 1); 

		if (!strcmp("vmtoolsd.exe", pMBBuffer)) 
			printf("[+] vmtoolsd.exe detected\n");

			if (!strcmp("vm3dservice.exe", pMBBuffer))
				printf("[+] vm3dservice.exe detected\n");

			if (!strcmp("VGAuthService.exe", pMBBuffer))
				printf("[+] vmtoolsd.exe detected\n");
	}

	WIN32_FIND_DATAW FData;
	printf("\n\n[***]Let's Hunt for VMware Artifacts : \n\n");

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

	printf("[**] In HKEY_LOCAL_MACHINE\\SOFTWARE :\n\n");

	HKEY hkResult;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Drivers", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware Drivers\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware Tools\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware VGAuth", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware VGAuth\n");
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMwareHostOpen", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS)
		printf("[+] Found Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMwareHostOpen\n");

	printf("\n\n[**] In HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services :\n\n");

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


	printf("\n\n[+++]Looking for a MAC address starting with 00:05:69, 00:0C:29, 00:1C:14 or 00:50:56\n\n");
	VMwareMACCheck();

	printf("\n\n[+++] Let's Hunt for VMware Serial Number : \n\n");
	VMserialNumber();
	

	printf("\n\n\n");
	return 0;
	
}