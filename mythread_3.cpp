#include "mythread_3.h"

mythread_3::mythread_3()
{

}
void mythread_3::run()
{
    //DoQuerySvc("1394ohci");
    HKEY hTestKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("System\\CurrentControlSet\\Services"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        emit title_3("HKLM\\System\\CurrentControlSet\\Services", 0);
        //emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }


}
void mythread_3::DoQuerySvc(const char* svc)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    LPQUERY_SERVICE_CONFIGA lpsc = NULL;
    LPSERVICE_DESCRIPTION lpsd = NULL;
    DWORD dwBytesNeeded, cbBufSize, dwError;
    string b;
    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(
        NULL,                    // local computer
        SERVICES_ACTIVE_DATABASE,                    // ServicesActive database
        SC_MANAGER_ENUMERATE_SERVICE);  // full access rights

    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    schService = OpenServiceA(
        schSCManager,          // SCM database
        svc,             // name of service
        SERVICE_QUERY_CONFIG); // need query config access

    if (schService == NULL)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Get the configuration information.

    if (!QueryServiceConfigA(
        schService,
        NULL,
        0,
        &dwBytesNeeded))
    {
        dwError = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == dwError)
        {
            cbBufSize = dwBytesNeeded;
            lpsc = (LPQUERY_SERVICE_CONFIGA)LocalAlloc(LMEM_FIXED, cbBufSize);
        }
        else
        {
            printf("QueryServiceConfig failed (%d)", dwError);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            //return;
        }
    }


    if (!QueryServiceConfigA(
        schService,
        lpsc,
        cbBufSize,
        &dwBytesNeeded))
    {
        printf("QueryServiceConfig failed (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        //return;
    }
    lpsd = (LPSERVICE_DESCRIPTION)LocalAlloc(LMEM_FIXED, cbBufSize);
    if (!QueryServiceConfig2A(
        schService,
        SERVICE_CONFIG_DESCRIPTION,
        NULL,
        0,
        &dwBytesNeeded))
    {
        dwError = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == dwError)
        {
            cbBufSize = dwBytesNeeded;
            lpsd = (LPSERVICE_DESCRIPTION)LocalAlloc(LMEM_FIXED, cbBufSize);
        }
        else
        {
            printf("QueryServiceConfig2 failed (%d)", dwError);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            //return;
        }
    }

    if (!QueryServiceConfig2(
        schService,
        SERVICE_CONFIG_DESCRIPTION,
        (LPBYTE)lpsd,
        cbBufSize,
        &dwBytesNeeded))
    {
        printf("QueryServiceConfig2 failed (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        //return;
    }

    // Print the configuration information.

    //printf("%s configuration: \n", svc);
    //printf("  Type: 0x%x\n", lpsc->dwServiceType);
    if (lpsc->dwServiceType == SERVICE_WIN32_SHARE_PROCESS)
    {
        printf("1\n");
    }
    else if (lpsc->dwServiceType == SERVICE_WIN32_OWN_PROCESS)
    {
        printf("2\n");
    }
    else if (lpsc->dwServiceType == SERVICE_FILE_SYSTEM_DRIVER)
    {
        printf("3\n");
    }
    else if (lpsc->dwServiceType == SERVICE_KERNEL_DRIVER)
        printf("4\n");
    else if (lpsc->dwServiceType == SERVICE_INTERACTIVE_PROCESS)
        printf("5\n");
    //printf("  Start Type: 0x%x\n", lpsc->dwStartType);
    //printf("  Error Control: 0x%x\n", lpsc->dwErrorControl);
    //printf("  Binary path: %s\n", (char *)lpsc->lpBinaryPathName);

    //char b[16];
    //s = lpsc->lpDisplayName;
    //s.append(":");
    //TcharToChar(lpsd->lpDescription, b);
    //s.append(s2);
    QString a;
    a = QString::fromWCharArray(lpsd->lpDescription);
    if(lpsc->dwServiceType == SERVICE_KERNEL_DRIVER || lpsc->dwServiceType == SERVICE_FILE_SYSTEM_DRIVER)
    {
        emit content_3((QString)svc, 0);
        //emit content_3((QString)(char *)(lpsc->lpBinaryPathName), 1);
        b = string_test(lpsc->lpBinaryPathName) ;
        emit content_3(QString::fromStdString(b), 1);
        emit content_3((QString)QString::fromLocal8Bit(lpsc->lpDisplayName), 2);
        //if (lpsd->lpDescription != NULL && lstrcmp(lpsd->lpDescription, TEXT("")) != 0);
            {emit content_3(a, 3);}
    }
    //printf("  Account: %s\n", (char *)lpsc->lpServiceStartName);
    //printf("  DisplayName: %s\n", (char*)lpsc->lpDisplayName);
    //emit content_3((QString)(char *)lpsc->lpDisplayName, 2);
    if (lpsd->lpDescription != NULL && lstrcmp(lpsd->lpDescription, TEXT("")) != 0)
        printf("  Description: %s\n", (char *)lpsd->lpDescription);
   // if (lpsc->lpLoadOrderGroup != NULL && lstrcmp(lpsc->lpLoadOrderGroup, TEXT("")) != 0)
       // printf("  Load order group: %s\n", lpsc->lpLoadOrderGroup);
    //if (lpsc->dwTagId != 0)
       // printf("  Tag ID: %d\n", lpsc->dwTagId);
   // if (lpsc->lpDependencies != NULL && lstrcmp(lpsc->lpDependencies, TEXT("")) != 0)
        //printf("  Dependencies: %s\n", lpsc->lpDependencies);

    LocalFree(lpsc);
    LocalFree(lpsd);
}
void mythread_3::QueryKey(HKEY hKey)
{
    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name
    DWORD    cchClassName = MAX_PATH;  // size of class string
    DWORD    cSubKeys = 0;               // number of subkeys
    DWORD    cbMaxSubKey;              // longest subkey size
    DWORD    cchMaxClass;              // longest class string
    DWORD    cValues;              // number of values for key
    DWORD    cchMaxValue;          // longest value name
    DWORD    cbMaxValueData;       // longest value data
    DWORD    cbSecurityDescriptor; // size of security descriptor
    FILETIME ftLastWriteTime;      // last write time

    DWORD i, retCode;
    char a[256];


    // Get the class name and the value count.
    retCode = RegQueryInfoKey(
        hKey,                    // key handle
        achClass,                // buffer for class name
        &cchClassName,           // size of class string
        NULL,                    // reserved
        &cSubKeys,               // number of subkeys
        &cbMaxSubKey,            // longest subkey size
        &cchMaxClass,            // longest class string
        &cValues,                // number of values for this key
        &cchMaxValue,            // longest value name
        &cbMaxValueData,         // longest value data
        &cbSecurityDescriptor,   // security descriptor
        &ftLastWriteTime);       // last write time

        if (cSubKeys)
        {
            printf("\nNumber of subkeys: %d\n", cSubKeys);
            //emit content_3("ss", 0);
            for (i = 0; i < cSubKeys; i++)
            {
                cbName = MAX_KEY_LENGTH;
                retCode = RegEnumKeyEx(hKey, i,
                    achKey,
                    &cbName,
                    NULL,
                    NULL,
                    NULL,
                    &ftLastWriteTime);
                if (retCode == ERROR_SUCCESS)
                {
                    //printf("(%d) %s\n", i + 1, achKey);
                    TcharToChar(achKey, a);
                    DoQuerySvc(a);
                }
            }
        }
}
void mythread_3::TcharToChar(const TCHAR* tchar, char* _char)
{
    int iLength;
    //获取字节长度
    iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
    //将tchar值赋给_char
    WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}
void mythread_3::Wchar_tToString(string& szDst, wchar_t *wchar)
{
    wchar_t * wText = wchar;
    DWORD dwNum = WideCharToMultiByte(CP_OEMCP,NULL,wText,-1,NULL,0,NULL,FALSE);// WideCharToMultiByte的运用
    char *psText; // psText为char*的临时数组，作为赋值给std::string的中间变量
    psText = new char[dwNum];
    WideCharToMultiByte (CP_OEMCP,NULL,wText,-1,psText,dwNum,NULL,FALSE);// WideCharToMultiByte的再次运用
    szDst = psText;// std::string赋值
    delete []psText;// psText的清除
}
//字符串处理函数
string mythread_3::string_test(const char* a)
{
    int flag = 0;
    int flag2 = 0;
    string b = "c:\\windows\\system32\\";
    string c = "SysWOW64";
    if (strstr(a, c.c_str()) != NULL)
    {
        b = "c:\\windows\\SysWOW64\\";
    }
    for (int i = 0;; i++)
    {
        if (a[i] == '\0')
            //cout << a[i];
            break;
        if ((flag == 1)&&(flag2 == 0))
        {
            if ((a[i] == 'r') || (a[i] == 'R'))
            {
                flag = 1;
                flag2 = 1;
            }
            else
            {
                flag = 0;
                b = b.substr(0, b.length() - 1);//去除这个字符
            }
        }
        if ((a[i] == 'd' || a[i] == 'D')||(flag == 1))
        {
            flag = 1;
            //cout << b;
            b += a[i];
            //cout << b;
        }
    }
    return b;
}
