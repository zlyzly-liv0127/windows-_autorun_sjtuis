#include "mythread_5.h"

mythread_5::mythread_5()
{

}
void mythread_5::run()
{
    emit title_5("HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls", 0);
    //get_task();
    HKEY hTestKey;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        QueryKey(hTestKey);
    }
}
void mythread_5::QueryKey(HKEY hKey)
{
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

        LPSTR  achValue;
        DWORD cchValue = MAX_VALUE_NAME;
        DWORD Type;
        LPBYTE  Data;
        DWORD cbData;
        string a;


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

        if (cValues)
        {
            printf("\nNumber of values: %d\n", cValues);

            for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
            {
                cchValue = MAX_VALUE_NAME;
                achValue = (LPSTR)malloc(cchValue);
                achValue[0] = '\0';
                cbData = cbMaxValueData + 256;
                //TCHAR Data[300];
                Data = (LPBYTE)malloc(cbData);
                Data[0] = '\0';


                retCode = RegEnumValueA(hKey, i,
                    achValue,
                    &cchValue,
                    NULL,
                    &Type,
                    Data,
                    &cbData);



                if (retCode == ERROR_SUCCESS)
                {

                    emit content_5((QString)(achValue), 0);
                    a = string_test((char *)(Data), 0);
                    emit content_5(QString::fromStdString(a), 1);
                    emit content_5((QString)(achValue), 0);
                    a = string_test((char *)(Data), 1);
                    emit content_5(QString::fromStdString(a), 1);
                    }
                }
            }

}
string mythread_5::string_test(const char* a, int flag)
{
    string b;
    if(flag == 1)
    {
        b = "c:\\windows\\SysWOW64\\";
    }
    else if(flag == 0)
    {
        b = "c:\\windows\\system32\\";
    }
    for (int i = 0;a[i]; i++)
    {
        b += a[i];
    }
    return b;
}
