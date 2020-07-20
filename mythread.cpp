#include "mythread.h"
#include <vector>
#include <string>
#include <QString>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>

#include <io.h>
#include <shlobj.h>

#define INFO_BUFFER_SIZE 32767
using namespace std;
mythread::mythread()
{

}

void mythread::run()
{

    HKEY hTestKey;
    //HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
    emit title("HKCU\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //emit title("HKCU\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
    emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
    emit title("HKCU\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //emit title("HKCU\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
    emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
    emit title("HKCU\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //emit title("HKCU\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
    emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        //emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
        //打开键成功就执行
        QueryKey(hTestKey);
    }

    //C:\Users\hp\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    vector<string> file;
    string str = "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    CHAR infoBuf[256];
    ExpandEnvironmentStringsA((LPCSTR)str.c_str(), infoBuf,
        INFO_BUFFER_SIZE);
    emit title(QString(infoBuf), 0);
    find_file(infoBuf, file);
    //C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    emit title("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", 0);
    find_file("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", file);


    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
    HKEY hk;
    LPBYTE  Data;
    DWORD cbData = 2048;
    Data = (LPBYTE)malloc(cbData);
    //Data[0] = '\0';
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("Userinit"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("Userinit", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AppSetup
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AppSetup", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("AppSetup"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("AppSetup", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VMApplet
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\VMApplet", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("VMApplet"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("VmApplet", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VMApplet
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\VMApplet", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("VMApplet"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("VmApplet", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("Taskman"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("Taskman", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AlternateShells
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AlternateShells"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AlternateShells\\AlternateShells", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("AlternateShells"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("AlternateShells", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("InitialProgram"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("InitialProgram", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("Shell"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content("Shell", 0);
            emit content((QString)(char *)Data, 1);
        }
    }
    //HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("StartupPrograms"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content((QString)(char *)Data, 0);
            //emit content((QString)(char *)Data, 1);
            string a;
            a = string_test((char *)Data, 1);
            emit content(QString::fromStdString(a), 1);
        }
    }
    //HKLM\Software\Policies\Microsoft\Windows\System\Scripts\Startup
    emit title("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Policies\Microsoft\Windows\System\Scripts\Logon
    emit title("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Policies\Microsoft\Windows\System\Scripts\Logon
    emit title("HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Policies\Microsoft\Windows\System\Scripts\Shutdown
    emit title("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Policies\Microsoft\Windows\System\Scripts\Logoff
    emit title("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Policies\Microsoft\Windows\System\Scripts\Logoff
    emit title("HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Runonce", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Runonce"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Runonce", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Runonce"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System1"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows CE Services\AutoStartOnConnect
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnConnect", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnConnect"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnConnect
    emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\AutoStartOnConnect", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\AutoStartOnConnect"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows CE Services\AutoStartOnDisConnect
    emit title("HKLM\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnDisConnect", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnDisConnect"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnDisConnect
    emit title("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\AutoStartOnDisConnect", 0);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\AutoStartOnDisConnect"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run
    emit title("HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run", 0);
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {

        //打开键成功就执行
        QueryKey(hTestKey);
    }
    //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("Shell"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content((QString)(char *)Data, 0);
            //emit content((QString)(char *)Data, 1);
            string a;
            a = string_test((char *)Data, 1);
            emit content(QString::fromStdString(a), 1);
        }
    }
    //HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
    if(RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("Shell"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content((QString)(char *)Data, 0);
            //emit content((QString)(char *)Data, 1);
            string a;
            a = string_test((char *)Data, 1);
            emit content(QString::fromStdString(a), 1);
        }
    }
    //HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), 0, KEY_READ, &hk) == ERROR_SUCCESS)
    {
        emit title("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell", 0);
        if(RegGetValueA(hk, NULL, (LPCSTR)("AlternateShell"), RRF_RT_ANY, NULL, Data, &cbData) == ERROR_SUCCESS)
        {
            emit content((QString)(char *)Data, 0);
            //emit content((QString)(char *)Data, 1);
            string a;
            a = string_test((char *)Data, 0);
            emit content(QString::fromStdString(a), 1);
        }
    }

}
void mythread::QueryKey(HKEY hKey)
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
        CHAR  infoBuf[INFO_BUFFER_SIZE];//for ExpandEnvironmentStrings API


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
            //printf("\nNumber of values: %d\n", cValues);
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
                    if(Type == REG_EXPAND_SZ)
                    {
                        emit content((QString)(achValue), 0);
                        //展开%%的重定向
                        ExpandEnvironmentStringsA((LPCSTR)(char *)Data, infoBuf,
                            INFO_BUFFER_SIZE);
                        emit content((QString)(infoBuf), 1);
                    }
                    else{
                    emit content((QString)(achValue), 0);
                    emit content((QString)(char *)(Data), 1);
                    }
                }
            }
        }
}
void mythread::TcharToChar(const TCHAR* tchar, char* _char)
{
    int iLength;
    //获取字节长度
    iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
    //将tchar值赋给_char
    WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

bool mythread::GetShellPath(const char* Src, LPWSTR ShellPath)

{

    bool blret = false;

    ::CoInitialize(NULL); //初始化COM运行环境

    IShellLink* psl = NULL;

    //创建COM接口，IShellLink对象创建

    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);

    if (SUCCEEDED(hr))

    {

        IPersistFile* ppf;
        hr = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

        if (SUCCEEDED(hr))

        {

            WCHAR wsz[MAX_PATH];

            MultiByteToWideChar(CP_ACP, 0, Src, -1, wsz, MAX_PATH);    //转下宽字节

            hr = ppf->Load(wsz, STGM_READ);    //加载文件

            if (SUCCEEDED(hr))
            {

                WIN32_FIND_DATA wfd;

                psl->GetPath(ShellPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_SHORTPATH);  //获取目标路径

                blret = true;

            }

            ppf->Release();
        }
        psl->Release();  //释放对象

    }

    ::CoUninitialize();   //释放COM接口


    return blret;

}
//遍历特定文件夹下的文件
void mythread::find_file(const char* mainDir, vector<string>& files)
{
    files.clear();//清空文件
    intptr_t hFile;
    _finddata_t fileinfo;
    char findDir[250];
    strcpy_s(findDir, mainDir);
    strcat_s(findDir, "\\*.lnk");
    TCHAR ShellPath[250];
    char ShellPath_char[250];
    if ((hFile = _findfirst(findDir, &fileinfo)) != -1)
    {
        do
        {
            if (!(fileinfo.attrib & _A_SUBDIR))//find fold
            {
                if (fileinfo.name[0] == '.') //avoid . ..
                    continue;
                char filename[_MAX_PATH];
                strcpy_s(filename, mainDir);
                strcat_s(filename, "\\");
                strcat_s(filename, fileinfo.name);
                string temfilename = filename;
                files.push_back(temfilename);
                //cout << temfilename << endl;
                emit content(QString::fromLocal8Bit(temfilename.c_str()), 0);
                GetShellPath(temfilename.c_str(), ShellPath);
                TcharToChar(ShellPath, ShellPath_char);
                //printf("%s\n", ShellPath_char);
                emit content((QString)(ShellPath_char), 1);
            }
        } while (_findnext(hFile, &fileinfo) == 0);
        _findclose(hFile);
    }
}
string mythread::string_test(const char* a, int flag)
{

    string b;
    if(flag == 1)
    {
        b = "c:\\windows\\system32\\";
        for (int i = 0;a[i]; i++)
        {
            b += a[i];
        }
        b.append(".exe");
    }
    else if(flag == 0)
    {
        b = "c:\\windows\\system32\\";
        for (int i = 0;a[i]; i++)
        {
            b += a[i];
        }
    }

    return b;
}


