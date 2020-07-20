#include "mythread_4.h"

mythread_4::mythread_4()
{

}
void mythread_4::run()
{
    emit title_4("Task Scheduler", 0);
    get_task();
}

void mythread_4::get_task()
{
    //  Initialize COM.
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr))
        {
            printf("\nCoInitializeEx failed: %x", hr);
            return;
        }

        //  Set general COM security levels.
        hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            0,
            NULL);

        if (FAILED(hr))
        {
            printf("\nCoInitializeSecurity failed: %x", hr);
            CoUninitialize();
            return;
        }

        //  ------------------------------------------------------
        //  Create an instance of the Task Service.
        ITaskService* pService = NULL;
        hr = CoCreateInstance(CLSID_TaskScheduler,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_ITaskService,
            (void**)&pService);
        if (FAILED(hr))
        {
            printf("\nFailed to CoCreate an instance of the TaskService class: %x", hr);
            CoUninitialize();
            return;
        }

        //  Connect to the task service.
        hr = pService->Connect(_variant_t(), _variant_t(),
            _variant_t(), _variant_t());
        if (FAILED(hr))
        {
            printf("\nITaskService::Connect failed: %x", hr);
            pService->Release();
            CoUninitialize();
            return;
        }

        //  ------------------------------------------------------
        //  Get the pointer to the root task folder.
        ITaskFolder* pRootFolder = NULL;
        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (FAILED(hr))
        {
            printf("\nCannot get Root Folder pointer: %x", hr);
            return;
        }
        walkFoldersFormat(pRootFolder, hr);
        pRootFolder->Release();


        pService->Release();
        CoUninitialize();
        return;
}
void mythread_4::walkFoldersFormat(ITaskFolder* rootFolder, HRESULT hr) {
    ITaskFolderCollection* pFolders = NULL;
    //获得根目录下的所有子目录
    BSTR name2 = NULL;
    hr = rootFolder->get_Name(&name2);
    hr = rootFolder->GetFolders(0, &pFolders);
    getTasksFormat(rootFolder, hr);
    wchar2strstring(tmp, name2);
    SysFreeString(name2);
    if(a != "")
    {
        a += "\\";
    }

    a.append(tmp);
    if (FAILED(hr))
    {
        //当前目录下无子目录
        printf("\nCannot get Folders: %x", hr);
        //wchar2strstring(tmp, name2);
        //a.erase(a.length()-tmp.length());
        return;
    }

    LONG numFolders = 0;
    hr = pFolders->get_Count(&numFolders);
    //printf("Number of Folders:%d", numFolders);
    //遍历当前子目录
    if (numFolders != 0) {
        for (LONG i = 0; i < numFolders; i++) {
            ITaskFolder* pRootFolder = NULL;
            hr = pFolders->get_Item(_variant_t(i + 1), &pRootFolder);
            if (SUCCEEDED(hr)) {
                BSTR name = NULL;
                hr = pRootFolder->get_Name(&name);

                //hr = rootFolder->get_Name(&name2);//获得根目录的名字
                if (FAILED(hr))
                {
                    printf("\nCannot get Folder name: %x", hr);
                    return;
                }

                walkFoldersFormat(pRootFolder, hr);
                wchar2strstring(tmp, name);
                a.erase(a.length() - tmp.length() - 1);
                //cout << "退出目录" << a << endl;
                SysFreeString(name);
            }
            else
                printf("\n\tCannot get the folder name: %x", hr);
        }
        //wchar2strstring(tmp, name2);
        //a.erase(a.length()-tmp.length()-1);
        pFolders->Release();
        //name2 = NULL;
    }
}
// Get the registered tasks in the folder
void mythread_4::getTasksFormat(ITaskFolder* rootFolder, HRESULT hr) {
    IRegisteredTaskCollection* pTaskCollection = NULL;
    hr = rootFolder->GetTasks(NULL, &pTaskCollection);
    CHAR  infoBuf[INFO_BUFFER_SIZE];
    if (FAILED(hr))
    {
        printf("\n\tCannot get the registered tasks.: %x", hr);
        return;
    }

    LONG numTasks = 0;
    hr = pTaskCollection->get_Count(&numTasks);

    if (numTasks == 0)
    {
        //当前目录下无task
        printf("\n\tNo Tasks are currently running");
        //a.erase(a.length()-tmp.length()-1);
        pTaskCollection->Release();
        return;
    }

    //printf("\nNumber of Tasks : %d", numTasks);

    TASK_STATE taskState;

    for (LONG i = 0; i < numTasks; i++)
    {
        IRegisteredTask* pRegisteredTask = NULL;
        hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

        if (SUCCEEDED(hr))
        {
            BSTR taskName = NULL;
            hr = pRegisteredTask->get_Name(&taskName);
            if (SUCCEEDED(hr))
            {
                //emit content_4((QString)(char *)taskName, 0);
                //printf("\n\tTaskName: %S", taskName);
                wchar2strstring(tmp, taskName);
                SysFreeString(taskName);
                a += '\\';
                a.append(tmp);
                emit content_4(QString::fromStdString(a), 0);
                a.erase(a.length()-tmp.length()-1);
                hr = pRegisteredTask->get_State(&taskState);
                if (SUCCEEDED(hr))
                {
                    printf("\n\tState: %d", taskState);
                    switch((int)taskState)
                    {
                        case 0: {emit content_4("TASK_STATE_UNKNOWN", 2);break;}
                        case 1: {emit content_4("TASK_STATE_DISABLED", 2);break;}
                        case 2: {emit content_4("TASK_STATE_QUEUED", 2);break;}
                        case 3: {emit content_4("TASK_STATE_READY", 2);break;}
                        case 4: {emit content_4("TASK_STATE_RUNNING", 2);break;}
                    }
                }
                else
                    printf("\n\tCannot get the registered task state: %x", hr);

                ITaskDefinition* taskDefination = NULL;
                hr = pRegisteredTask->get_Definition(&taskDefination);
                if (FAILED(hr))
                {
                    printf("\n\tCannot get the task defination: %x", hr);
                    return;
                }

                IActionCollection* taskActions = NULL;
                hr = taskDefination->get_Actions(&taskActions);
                if (FAILED(hr))
                {
                    printf("\n\tCannot get the task actions: %x", hr);
                    return;
                }
                taskDefination->Release();

                /*LONG numActions = 0;
                hr = taskActions->get_Count(&numActions);
                if (SUCCEEDED(hr))
                    printf("\n\tCount of Actions: %d", numActions);
                else
                    printf("\n\tCannot get the number of actions: %x", hr);*/

                IAction* action = NULL;
                hr = taskActions->get_Item(1, &action);
                if (FAILED(hr))
                {
                    printf("\n\tCannot get the action: %x", hr);
                    return;
                }
                taskActions->Release();

                IExecAction* execAction = NULL;
                hr = action->QueryInterface(IID_IExecAction, (void**)&execAction);
                if (FAILED(hr))
                {
                    printf("\n\tQueryInterface call failed for IExecAction: %x", hr);
                    return;
                }
                action->Release();

                BSTR imagePath = NULL;
                hr = execAction->get_Path(&imagePath);
                wchar2strstring(tmp, imagePath);

                //展开%%的重定向
                ExpandEnvironmentStringsA((LPCSTR)(tmp.c_str()), infoBuf,
                    INFO_BUFFER_SIZE);
                emit content_4(QString::fromLocal8Bit(infoBuf), 1);
                //emit content_4(QString::fromLocal8Bit(tmp.c_str()), 1);
                if (SUCCEEDED(hr))
                    printf("\n\tImage Path: %S", imagePath);
                else
                    printf("\n\tCannot get the image path: %x", hr);
                execAction->Release();
            }
            else
            {
                printf("\n\tCannot get the registered task name: %x", hr);
            }
            pRegisteredTask->Release();
        }
        else
        {
            printf("\n\tCannot get the registered task item at index=%d: %x", i + 1, hr);
        }
    }
    //wchar2strstring(tmp, name2);
    //a.erase(a.length()-tmp.length());
    pTaskCollection->Release();
}


void mythread_4::wchar2strstring(std::string & szDst,WCHAR * wchart)
{
    wchar_t * wtext = wchart;
    DWORD dwNmu = WideCharToMultiByte(CP_OEMCP,NULL,wtext,-1,NULL,0, NULL,FALSE);
    char * psTest;
    psTest = new char[dwNmu];
    WideCharToMultiByte(CP_OEMCP, NULL, wtext, -1, psTest, dwNmu, NULL, FALSE);
    szDst = psTest;
    delete[]psTest;
}
