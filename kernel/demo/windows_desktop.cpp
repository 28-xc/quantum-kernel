#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <commdlg.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_CAP 32768
#define WINDOW_CLASS L"CACR2026LatticeDemoLauncher"
#define OPEN_PAGE 101
#define OPEN_LOG 102
#define CLOSE_DEMO 103
#define WM_OPEN_EXISTING_INSTANCE (WM_APP+1)
#define WM_SAVE_RESULT (WM_APP+2)
#define WM_PICK_TEXT_FILE (WM_APP+3)
static HWND window, status_label, detail_label, progress, open_button;
static HANDLE process, job, log_handle, instance_mutex;
static HFONT font;
static HWND startup_panel;
static HFONT startup_title_font, startup_small_font;
static ULONGLONG startup_painted;
static void finish_startup_panel(void);
static void resize_startup_panel(void);
static wchar_t exe_dir[PATH_CAP], package[PATH_CAP], cache[PATH_CAP], run_dir[PATH_CAP];
static wchar_t log_path[PATH_CAP], stop_path[PATH_CAP], browser_url[512];
static int headless=0, start_history=0, ready=0, closing=0, failed=0, exit_status=0;
static ULONGLONG close_deadline;
static char log_text[1048576];
static DWORD consumed=0;

static int early_error(const wchar_t *message, DWORD code) {
    wchar_t details[2048];
    _snwprintf(details,2048,L"%ls\n系统错误码：%lu。请检查当前用户的临时文件与运行记录目录是否可用。",message,code);
    if(headless) {
        char encoded[8192]; DWORD written;
        int count=WideCharToMultiByte(CP_UTF8,0,details,-1,encoded,sizeof encoded,NULL,NULL);
        HANDLE error_stream=GetStdHandle(STD_ERROR_HANDLE);
        if(count>0&&error_stream!=INVALID_HANDLE_VALUE) WriteFile(error_stream,encoded,(DWORD)count-1,&written,NULL);
    }
    else MessageBoxW(NULL,message,L"Quantum Kernel 无法启动",MB_OK|MB_ICONERROR);
    return 2;
}

static void join(wchar_t *out, const wchar_t *base, const wchar_t *tail) {
    _snwprintf(out, PATH_CAP-1, L"%ls\\%ls", base, tail); out[PATH_CAP-1]=0;
}
static int full(wchar_t *out, const wchar_t *value) {
    DWORD n=GetFullPathNameW(value,PATH_CAP,out,NULL); return n>0&&n<PATH_CAP;
}
static int regular_file(const wchar_t *path) {
    DWORD a=GetFileAttributesW(path); return a!=INVALID_FILE_ATTRIBUTES&&!(a&FILE_ATTRIBUTE_DIRECTORY);
}
static int within(const wchar_t *path,const wchar_t *root) {
    size_t n=wcslen(root);
    return _wcsnicmp(path,root,n)==0&&(path[n]==0||path[n]==L'\\');
}
static void write_log(const wchar_t *value) {
    if (!log_handle||log_handle==INVALID_HANDLE_VALUE) return;
    char buffer[32768]; int n=WideCharToMultiByte(CP_UTF8,0,value,-1,buffer,sizeof buffer,NULL,NULL);
    DWORD done; if(n>0) WriteFile(log_handle,buffer,(DWORD)n-1,&done,NULL);
    WriteFile(log_handle,"\r\n",2,&done,NULL); FlushFileBuffers(log_handle);
}
static void fail(const wchar_t *message, int code) {
    failed=1; exit_status=code; write_log(message);
    finish_startup_panel();
    if(window) {
        SetWindowTextW(status_label,L"启动失败");
        SetWindowTextW(detail_label,L"请查看运行记录。");
        SendMessageW(progress,PBM_SETMARQUEE,FALSE,0);
    }
    if(headless) PostMessageW(window,WM_CLOSE,0,0);
}
static void request_stop(void) {
    HANDLE h=CreateFileW(stop_path,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h!=INVALID_HANDLE_VALUE) { DWORD done; WriteFile(h,"stop\n",5,&done,NULL); CloseHandle(h); }
}
// Embed WebView2 in the main window.
#include <WebView2.h>
#include <objbase.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
static ICoreWebView2Controller* web_controller=nullptr;
static ICoreWebView2* web=nullptr;
static HMODULE web_loader=nullptr;
static int test_debug_port=0,force_fixed_runtime=0,desktop_ready=0;
enum class TextPicker : WPARAM { None, Message, PolynomialA, PolynomialB };
static bool text_picker_pending=false;
static wchar_t origin[256],profile_dir[PATH_CAP],download_dir[PATH_CAP];
static LARGE_INTEGER native_start,native_frequency;
static void resize_web(void) {
    if(web_controller){RECT r;GetClientRect(window,&r);r.top=desktop_ready?0:42;web_controller->put_Bounds(r);}
}
static GUID guid(const wchar_t* value){GUID id;IIDFromString(value,&id);return id;}
#define CALLBACK_REF(TYPE,ID) \
    LONG references=1; \
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** result) override { \
        if(!result)return E_POINTER; \
        *result=nullptr; \
        if(IsEqualIID(id,IID_IUnknown)||IsEqualIID(id,guid(L"{" ID L"}"))){*result=static_cast<TYPE*>(this);AddRef();return S_OK;}return E_NOINTERFACE;} \
    ULONG STDMETHODCALLTYPE AddRef(void) override{return InterlockedIncrement(&references);} \
    ULONG STDMETHODCALLTYPE Release(void) override{ULONG n=InterlockedDecrement(&references);if(!n)delete this;return n;}
static bool local_uri(const wchar_t* uri){return uri&&origin[0]&&wcsncmp(uri,origin,wcslen(origin))==0&&(uri[wcslen(origin)]==L'/'||uri[wcslen(origin)]==0);}
static void save_ready(void){
    if(desktop_ready)return;
    desktop_ready=1;
    finish_startup_panel();
    LARGE_INTEGER now;QueryPerformanceCounter(&now);
    double elapsed=(double)(now.QuadPart-native_start.QuadPart)/(double)native_frequency.QuadPart;
    wchar_t path[PATH_CAP],message[256];join(path,run_dir,L"desktop-ready.txt");
    char content[1024],url[512];WideCharToMultiByte(CP_UTF8,0,browser_url,-1,url,sizeof url,nullptr,nullptr);
    int count=snprintf(content,sizeof content,"status=READY\ninteractive_seconds=%.9f\npid=%lu\nurl=%s\nhost=Win32 WebView2\nexternal_browser=false\n",elapsed,GetCurrentProcessId(),url);
    HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file!=INVALID_HANDLE_VALUE){DWORD done;WriteFile(file,content,(DWORD)count,&done,nullptr);CloseHandle(file);}
    _snwprintf(message,256,L"DESKTOP_READY_SECONDS=%.6f",elapsed);write_log(message);
    ShowWindow(status_label,SW_HIDE);ShowWindow(detail_label,SW_HIDE);ShowWindow(progress,SW_HIDE);
    ShowWindow(open_button,SW_HIDE);ShowWindow(GetDlgItem(window,OPEN_LOG),SW_HIDE);ShowWindow(GetDlgItem(window,CLOSE_DEMO),SW_HIDE);
    web_controller->put_IsVisible(TRUE);resize_web();
}
static const wchar_t* picker_prefix(TextPicker picker){
    if(picker==TextPicker::PolynomialA)return L"coefficients-a-file";
    if(picker==TextPicker::PolynomialB)return L"coefficients-b-file";
    return L"message-file";
}
static void send_text_file(const wchar_t* path,TextPicker picker){
    if(!web||closing)return;
    const std::wstring prefix=picker_prefix(picker);
    std::wstring message=prefix+L"-error";
    const LONGLONG maximum=picker==TextPicker::Message?65536:MAXDWORD;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(file!=INVALID_HANDLE_VALUE){
        LARGE_INTEGER length;
        if(GetFileSizeEx(file,&length)&&length.QuadPart>=0){
            if(length.QuadPart>maximum)message=prefix+L"-too-large";
            else{
                std::string bytes(static_cast<size_t>(length.QuadPart),'\0');
                DWORD count=0;
                if(bytes.empty()||(ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr)&&count==bytes.size())){
                    static const wchar_t digits[]=L"0123456789abcdef";
                    message=prefix+L":";
                    message.reserve(message.size()+bytes.size()*2+1+wcslen(path));
                    for(unsigned char byte:bytes){message+=digits[byte>>4];message+=digits[byte&15];}
                    const wchar_t* separator=wcsrchr(path,L'\\');
                    message+=L'\n';message+=(separator?separator+1:path);
                }
            }
        }
        CloseHandle(file);
    }
    web->PostWebMessageAsString(message.c_str());
}
static void choose_text_file(TextPicker picker){
    if(!web||closing)return;
    const bool coefficients=picker!=TextPicker::Message;
    IFileOpenDialog* dialog=nullptr;
    HRESULT status=CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog));
    if(SUCCEEDED(status)){
        dialog->SetTitle(coefficients?L"选择系数文件":L"选择消息文件");
        dialog->SetOptions(FOS_FORCEFILESYSTEM|FOS_FILEMUSTEXIST|FOS_PATHMUSTEXIST|FOS_NOCHANGEDIR|FOS_DONTADDTORECENT);
        const COMDLG_FILTERSPEC types[]={{L"文本文档 (*.txt)",L"*.txt"},{L"所有文件 (*.*)",L"*.*"}};
        dialog->SetFileTypes(coefficients?1:ARRAYSIZE(types),types);
        wchar_t folder[PATH_CAP];join(folder,exe_dir,L"示例文件");
        IShellItem* initial=nullptr;
        if(SUCCEEDED(SHCreateItemFromParsingName(folder,nullptr,IID_PPV_ARGS(&initial)))){
            dialog->SetFolder(initial);
            initial->Release();
        }
        status=dialog->Show(window);
        if(SUCCEEDED(status)){
            IShellItem* selected=nullptr;
            status=dialog->GetResult(&selected);
            if(SUCCEEDED(status)){
                LPWSTR path=nullptr;
                status=selected->GetDisplayName(SIGDN_FILESYSPATH,&path);
                if(SUCCEEDED(status))send_text_file(path,picker);
                CoTaskMemFree(path);
                selected->Release();
            }
        }
        dialog->Release();
    }
    if(web&&!closing&&FAILED(status)){
        const bool cancelled=status==HRESULT_FROM_WIN32(ERROR_CANCELLED);
        if(!cancelled||coefficients){
            const std::wstring reply=std::wstring(picker_prefix(picker))+(cancelled?L"-cancelled":L"-error");
            web->PostWebMessageAsString(reply.c_str());
        }
    }
}
class MessageHandler final:public ICoreWebView2WebMessageReceivedEventHandler{
public: CALLBACK_REF(ICoreWebView2WebMessageReceivedEventHandler,L"57213f19-00e6-49fa-8e07-898ea01ecbd2")
 HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2*,ICoreWebView2WebMessageReceivedEventArgs* args) override{
  LPWSTR source=nullptr,value=nullptr;args->get_Source(&source);args->TryGetWebMessageAsString(&value);
  if(local_uri(source)&&value){
   if(wcscmp(value,L"desktop-ready")==0)save_ready();
   else if(!text_picker_pending&&!closing){
    TextPicker picker=TextPicker::None;
    if(wcscmp(value,L"pick-message-file")==0)picker=TextPicker::Message;
    if(wcscmp(value,L"pick-coefficients-a")==0)picker=TextPicker::PolynomialA;
    if(wcscmp(value,L"pick-coefficients-b")==0)picker=TextPicker::PolynomialB;
    if(picker!=TextPicker::None)
        text_picker_pending=PostMessageW(window,WM_PICK_TEXT_FILE,static_cast<WPARAM>(picker),0)!=FALSE;
   }
  }
  CoTaskMemFree(source);CoTaskMemFree(value);return S_OK;
 }
};
class NavigationHandler final:public ICoreWebView2NavigationStartingEventHandler{
public: CALLBACK_REF(ICoreWebView2NavigationStartingEventHandler,L"9adbe429-f36d-432b-9ddc-f8881fbd76e3")
 HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2*,ICoreWebView2NavigationStartingEventArgs* args) override{
  LPWSTR uri=nullptr;args->get_Uri(&uri);
  if(uri&&!local_uri(uri)&&wcscmp(uri,L"about:blank")!=0){args->put_Cancel(TRUE);SetWindowTextW(status_label,L"此窗口仅打开本地文件。");write_log(uri);}
  CoTaskMemFree(uri);return S_OK;
 }
};
class NewWindowHandler final:public ICoreWebView2NewWindowRequestedEventHandler{
public: CALLBACK_REF(ICoreWebView2NewWindowRequestedEventHandler,L"d4c185fe-c81c-4989-97af-2d3fa7ab5651")
 HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2*,ICoreWebView2NewWindowRequestedEventArgs* args) override{
  args->put_Handled(TRUE);LPWSTR uri=nullptr;args->get_Uri(&uri);
  if(local_uri(uri))web->Navigate(uri);else SetWindowTextW(status_label,L"外部网页未打开。请使用软件内的材料和下载入口。");
  CoTaskMemFree(uri);return S_OK;
 }
};
static void download_notice(bool saved) {
    if(web) web->PostWebMessageAsString(saved?L"export-saved":L"export-failed");
}
class DownloadStateHandler final:public ICoreWebView2StateChangedEventHandler{
 std::wstring path;
public: explicit DownloadStateHandler(const wchar_t* p):path(p){} CALLBACK_REF(ICoreWebView2StateChangedEventHandler,L"81336594-7ede-4ba9-bf71-acf0a95b58dd")
 HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2DownloadOperation* operation,IUnknown*) override{
  COREWEBVIEW2_DOWNLOAD_STATE state;
  if(FAILED(operation->get_State(&state)))return S_OK;
  if(state==COREWEBVIEW2_DOWNLOAD_STATE_COMPLETED){
      std::wstring message=L"已保存文件："+path;
      write_log(message.c_str());download_notice(true);
  }else if(state==COREWEBVIEW2_DOWNLOAD_STATE_INTERRUPTED){
      write_log(L"文件保存失败");download_notice(false);
  }
  return S_OK;
 }
};
struct PendingSave {
    ICoreWebView2DownloadStartingEventArgs* args;
    ICoreWebView2Deferral* deferral;
};

static void choose_save_path(PendingSave* save) {
    auto* args=save->args;
    ICoreWebView2DownloadOperation* operation=nullptr;
    args->get_DownloadOperation(&operation);
    bool accepted=false;
    if(operation&&!closing){
        LPWSTR proposed=nullptr,uri=nullptr;
        args->get_ResultFilePath(&proposed);
        operation->get_Uri(&uri);

        const wchar_t* sep=proposed?wcsrchr(proposed,L'\\'):nullptr;
        std::wstring name=sep?sep+1:(proposed?proposed:L"result");
        for(auto& ch:name) if(wcschr(L"<>:\"/\\|?*",ch)||ch<32) ch=L'_';
        if(name.empty()) name=L"result";
        const auto dot=name.find_last_of(L'.');
        const wchar_t* extension=dot==std::wstring::npos?L"":name.c_str()+dot+1;
        const bool excel=_wcsicmp(extension,L"xlsx")==0;

        wchar_t initial[PATH_CAP],target[PATH_CAP];
        wcscpy(initial,download_dir);
        const wchar_t* route=local_uri(uri)?uri+wcslen(origin):nullptr;
        if(excel&&route&&wcsncmp(route,L"/wb/records/",12)==0){
            const wchar_t* group=L"correctness";
            const wchar_t* query=wcschr(route,L'?');
            if(query&&wcscmp(query,L"?folder=performance")==0)group=L"performance";
            if(query&&wcscmp(query,L"?folder=security")==0)group=L"security";
            std::wstring dir=std::wstring(L"04_实验结果与验证材料\\")+group;
            wchar_t preferred[PATH_CAP];
            join(preferred,package,dir.c_str());
            const DWORD attributes=GetFileAttributesW(preferred);
            if(attributes!=INVALID_FILE_ATTRIBUTES&&(attributes&FILE_ATTRIBUTE_DIRECTORY))
                wcscpy(initial,preferred);
        }
        join(target,initial,name.c_str());
        OPENFILENAMEW dialog={};
        dialog.lStructSize=sizeof(dialog);
        dialog.hwndOwner=window;
        dialog.lpstrTitle=L"另存为";
        dialog.lpstrInitialDir=initial;
        dialog.lpstrFile=target;
        dialog.nMaxFile=PATH_CAP;
        const struct {const wchar_t* ext;const wchar_t* filter;} formats[]={
            {L"xlsx",L"Excel 工作簿 (*.xlsx)\0*.xlsx\0"},
            {L"bin",L"二进制文件 (*.bin)\0*.bin\0"},
            {L"json",L"JSON 文件 (*.json)\0*.json\0"},
            {L"xml",L"XML 文件 (*.xml)\0*.xml\0"},
            {L"tsv",L"制表符分隔表格 (*.tsv)\0*.tsv\0"},
            {L"md",L"Markdown 文档 (*.md)\0*.md\0"},
            {L"txt",L"文本文档 (*.txt)\0*.txt\0"},
            {L"ps1",L"PowerShell 脚本 (*.ps1)\0*.ps1\0"}
        };
        dialog.lpstrFilter=L"所有文件 (*.*)\0*.*\0";
        for(const auto& format:formats){
            if(_wcsicmp(extension,format.ext)==0){
                dialog.lpstrFilter=format.filter;
                dialog.lpstrDefExt=format.ext;
                break;
            }
        }
        dialog.Flags=OFN_EXPLORER|OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR|OFN_DONTADDTORECENT;
        if(GetSaveFileNameW(&dialog)){
            accepted=SUCCEEDED(args->put_ResultFilePath(target));
            if(accepted){
                auto* observer=new DownloadStateHandler(target);
                EventRegistrationToken token;
                operation->add_StateChanged(observer,&token);
                observer->Release();
            }else download_notice(false);
        }else if(CommDlgExtendedError())download_notice(false);
        CoTaskMemFree(uri);CoTaskMemFree(proposed);
    }
    if(!accepted)args->put_Cancel(TRUE);
    if(operation)operation->Release();
    save->deferral->Complete();
    save->deferral->Release();
    args->Release();
    delete save;
}

class DownloadHandler final:public ICoreWebView2DownloadStartingEventHandler{
public: CALLBACK_REF(ICoreWebView2DownloadStartingEventHandler,L"efedc989-c396-41ca-83f7-07f845a55724")
 HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2*,ICoreWebView2DownloadStartingEventArgs* args) override{
    args->put_Handled(TRUE);
    ICoreWebView2Deferral* wait=nullptr;
    if(FAILED(args->GetDeferral(&wait))||!wait){args->put_Cancel(TRUE);return S_OK;}
    args->AddRef();
    auto* save=new PendingSave{args,wait};
    if(!PostMessageW(window,WM_SAVE_RESULT,0,reinterpret_cast<LPARAM>(save))){
        args->put_Cancel(TRUE);
        wait->Complete();wait->Release();args->Release();delete save;
    }
    return S_OK;
 }
};
static void navigate_if_ready(void){if(web&&ready){web->Navigate(browser_url);write_log(L"本地操作界面已在软件窗口中载入，未打开外部浏览器。");}}
class ControllerHandler final:public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler{
public: CALLBACK_REF(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,L"6c4819f3-c9b7-4260-8127-c9f5bde7f68c")
 HRESULT STDMETHODCALLTYPE Invoke(HRESULT result,ICoreWebView2Controller* controller) override{
  if(FAILED(result)||!controller){fail(L"无法创建软件内嵌界面。请查看运行记录并确认随包 WebView2 文件完整。",2);return S_OK;}
  web_controller=controller;web_controller->AddRef();controller->get_CoreWebView2(&web);resize_web();resize_startup_panel();
  ICoreWebView2Settings* settings=nullptr;web->get_Settings(&settings);
  if(settings){settings->put_IsStatusBarEnabled(FALSE);settings->put_AreDefaultContextMenusEnabled(FALSE);settings->put_AreDevToolsEnabled(test_debug_port!=0);settings->Release();}
  EventRegistrationToken token;
  auto* messages=new MessageHandler;web->add_WebMessageReceived(messages,&token);messages->Release();
  auto* navigation=new NavigationHandler;web->add_NavigationStarting(navigation,&token);navigation->Release();
  auto* new_window=new NewWindowHandler;web->add_NewWindowRequested(new_window,&token);new_window->Release();
  ICoreWebView2_4* web4=nullptr;GUID id=guid(L"{20d02d59-6df2-42dc-bd06-f98a694b1302}");
  if(SUCCEEDED(web->QueryInterface(id,(void**)&web4))){auto* download=new DownloadHandler;web4->add_DownloadStarting(download,&token);download->Release();web4->Release();}
  const wchar_t* script=LR"JS((function(){window.__nativeMessagePicker=true;window.__nativeCoefficientPicker=true;let sent=false;const timer=setInterval(()=>{if(!sent&&window.__ready&&(!document.getElementById('live-platform')||window.__platformReady)){sent=true;clearInterval(timer);requestAnimationFrame(()=>requestAnimationFrame(()=>chrome.webview.postMessage('desktop-ready')));}},15);})();)JS";
  web->AddScriptToExecuteOnDocumentCreated(script,nullptr);navigate_if_ready();return S_OK;
 }
};
class EnvironmentHandler final:public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler{
public: CALLBACK_REF(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,L"4e8a3389-c9d8-4bd2-b6b5-124fee6cc14d")
 HRESULT STDMETHODCALLTYPE Invoke(HRESULT result,ICoreWebView2Environment* environment) override{
  if(FAILED(result)||!environment){wchar_t message[512];_snwprintf(message,512,L"无法初始化内嵌运行环境（0x%08lx）。请确认材料在本机完整解压，运行环境/WebView2文件完整且当前用户可读取。",(unsigned long)result);fail(message,2);return S_OK;}
  auto* handler=new ControllerHandler;HRESULT hr=environment->CreateCoreWebView2Controller(window,handler);handler->Release();
  if(FAILED(hr))fail(L"无法创建本机软件窗口中的操作界面。",2);
  return S_OK;
 }
};
// Grant the Fixed Runtime read/execute access on Windows 10.
static bool fixed_acl_present(const wchar_t* path,const wchar_t* sid_text){
    PSID sid=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;bool found=false;
    if(!ConvertStringSidToSidW(sid_text,&sid))return false;
    if(GetNamedSecurityInfoW(const_cast<LPWSTR>(path),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&acl,nullptr,&descriptor)==ERROR_SUCCESS&&acl){
        for(DWORD i=0;i<acl->AceCount;i++){
            void* item=nullptr;if(!GetAce(acl,i,&item))continue;
            auto* header=static_cast<ACE_HEADER*>(item);
            if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE||(header->AceFlags&(OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE))!=(OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE))continue;
            auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(item);
            if(!EqualSid(sid,&ace->SidStart))continue;
            DWORD mask=ace->Mask;GENERIC_MAPPING mapping={FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};MapGenericMask(&mask,&mapping);
            if((mask&(FILE_GENERIC_READ|FILE_GENERIC_EXECUTE))==(FILE_GENERIC_READ|FILE_GENERIC_EXECUTE)){found=true;break;}
        }
    }
    if(descriptor)LocalFree(descriptor);
    LocalFree(sid);return found;
}
static bool prepare_fixed_runtime(const wchar_t* path){
    if(wcsncmp(path,L"\\\\",2)==0){fail(L"随包界面运行环境不能从网络共享路径运行。请将完整材料复制到本机磁盘后启动。",2);return false;}
    wchar_t binary[PATH_CAP];join(binary,path,L"msedgewebview2.exe");
    if(GetFileAttributesW(binary)==INVALID_FILE_ATTRIBUTES){fail(L"缺少随包界面运行环境。请完整解压材料，保留运行环境/WebView2 目录。",2);return false;}
    using VersionFn=LONG(WINAPI*)(OSVERSIONINFOW*);auto version=reinterpret_cast<VersionFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion"));
    OSVERSIONINFOW info={};info.dwOSVersionInfoSize=sizeof info;
    if(!version||version(&info)!=0){fail(L"无法确认 Windows 版本，请查看运行记录。",2);return false;}
    if(info.dwMajorVersion>=10&&info.dwBuildNumber>=22000)return true;
    if(info.dwMajorVersion<10){fail(L"Quantum Kernel 需要 Windows 10 或更新的 64 位系统。",2);return false;}
    const wchar_t* sids[]={L"S-1-15-2-2",L"S-1-15-2-1"};
    for(const auto* sid:sids){
        if(fixed_acl_present(path,sid))continue;
        wchar_t system[PATH_CAP],tool[PATH_CAP],command[PATH_CAP];GetSystemDirectoryW(system,PATH_CAP);join(tool,system,L"icacls.exe");
        _snwprintf(command,PATH_CAP,L"\"%ls\" \"%ls\" /grant *%ls:(OI)(CI)(RX)",tool,path,sid);
        STARTUPINFOW startup={};startup.cb=sizeof startup;PROCESS_INFORMATION process_info={};
        if(!CreateProcessW(tool,command,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process_info)){fail(L"无法为 Windows 10 的内嵌界面配置读取权限。请把材料复制到当前用户可管理的本机目录后重试。",2);return false;}
        DWORD wait=WaitForSingleObject(process_info.hProcess,10000),code=1;
        if(wait==WAIT_OBJECT_0)GetExitCodeProcess(process_info.hProcess,&code);else TerminateProcess(process_info.hProcess,2);
        CloseHandle(process_info.hThread);CloseHandle(process_info.hProcess);
        if(code!=0||!fixed_acl_present(path,sid)){fail(L"Windows 10 内嵌界面目录读取权限未能配置。请将完整材料复制到当前用户可管理的本机目录。",2);return false;}
        write_log(L"已按 Microsoft 固定运行时要求设置 AppContainer 目录读/执行权限；未授予写权限。");
    }
    return true;
}

static void initialize_web(void){
  wchar_t loader[PATH_CAP];join(loader,exe_dir,L"运行环境\\WebView2Loader.dll");web_loader=LoadLibraryExW(loader,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
  if(!web_loader){fail(L"缺少内嵌界面加载组件。请完整解压材料，保留运行环境/WebView2Loader.dll。",2);return;}
  using CreateEnvironment=HRESULT(STDAPICALLTYPE*)(PCWSTR,PCWSTR,ICoreWebView2EnvironmentOptions*,ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
  using GetVersion=HRESULT(STDAPICALLTYPE*)(PCWSTR,LPWSTR*);
  auto create=reinterpret_cast<CreateEnvironment>(GetProcAddress(web_loader,"CreateCoreWebView2EnvironmentWithOptions"));
  auto version=reinterpret_cast<GetVersion>(GetProcAddress(web_loader,"GetAvailableCoreWebView2BrowserVersionString"));
  if(!create||!version){fail(L"内嵌界面加载组件不完整，请恢复原始随包文件。",2);return;}
  wchar_t fixed[PATH_CAP];join(fixed,exe_dir,L"运行环境\\WebView2");LPWSTR info=nullptr;
  PCWSTR selected=nullptr;
  if(force_fixed_runtime||FAILED(version(nullptr,&info))){selected=fixed;write_log(L"WEBVIEW2_RUNTIME=fixed-package");}
  else {write_log(L"WEBVIEW2_RUNTIME=system");write_log(info);}
  CoTaskMemFree(info);
  if(selected&&!prepare_fixed_runtime(selected))return;
  join(profile_dir,cache,L"webview2");SHCreateDirectoryExW(nullptr,profile_dir,nullptr);
  join(download_dir,run_dir,L"downloads");SHCreateDirectoryExW(nullptr,download_dir,nullptr);
  wchar_t debug[256]=L"";if(test_debug_port)_snwprintf(debug,256,L"--remote-debugging-port=%d --remote-debugging-address=127.0.0.1",test_debug_port);
  SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",test_debug_port?debug:nullptr);
  auto* handler=new EnvironmentHandler;HRESULT hr=create(selected,profile_dir,nullptr,handler);handler->Release();
  if(FAILED(hr))fail(L"无法启动内嵌运行环境。请检查运行环境文件和包外运行目录权限。",2);
}

static void open_page(void){if(web&&ready)web->Navigate(browser_url);}
static void quote(wchar_t *command, const wchar_t *value) {
    size_t used=wcslen(command), slash=0;
    if(used+2>=PATH_CAP) return;
    command[used++]=L'"';
    for(const wchar_t *p=value;;++p) {
        if(*p==L'\\') { ++slash; continue; }
        size_t count=(*p==L'"'||*p==0)?slash*2:slash;
        if(*p==L'"') ++count;
        while(count--&&used<PATH_CAP-3) command[used++]=L'\\';
        slash=0;
        if(!*p) break;
        if(used<PATH_CAP-3) command[used++]=*p;
    }
    command[used++]=L'"'; command[used++]=L' '; command[used]=0;
}
static int free_port(void) {
    WSADATA info; SOCKET s; struct sockaddr_in address; int len=sizeof address, port=0;
    if(WSAStartup(MAKEWORD(2,2),&info)!=0) return 0;
    s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    ZeroMemory(&address,sizeof address); address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(s!=INVALID_SOCKET&&bind(s,(struct sockaddr*)&address,sizeof address)==0&&getsockname(s,(struct sockaddr*)&address,&len)==0)
        port=ntohs(address.sin_port);
    if(s!=INVALID_SOCKET) closesocket(s);
    WSACleanup(); return port;
}
static void read_log(void) {
    HANDLE h=CreateFileW(log_path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size; DWORD bytes=0;
    if(GetFileSizeEx(h,&size)&&size.QuadPart>0) {
        DWORD count=(DWORD)(size.QuadPart<(LONGLONG)sizeof(log_text)-1?size.QuadPart:(LONGLONG)sizeof(log_text)-1);
        SetFilePointer(h,(LONG)(size.QuadPart-count),NULL,FILE_BEGIN);
        if(ReadFile(h,log_text,count,&bytes,NULL)) log_text[bytes]=0;
    }
    CloseHandle(h);
    if(!bytes||bytes==consumed) return;
    consumed=bytes;
    char *url=strstr(log_text,"DEMO_URL=");
    if(url&&!ready) {
        char value[512]; size_t n=strcspn(url+9,"\r\n");
        if(n<sizeof value) {
            memcpy(value,url+9,n); value[n]=0;
            if(strncmp(value,"http://127.0.0.1:",17)==0) {
                MultiByteToWideChar(CP_UTF8,0,value,-1,browser_url,512);
                ready=1; EnableWindow(open_button,TRUE);
                SendMessageW(progress,PBM_SETMARQUEE,FALSE,0);
                SetWindowTextW(status_label,L"");
                SetWindowTextW(detail_label,L"正在打开…");
                navigate_if_ready();
            }
        }
    }
    if(!ready&&!failed&&!closing) {
        char *end=log_text+bytes; while(end>log_text&&(end[-1]=='\r'||end[-1]=='\n')) --end;
        char *start=end; while(start>log_text&&start[-1]!='\n') --start;
        if(end-start<2048) {
            char line[2048]; wchar_t wide[2048]; memcpy(line,start,end-start); line[end-start]=0;
            if(MultiByteToWideChar(CP_UTF8,0,line,-1,wide,2048)>0) SetWindowTextW(detail_label,wide);
        }
    }
}
static void stopped(void) {
    DWORD code=0; GetExitCodeProcess(process,&code); CloseHandle(process); process=NULL;
    read_log();
    if(closing) { exit_status=0; DestroyWindow(window); return; }
    if(code!=0||!ready) {
        fail(L"启动程序未完成。请点击“查看运行记录”查看具体原因；确认材料已完整解压，且运行所需文件没有被移动或修改。",code?(int)code:3);
    } else {
        ShowWindow(status_label,SW_SHOW);ShowWindow(detail_label,SW_SHOW);
        ShowWindow(GetDlgItem(window,CLOSE_DEMO),SW_SHOW);SetWindowTextW(status_label,L"本机服务已结束");
        SetWindowTextW(detail_label,L"再次双击“Quantum Kernel.exe”即可重新启动。");
        if(headless) DestroyWindow(window);
    }
}
static void finish_startup_panel(void) {
    if(!startup_panel)return;
    DestroyWindow(startup_panel);startup_panel=nullptr;
    ShowWindow(status_label,SW_SHOW);ShowWindow(open_button,SW_SHOW);
    ShowWindow(GetDlgItem(window,OPEN_LOG),SW_SHOW);ShowWindow(GetDlgItem(window,CLOSE_DEMO),SW_SHOW);
    if(failed||closing)ShowWindow(detail_label,SW_SHOW);
    InvalidateRect(window,nullptr,TRUE);
}
static void resize_startup_panel(void) {
    if(!startup_panel)return;
    RECT bounds;GetClientRect(window,&bounds);
    SetWindowPos(startup_panel,HWND_TOP,0,0,bounds.right,bounds.bottom,SWP_NOACTIVATE);
}
static void startup_text(HDC dc,const wchar_t* text,HFONT selected,COLORREF color,RECT bounds) {
    HGDIOBJ old=SelectObject(dc,selected);SetTextColor(dc,color);SetBkMode(dc,TRANSPARENT);
    DrawTextW(dc,text,-1,&bounds,DT_CENTER|DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
    SelectObject(dc,old);
}
static LRESULT CALLBACK startup_procedure(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam) {
    if(message==WM_ERASEBKGND)return 1;
    if(message==WM_PAINT) {
        PAINTSTRUCT paint;HDC screen=BeginPaint(hwnd,&paint);RECT bounds;GetClientRect(hwnd,&bounds);
        if(bounds.right>0&&bounds.bottom>0) {
            HDC dc=CreateCompatibleDC(screen);HBITMAP bitmap=CreateCompatibleBitmap(screen,bounds.right,bounds.bottom);
            HGDIOBJ old_bitmap=SelectObject(dc,bitmap);
            HBRUSH background=CreateSolidBrush(RGB(16,44,58));FillRect(dc,&bounds,background);DeleteObject(background);
            int cx=bounds.right/2,top=bounds.bottom/2-180;
            HICON logo = (HICON)LoadImageW(GetModuleHandleW(NULL),MAKEINTRESOURCEW(101),IMAGE_ICON,76,76,LR_SHARED);
            if(logo) DrawIconEx(dc,cx-38,top,logo,76,76,0,NULL,DI_NORMAL);
            RECT title={20,top+94,bounds.right-20,top+149};
            startup_text(dc,L"Quantum Kernel",startup_title_font,RGB(255,255,255),title);
            RECT algorithms={20,top+159,bounds.right-20,top+190};
            startup_text(dc,L"ML-KEM  ·  ML-DSA",font,RGB(177,199,209),algorithms);
            RECT track={cx-140,top+224,cx+140,top+227};
            HBRUSH track_brush=CreateSolidBrush(RGB(57,86,99));FillRect(dc,&track,track_brush);DeleteObject(track_brush);
            ULONGLONG phase=GetTickCount64()%1600;int offset=(int)((phase<800?phase:1600-phase)*200/800);
            RECT segment={cx-140+offset,top+224,cx-60+offset,top+227};
            HBRUSH activity=CreateSolidBrush(RGB(107,208,197));FillRect(dc,&segment,activity);DeleteObject(activity);
            RECT state={20,top+245,bounds.right-20,top+275};
            startup_text(dc,ready?L"正在打开…":L"正在启动…",startup_small_font,RGB(177,199,209),state);
            BitBlt(screen,paint.rcPaint.left,paint.rcPaint.top,paint.rcPaint.right-paint.rcPaint.left,paint.rcPaint.bottom-paint.rcPaint.top,dc,paint.rcPaint.left,paint.rcPaint.top,SRCCOPY);
            SelectObject(dc,old_bitmap);DeleteObject(bitmap);DeleteDC(dc);
        }
        EndPaint(hwnd,&paint);return 0;
    }
    return DefWindowProcW(hwnd,message,wparam,lparam);
}
static LRESULT CALLBACK procedure(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam) {
    switch(message) {
    case WM_SIZE:
        resize_web();resize_startup_panel();
        if(status_label){RECT r;GetClientRect(hwnd,&r);MoveWindow(status_label,16,9,r.right-365,25,TRUE);MoveWindow(GetDlgItem(hwnd,OPEN_LOG),r.right-225,5,110,30,TRUE);MoveWindow(GetDlgItem(hwnd,CLOSE_DEMO),r.right-110,5,100,30,TRUE);MoveWindow(open_button,r.right-340,5,105,30,TRUE);}
        return 0;
    case WM_COMMAND:
        if(LOWORD(wparam)==OPEN_PAGE) open_page();
        if(LOWORD(wparam)==OPEN_LOG) ShellExecuteW(NULL,L"open",run_dir,NULL,NULL,SW_SHOWNORMAL);
        if(LOWORD(wparam)==CLOSE_DEMO) PostMessageW(hwnd,WM_CLOSE,0,0);
        return 0;
    case WM_SAVE_RESULT:
        choose_save_path(reinterpret_cast<PendingSave*>(lparam));return 0;
    case WM_PICK_TEXT_FILE:
        choose_text_file(static_cast<TextPicker>(wparam));text_picker_pending=false;return 0;
    case WM_OPEN_EXISTING_INSTANCE:
        ShowWindow(hwnd,SW_RESTORE); SetForegroundWindow(hwnd); open_page(); return 0;
    case WM_TIMER:
        read_log();
        if(startup_panel&&GetTickCount64()-startup_painted>=60) {
            startup_painted=GetTickCount64();RECT r;GetClientRect(startup_panel,&r);
            r.top=r.bottom/2+39;r.bottom=r.top+68;
            SetWindowPos(startup_panel,HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
            InvalidateRect(startup_panel,&r,FALSE);
        }
        if(process&&WaitForSingleObject(process,0)==WAIT_OBJECT_0) { stopped(); return 0; }
        if(closing&&GetTickCount64()>close_deadline) {
            write_log(L"用户关闭；准备过程或等待中的本次子进程已结束。");
            if(job) TerminateJobObject(job,0);
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        if(process&&!closing) {
            closing=1;finish_startup_panel(); request_stop(); close_deadline=GetTickCount64()+(ready?10000:3000);
            SetWindowTextW(status_label,L"正在关闭");
            SetWindowTextW(detail_label,L"正在保存运行记录…");
            EnableWindow(open_button,FALSE); return 0;
        }
        if(!process) DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if(web_controller){web_controller->Close();web_controller->Release();web_controller=nullptr;}
        if(web){web->Release();web=nullptr;}
        if(job) { CloseHandle(job); job=NULL; }
        PostQuitMessage(exit_status); return 0;
    }
    return DefWindowProcW(hwnd,message,wparam,lparam);
}
static HWND control(const wchar_t *kind,const wchar_t *text,DWORD style,int x,int y,int w,int h,int id) {
    HWND result=CreateWindowExW(0,kind,text,WS_CHILD|WS_VISIBLE|style,x,y,w,h,window,(HMENU)(INT_PTR)id,GetModuleHandleW(NULL),NULL);
    SendMessageW(result,WM_SETFONT,(WPARAM)font,TRUE); return result;
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR raw,int show) {
    QueryPerformanceCounter(&native_start);QueryPerformanceFrequency(&native_frequency);
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    (void)previous; (void)raw; (void)show;
    int argc=0, port=0; LPWSTR *argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    wchar_t explicit_cache[PATH_CAP]=L"", explicit_output[PATH_CAP]=L"";
    for(int i=1;i<argc;++i) {
        if(wcscmp(argv[i],L"--no-browser")==0) {} // legacy argument: external browsers are never opened
        else if(wcscmp(argv[i],L"--test-debug-port")==0&&i+1<argc) test_debug_port=_wtoi(argv[++i]);
        else if(wcscmp(argv[i],L"--test-fixed-runtime")==0) force_fixed_runtime=1;
        else if(wcscmp(argv[i],L"--history")==0) start_history=1;
        else if(wcscmp(argv[i],L"--headless")==0) headless=1;
        else if(wcscmp(argv[i],L"--cache-root")==0&&i+1<argc) full(explicit_cache,argv[++i]);
        else if(wcscmp(argv[i],L"--output")==0&&i+1<argc) full(explicit_output,argv[++i]);
        else if(wcscmp(argv[i],L"--port")==0&&i+1<argc) port=_wtoi(argv[++i]);
        else { LocalFree(argv); return early_error(L"启动参数无效。请直接双击程序，或核对使用说明中的参数。",ERROR_INVALID_PARAMETER); }
    }
    LocalFree(argv);
    if(test_debug_port&&(test_debug_port<1024||test_debug_port>65535))return early_error(L"测试调试端口无效。",ERROR_INVALID_PARAMETER);
    GetModuleFileNameW(NULL,exe_dir,PATH_CAP); wchar_t *slash=wcsrchr(exe_dir,L'\\'); if(slash) *slash=0;
    wchar_t buffer[PATH_CAP]; join(buffer,exe_dir,L"..\\.."); full(package,buffer);
    wchar_t base[PATH_CAP];
    HRESULT folder_result=SHGetFolderPathW(NULL,CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE,NULL,SHGFP_TYPE_CURRENT,base);
    if(folder_result!=S_OK) return early_error(L"无法找到当前用户的本地运行目录。",(DWORD)folder_result);
    join(buffer,base,L"CACR2026LatticeDemo"); wcscpy(base,buffer);
    if(explicit_cache[0]) wcscpy(cache,explicit_cache); else join(cache,base,L"cache");
    if(explicit_output[0]) wcscpy(run_dir,explicit_output);
    else {
        SYSTEMTIME now; wchar_t tail[128]; GetLocalTime(&now);
        _snwprintf(tail,128,L"runs\\%04u%02u%02u-%02u%02u%02u-%lu",now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond,GetCurrentProcessId());
        join(run_dir,base,tail);
    }
    if(within(run_dir,package)||within(cache,package)||within(package,cache))
        return early_error(L"运行记录与缓存必须放在支撑材料之外。请直接双击程序使用默认位置。",ERROR_INVALID_PARAMETER);
    int made=SHCreateDirectoryExW(NULL,run_dir,NULL);
    if(made!=ERROR_SUCCESS&&made!=ERROR_ALREADY_EXISTS) return early_error(L"无法创建本次运行记录目录。",(DWORD)made);
    join(log_path,run_dir,L"启动记录.log"); join(stop_path,run_dir,L"stop.request");
    SECURITY_ATTRIBUTES security={sizeof security,NULL,TRUE};
    log_handle=CreateFileW(log_path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_handle==INVALID_HANDLE_VALUE) return early_error(L"无法写入本次启动记录。",GetLastError());
    write_log(L"Quantum Kernel 启动记录"); write_log(exe_dir);
    /* Only the desktop window takes the single-instance lock. */
    if(!headless) {
        instance_mutex=CreateMutexW(NULL,FALSE,L"Local\\CACR2026LatticeDemo");
        if(GetLastError()==ERROR_ALREADY_EXISTS) {
            HWND existing=FindWindowW(WINDOW_CLASS,NULL); if(existing) PostMessageW(existing,WM_OPEN_EXISTING_INSTANCE,0,0);
            CloseHandle(instance_mutex); CloseHandle(log_handle); return 0;
        }
    }
    SetProcessDPIAware(); INITCOMMONCONTROLSEX controls={sizeof controls,ICC_PROGRESS_CLASS}; InitCommonControlsEx(&controls);
    WNDCLASSW klass={0}; klass.lpfnWndProc=procedure; klass.hInstance=instance; klass.lpszClassName=WINDOW_CLASS;
    klass.hCursor=LoadCursorW(NULL,IDC_ARROW); klass.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(101)); klass.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&klass);
    WNDCLASSW startup_class={0};startup_class.lpfnWndProc=startup_procedure;startup_class.hInstance=instance;
    startup_class.lpszClassName=L"CACR2026LatticeDemoStartup";startup_class.hCursor=LoadCursorW(NULL,IDC_ARROW);
    RegisterClassW(&startup_class);
    startup_title_font=CreateFontW(-38,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    startup_small_font=CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    font=CreateFontW(-18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    window=CreateWindowExW(0,WINDOW_CLASS,L"Quantum Kernel",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,1320,880,NULL,NULL,instance,NULL);
    status_label=control(L"STATIC",L"正在准备软件界面…",0,16,9,900,25,0);
    detail_label=control(L"STATIC",L"正在加载本机密码功能…",0,32,88,850,55,0);
    progress=control(PROGRESS_CLASSW,L"",PBS_MARQUEE,32,155,700,16,0);SendMessageW(progress,PBM_SETMARQUEE,TRUE,35);
    open_button=control(L"BUTTON",L"返回首页",BS_PUSHBUTTON,960,5,105,30,OPEN_PAGE);EnableWindow(open_button,FALSE);
    control(L"BUTTON",L"运行记录",BS_PUSHBUTTON,1075,5,110,30,OPEN_LOG);
    control(L"BUTTON",L"关闭",BS_PUSHBUTTON,1190,5,100,30,CLOSE_DEMO);
    if(!headless) {
        ShowWindow(status_label,SW_HIDE);ShowWindow(detail_label,SW_HIDE);ShowWindow(progress,SW_HIDE);
        ShowWindow(open_button,SW_HIDE);ShowWindow(GetDlgItem(window,OPEN_LOG),SW_HIDE);ShowWindow(GetDlgItem(window,CLOSE_DEMO),SW_HIDE);
        startup_panel=CreateWindowExW(0,L"CACR2026LatticeDemoStartup",L"正在启动",WS_CHILD|WS_VISIBLE,0,0,1320,880,window,nullptr,instance,nullptr);
        resize_startup_panel();ShowWindow(window,SW_SHOWNORMAL);UpdateWindow(window);UpdateWindow(startup_panel);
    }
    SetTimer(window,1,25,NULL);
    wchar_t python[PATH_CAP], entry[PATH_CAP], session[PATH_CAP], pycache[PATH_CAP];
    join(python,exe_dir,L"运行环境\\python\\python.exe");
    join(entry,exe_dir,L"入口\\fast_launch.py");
    join(session,run_dir,L"session"); join(pycache,run_dir,L"bytecode");
    if(!regular_file(python)||!regular_file(entry)) {
        fail(L"未找到随包运行环境或启动文件。请完整解压整套支撑材料后运行，不要单独复制此 EXE。点击“查看运行记录”可查看启动位置。",2);
    } else {
        if(!port) port=free_port();
        if(port<1024||port>65535) {
            fail(L"无法选择可用的本机端口。请关闭其他窗口后重试；显式端口须为 1024 至 65535。",2);
            goto message_loop;
        }
        _snwprintf(origin,256,L"http://127.0.0.1:%d",port);
        initialize_web();
        if(failed)goto message_loop;
        wchar_t command[PATH_CAP]=L"", number[32]; _snwprintf(number,32,L"%d",port);
        quote(command,python); quote(command,L"-B"); quote(command,L"-X");
        wchar_t cache_option[PATH_CAP]; _snwprintf(cache_option,PATH_CAP,L"pycache_prefix=%ls",pycache);
        quote(command,cache_option); quote(command,entry); quote(command,L"--package"); quote(command,package);
        quote(command,L"--cache-root"); quote(command,cache); quote(command,L"--output"); quote(command,session);
        if(start_history)quote(command,L"--history");
        quote(command,L"--stop-file"); quote(command,stop_path); quote(command,L"--no-browser"); quote(command,L"--port"); quote(command,number);
        SetEnvironmentVariableW(L"PYTHONDONTWRITEBYTECODE",L"1"); SetEnvironmentVariableW(L"PYTHONUTF8",L"1"); SetEnvironmentVariableW(L"PYTHONIOENCODING",L"utf-8");
        SetEnvironmentVariableW(L"PYTHONPYCACHEPREFIX",pycache);
        STARTUPINFOW start={0}; PROCESS_INFORMATION child={0}; start.cb=sizeof start; start.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
        start.wShowWindow=SW_HIDE; start.hStdOutput=log_handle; start.hStdError=log_handle;
        start.hStdInput=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,0,NULL);
        job=CreateJobObjectW(NULL,NULL); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if(!job||!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof limits)||
           !CreateProcessW(python,command,NULL,NULL,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,exe_dir,&start,&child)) {
            fail(L"无法启动随包运行程序。请确认解压完整、当前用户可写入运行记录目录；如程序被拦截，请查看系统给出的具体提示。",2);
        } else if(!AssignProcessToJobObject(job,child.hProcess)) {
            TerminateProcess(child.hProcess,2); CloseHandle(child.hProcess); CloseHandle(child.hThread);
            fail(L"本机服务未能启动。请关闭其他窗口后重试，并查看运行记录。",2);
        } else { process=child.hProcess; ResumeThread(child.hThread); CloseHandle(child.hThread); }
        if(start.hStdInput!=INVALID_HANDLE_VALUE) CloseHandle(start.hStdInput);
    }
message_loop:;
    MSG message; while(GetMessageW(&message,NULL,0,0)>0) { TranslateMessage(&message); DispatchMessageW(&message); }
    if(process) CloseHandle(process);
    if(instance_mutex) CloseHandle(instance_mutex);
    CloseHandle(log_handle); DeleteObject(font);DeleteObject(startup_title_font);DeleteObject(startup_small_font); CoUninitialize(); return exit_status;
}
