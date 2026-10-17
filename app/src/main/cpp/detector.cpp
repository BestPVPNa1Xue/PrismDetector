#include "rules.hpp"
#include "certificate_baseline.hpp"
#include "vendor/research/chain_closure_20261018/src/android_collectors.hpp"
#include "vendor/research/chain_closure_20261018/src/classes_jni.hpp"
#include "vendor/research/environment_memory/src/input_methods_jni.hpp"
#include "vendor/research/accessibility/src/accessibility_monitor.hpp"
#include "vendor/research/device_identity/src/android_adapter.hpp"
#include "vendor/research/src/verified_helpers.h"
#include <jni.h>
#include <android/log.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

namespace {
using namespace detector;
namespace ch=prism::chains;
namespace ev=prism::environment;
std::mutex scan_mutex;
prism::accessibility::State accessibility_state;
ev::InputMethodState ime_state;
std::array<bool,4> latches{};
std::vector<std::string> previous_accessibility,previous_ime;
bool have_accessibility=false,have_ime=false;
const char* original="已恢复规则";
const char* custom="自定义规则";
std::string join(const std::vector<std::string>& v){std::string s;for(auto& x:v)s+=x+"\n";return s.empty()?"（空列表）\n":s;}
std::string changes(const std::vector<std::string>& before,const std::vector<std::string>& after,bool have){if(!have)return "首次快照\n";std::string s;for(auto& x:after)if(std::find(before.begin(),before.end(),x)==before.end())s+="+ "+x+"\n";for(auto& x:before)if(std::find(after.begin(),after.end(),x)==after.end())s+="− "+x+"\n";return s.empty()?"集合无增删\n":s;}
std::string hx(std::uint64_t x){std::ostringstream s;s<<"0x"<<std::hex<<x;return s.str();}
std::string number(std::uint64_t x){std::ostringstream s;s<<x<<" 字节（"<<std::fixed<<std::setprecision(2)<<double(x)/1048576<<" MiB）";return s.str();}
void check(JNIEnv* e){if(e->ExceptionCheck()){e->ExceptionClear();throw std::runtime_error("Android JNI call failed");}}
std::string text(JNIEnv* e,jstring s){if(!s)return {};auto p=e->GetStringUTFChars(s,nullptr);check(e);if(!p)throw std::runtime_error("UTF unavailable");std::string r(p);e->ReleaseStringUTFChars(s,p);return r;}
jobject field(JNIEnv* e,jobject o,const char* n,const char* sig){auto c=e->GetObjectClass(o);check(e);auto f=e->GetFieldID(c,n,sig);check(e);auto r=e->GetObjectField(o,f);e->DeleteLocalRef(c);check(e);return r;}
std::string strfield(JNIEnv* e,jobject o,const char* n){auto v=(jstring)field(e,o,n,"Ljava/lang/String;");auto s=text(e,v);if(v)e->DeleteLocalRef(v);return s;}
std::vector<std::string> strings(JNIEnv* e,jobjectArray a){std::vector<std::string> v;if(!a)return v;auto count=e->GetArrayLength(a);check(e);for(int k=0;k<count;++k){auto s=(jstring)e->GetObjectArrayElement(a,k);check(e);v.push_back(text(e,s));if(s)e->DeleteLocalRef(s);}return v;}
struct Package {int status=0;std::string error,version,source;std::vector<std::string> splits,activities,certificates,history;};
Package package(JNIEnv* e,jobject ctx,const char* name){
    Package p;auto c=e->FindClass("na1xue/prism/detector/Platform");check(e);
    auto method=e->GetStaticMethodID(c,"packageData","(Landroid/content/Context;Ljava/lang/String;)Lna1xue/prism/detector/Platform$PackageData;");check(e);
    auto n=e->NewStringUTF(name);check(e);auto o=e->CallStaticObjectMethod(c,method,ctx,n);check(e);if(!o)throw std::runtime_error("null PackageData");
    auto oc=e->GetObjectClass(o);check(e);auto f=e->GetFieldID(oc,"status","I");check(e);p.status=e->GetIntField(o,f);check(e);
    p.error=strfield(e,o,"error");p.version=strfield(e,o,"version");p.source=strfield(e,o,"source");
    auto readlist=[&](const char* name){auto a=(jobjectArray)field(e,o,name,"[Ljava/lang/String;");auto out=strings(e,a);if(a)e->DeleteLocalRef(a);return out;};
    p.splits=readlist("splits");p.activities=readlist("activities");
    auto hashes=[&](const char* name){std::vector<std::string> out;auto a=(jobjectArray)field(e,o,name,"[[B");if(a){auto len=e->GetArrayLength(a);check(e);for(int i=0;i<len;++i){auto b=(jbyteArray)e->GetObjectArrayElement(a,i);check(e);if(!b)continue;auto size=e->GetArrayLength(b);check(e);if(size<=0 || size>1024*1024)throw std::runtime_error("invalid certificate size");prism::Bytes raw(size);e->GetByteArrayRegion(b,0,size,reinterpret_cast<jbyte*>(raw.data()));check(e);auto digest=prism::sha256(raw);out.push_back(prism::hex(prism::Bytes(digest.begin(),digest.end())));e->DeleteLocalRef(b);}e->DeleteLocalRef(a);}return out;};
    p.certificates=hashes("certificates");p.history=hashes("history");
    e->DeleteLocalRef(oc);e->DeleteLocalRef(o);e->DeleteLocalRef(n);e->DeleteLocalRef(c);return p;
}
void packages(JNIEnv* e,jobject ctx,std::vector<Item>& items){
    auto p=package(e,ctx,"com.netease.x19");
    Item size{"minecraft_size","我的世界安装包体积","unknown","未安装网易我的世界","包名：com.netease.x19\n",custom};
    Item cert{"minecraft_certificate","我的世界 APK 证书","unknown","未安装网易我的世界","包名：com.netease.x19\n","平台证书 API + C++ SHA-256"};
    if(p.status<0){size.summary=cert.summary="安装信息读取失败";size.details+=p.error;cert.details+=p.error;}
    else if(p.status==0){size.state=cert.state="na";size.details+="当前 Android 用户未发现该包；未执行体积规则。";cert.details+="当前 Android 用户未发现该包。";}
    else {
        size.details+="版本："+p.version+"\nbase APK："+p.source+"\n";struct stat st{};
        if(!p.source.empty() && stat(p.source.c_str(),&st)==0 && S_ISREG(st.st_mode) && st.st_size>=0){
            size.state=apk_size_abnormal(st.st_size)?"warn":"pass";size.summary=size.state=="warn"?"我的世界安装包体积异常":"我的世界安装包体积超过 1 GiB";size.details+="base 大小："+number(st.st_size)+"\n";
            std::uint64_t total=st.st_size;bool split_ok=true;
            for(auto& path:p.splits){struct stat sp{};size.details+="split："+path+"\n";if(stat(path.c_str(),&sp)==0 && sp.st_size>=0){size.details+=number(sp.st_size)+"\n";total+=sp.st_size;}else{split_ok=false;size.details+="读取失败\n";}}
            if(split_ok)size.details+="APK 文件合计（仅展示）："+number(total)+"\n";
        }else size.summary="已安装，但无法读取 base APK 大小";
        size.details+="规则：base APK ≤ 1,073,741,824 字节时异常。分包、OBB、下载资源和缓存不参与判定。";
        cert.details+="版本："+p.version+"\n当前签名证书 SHA-256：\n"+join(p.certificates)+"历史签名证书 SHA-256：\n"+join(p.history);
        if(!p.certificates.empty()){
            bool match=matches_minecraft_certificate(p.certificates);cert.state=match?"pass":"danger";
            cert.summary=match?"当前签名与提供的网易原版基准一致":"当前签名与提供的网易原版基准不一致";
        }else{cert.summary="已安装，但证书读取失败";cert.details+=p.error;}
        cert.details+="\n基准版本：3.9.15.297907 (840297907)\n基准证书 SHA-256：\n"+std::string(minecraft_certificate_sha256)+"\n由系统 PackageManager 返回已安装包签名，C++ 计算摘要并比较完整当前签名者集合。历史证书仅展示，不单独作为通过条件。匹配只说明与提供样本的签名一致，不是整个 APK 文件完整性验证。";
    }
    items.push_back(size);items.push_back(cert);
    auto k=package(e,ctx,"io.github.sds100.keymapper");
    items.push_back({"keymapper_package","KeyMapper 安装状态",k.status==1?"danger":k.status==0?"na":"unknown",k.status==1?"已安装 KeyMapper":k.status==0?"未发现 KeyMapper":"安装状态读取失败","包名：io.github.sds100.keymapper\n版本："+k.version+"\n"+k.error+"\n安装与无障碍/输入法启用状态分别显示。",custom});
    auto own=package(e,ctx,"na1xue.prism.detector");auto a=prism::activity_info(own.activities);
    items.push_back({"host_features","宿主包名与 Activity 特征",own.status==1?"info":"unknown","PrismDetector 自身声明信息","package=na1xue.prism.detector\nwx_prefix="+a.wx_prefix+"\nhas_mpay="+(a.has_mpay?"true":"false")+"\nActivities：\n"+join(own.activities),original});
}
void accessibility(JNIEnv* e,jobject ctx,std::vector<Item>& items){
    auto a=prism::accessibility::observe_from_context(accessibility_state,e,ctx);bool exception=e->ExceptionCheck();if(exception)e->ExceptionClear();
    bool ok=a.enumeration.complete&&!exception&&a.result.has_value();bool found=false;for(auto& s:a.enumeration.ids)found|=keymapper_accessibility(s);
    std::string d="已启用无障碍服务 ID（系统返回原序）：\n"+join(a.enumeration.ids);
    for(auto& x:a.enumeration.diagnostics)d+=std::string(prism::accessibility::jni_stage_name(x.stage))+": "+x.detail+"\n";
    if(ok){d+="CRC32-bswap="+hx(accessibility_state.previous_hash.load())+"\nevent="+(a.result->kind==prism::accessibility::ResultKind::Event?std::to_string(a.result->event_type):"None")+"\n"+changes(previous_accessibility,a.enumeration.ids,have_accessibility);previous_accessibility=a.enumeration.ids;have_accessibility=true;}
    Item item{"accessibility","无障碍检测",service_state(ok,a.enumeration.ids,true),ok?(found?"危险：KeyMapper 无障碍服务已启用":a.enumeration.ids.empty()?"未发现已启用的无障碍服务":"可疑：存在其他已启用无障碍服务"):"无障碍枚举未完成",d+"\n按指定显示规则：普通已启用组件为可疑，精确匹配 KeyMapper 为危险；分类表示组件命中，不证明实际作弊。",original};
    for(auto& service:a.enumeration.ids)item.rows.push_back({service,keymapper_accessibility(service)?"danger":"suspicious"});
    items.push_back(std::move(item));
}
void inputmethods(JNIEnv* e,jobject ctx,std::vector<Item>& items){
    auto list=ev::enumerate_input_methods_from_context(e,ctx);bool exception=e->ExceptionCheck();if(exception)e->ExceptionClear();bool ok=list.complete&&!exception;bool found=false;for(auto& s:list.service_names)found|=keymapper_ime(s);
    std::string d="getInputMethodList → getServiceName：\n"+join(list.service_names)+"\n采集阶段："+list.stage+"\n";
    if(ok){auto result=ev::evaluate_input_methods(ime_state,list.service_names);d+="hash="+hx(ime_state.previous_hash)+"\nevent="+(result.kind==ev::InputMethodResult::Kind::Event?std::to_string(result.event_type):"None")+"\n"+changes(previous_ime,list.service_names,have_ime);previous_ime=list.service_names;have_ime=true;}
    auto c=e->FindClass("na1xue/prism/detector/Platform");check(e);auto m=e->GetStaticMethodID(c,"inputMethodSettings","(Landroid/content/Context;)Ljava/lang/String;");check(e);auto s=(jstring)e->CallStaticObjectMethod(c,m,ctx);check(e);d+="\n补充状态（不参与原哈希）：\n"+text(e,s);e->DeleteLocalRef(s);e->DeleteLocalRef(c);
    Item item{"input_methods","输入法检测",service_state(ok,list.service_names,false),ok?(found?"危险：已登记 KeyMapper 输入法服务":list.service_names.empty()?"未发现输入法服务":"可疑：存在其他输入法服务"):"输入法枚举未完成",d+"\n按指定显示规则：其他输入法（含系统输入法）为可疑，KeyMapper 精确特征为危险。这是全部已登记输入法，不代表正在使用；未启用时也可能出现在列表中。",original};
    for(auto& service:list.service_names)item.rows.push_back({service,keymapper_ime(service)?"danger":"suspicious"});
    items.push_back(std::move(item));
}
[[maybe_unused]] std::optional<std::vector<std::uint8_t>> read_memory(std::uint64_t address,std::size_t size){
    if(size>64*1024*1024 || address>UINT64_MAX-size)return {};
    std::vector<std::uint8_t> out(size);if(!size)return out;
    iovec local{out.data(),size},remote{reinterpret_cast<void*>(address),size};
    auto n=syscall(SYS_process_vm_readv,getpid(),&local,1,&remote,1,0);
    if(n==static_cast<ssize_t>(size))return out;
    int fd=open("/proc/self/mem",O_RDONLY|O_CLOEXEC);if(fd<0)return {};std::size_t done=0;
    while(done<size){auto k=pread(fd,out.data()+done,size-done,address+done);if(k<=0)break;done+=k;}close(fd);if(done!=size)return {};return out;
}
void libraries(std::vector<Item>& items){
    for(int index=0;index<4;++index){
        auto lib=static_cast<ev::Library>(index);std::string name=ev::library_name(lib);
        Item item{"integrity_"+std::to_string(index),name+" 完整性","unknown","尚未完成可执行区段比较","",original};
#ifndef __aarch64__
        item.summary="此项需要 ARM64 设备";item.state="na";item.details="重建的 ELF 基线与现场算法针对 AArch64。x86_64 构建只用于界面和平台接入测试。";
#else
        auto before=ch::android::read_maps(name,true);void* handle=nullptr;
        if(before.entries.empty() && (index==0 || index==2))handle=dlopen(name.c_str(),RTLD_NOW|RTLD_LOCAL);
        struct CloseLibrary{void* p;~CloseLibrary(){if(p)dlclose(p);}} close_library{handle};
        auto maps=ch::android::read_maps(name,true);item.details="主动 dlopen："+std::string(handle?"是":"否")+"\n匹配 maps 数："+std::to_string(maps.entries.size())+"\n";
        if(!maps.opened||!maps.fdopen_succeeded||!maps.complete){item.summary="maps 读取失败";items.push_back(item);continue;}
        if(maps.entries.empty()){item.summary="当前进程中未找到该库";items.push_back(item);continue;}
        auto path=maps.entries.front().path;item.details+="文件："+path+"\n";
        int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC);struct stat st{};
        if(fd<0 || fstat(fd,&st) || st.st_size<=0 || st.st_size>512*1024*1024){if(fd>=0)close(fd);item.summary="无法读取 ELF 文件基线";items.push_back(item);continue;}
        auto ptr=mmap(nullptr,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);close(fd);
        if(ptr==MAP_FAILED){item.summary="ELF 映射失败";items.push_back(item);continue;}
        struct Unmap{void* p;size_t n;~Unmap(){munmap(p,n);}} unmap{ptr,static_cast<size_t>(st.st_size)};
        auto baseline=ev::make_elf_baseline(ev::ByteView{static_cast<const std::uint8_t*>(ptr),static_cast<size_t>(st.st_size)},0,2);
        if(!baseline || !baseline->initialized){item.summary="缺少有效的 ARM64 可执行 section 基线";items.push_back(item);continue;}
        auto r=ev::compare_mappings(*baseline,maps.entries,read_memory);int code=r.code?static_cast<int>(*r.code):-1;
        item.details+="native code="+std::to_string(code)+"\nsections_compared="+std::to_string(r.sections_compared)+" / "+std::to_string(baseline->sections.size())+"\nselected_base="+hx(r.selected_base)+"\n"+r.detail+"\n";
        bool compared=r.complete&&r.sections_compared>0;
        if(compared&&code==46){item.state="pass";item.summary="已比较区段与文件一致";}
        else if(r.complete&&code==12){item.state="warn";item.summary="已比较区段或映射路径出现差异";latches[index]=true;}
        else item.summary="未完成完整性比较（不判通过）";
        bool predicted_termination=r.local_termination||(index==0&&r.code&&code!=46);
        item.details+="原模型本地终止条件="+std::string(predicted_termination?"true":"false")+"（本软件仅展示）\n当前会话差异锁存="+(latches[index]?std::string("true"):std::string("false"))+"\n最多前两个 SHF_EXECINSTR 区段；现场文件不是官方可信基线。差异不直接归因于某个 Hook 框架。";
#endif
        items.push_back(item);
    }
    items.push_back({"environment_events","环境事件 21 / 24","info","当前进程会话锁存值","event21 [art, android, libc] = ["+std::to_string(latches[3])+", "+std::to_string(latches[2])+", "+std::to_string(latches[1])+"]\nevent24 = "+std::to_string(latches[3])+"\n锁存仅来自已完成的 code 12；其他项目未知时，零值不代表全部检查通过。手动扫描调度，非原线程轮数。重启进程清除。",original});
}
[[maybe_unused]] __attribute__((noinline)) int entry_sentinel(int x){volatile int add=17;return x+add;}
void process_checks(bool active,std::vector<Item>& items){
    auto tracer=ch::tracer_pid(ch::android::read_tracer_status());items.push_back({"tracer","TracerPid 调试状态",tracer<0?"unknown":tracer>0?"warn":"pass",tracer<0?"读取或解析失败":tracer>0?"当前进程存在 tracer":"当前进程未报告 tracer","TracerPid="+std::to_string(tracer)+"\n读取本 PID 的 status，一次最多 2047 字节。原分支 signed > 0 触发；不覆盖所有 Java 调试方式，也不观察游戏进程。",original});
    auto s=ch::android::inspect_seccomp(0,active);
    bool complete=s.result.complete&&s.status.error==0&&s.status.filters>=0&&s.status.mode>=0&&s.handler.complete&&s.handler.error==0;
    if(s.result.probe_required && (!s.probe || !s.probe->completed || !s.probe->restore_succeeded))complete=false;
    std::string detail="Seccomp="+std::to_string(s.status.mode)+"\nSeccomp_filters="+std::to_string(s.status.filters)+"\nNoNewPrivs="+std::to_string(s.status.no_new_privs)+"\nlayer=0\nstatus_error="+std::to_string(s.status.error)+"\nacceptable="+std::to_string(s.result.flags.acceptable)+"\nexcessive_count="+std::to_string(s.result.flags.excessive_count)+"\nreason="+std::to_string(s.result.flags.reason)+"\ndiagnostic="+std::to_string(s.result.diagnostic)+"\n过滤器计数与原模型一起展示，不能单独推断某个软件。";
    items.push_back({"seccomp","Seccomp 过滤器",complete?(s.result.flags.acceptable?"pass":"warn"):"unknown",complete?(s.result.flags.acceptable?"原聚合规则可接受":"原聚合规则出现异常条件"):"聚合判定未完成",detail,original});
    items.push_back({"sigsys","SIGSYS 信号处理器",s.handler.error||!s.handler.complete?"unknown":s.handler.active?"info":"pass",s.handler.error?"处理器查询失败":s.handler.active?"当前进程存在 SIGSYS handler":"未安装活动 SIGSYS handler","address="+hx(s.handler.address)+"\npath="+s.handler.path+"\nrange="+hx(s.handler.start)+"–"+hx(s.handler.end)+"\nerror="+std::to_string(s.handler.error)+"\n原因码及整体解释见 Seccomp 项。",original});
    std::string pd="active="+std::to_string(active)+"\nprobe_required="+std::to_string(s.result.probe_required)+"\npath="+s.probe_path+"\n";
    if(s.probe)pd+="installed="+std::to_string(s.probe->installed)+"\ncompleted="+std::to_string(s.probe->completed)+"\nmarker_changed="+std::to_string(s.probe->changed)+"\nrestored="+std::to_string(s.probe->restore_succeeded)+"\n";
#ifdef __aarch64__
    items.push_back({"active_probe","SIGSYS 主动探测",s.probe?(s.probe->completed&&s.probe->restore_succeeded?"info":"unknown"):s.result.probe_required?"unknown":"na",s.probe?"已尝试主动 openat 探测":s.result.probe_required?"当前分支需要探测，可在设置中启用":"当前原分支无需主动探测",pd+"仅在原模型要求时执行。临时修改本进程 SIGSYS handler，扫描串行化并尝试恢复；默认关闭。",original});
#else
    items.push_back({"active_probe","SIGSYS 主动探测","na","此项需要 ARM64 设备",pd+"x86_64 适配不模拟 ARM64 syscall 与信号上下文。",original});
#endif
    auto maps=ch::android::read_maps("",true);ch::Event20State state;auto count=ch::event20_counts(state,maps.entries,maps.opened&&maps.fdopen_succeeded&&maps.complete);
    items.push_back({"event20","匿名可执行映射计数","info","仅展示部分模型，不给出异常结论","maps 条目="+std::to_string(maps.entries.size())+"\nacquisition="+std::to_string(maps.opened&&maps.complete)+"\n演示 baseline16=0\ndelta="+std::to_string(count.delta)+"\nempty="+std::to_string(count.empty)+"\n使用已恢复 maps parser 作为输入适配。原独立 scanner 和 baseline16 后续来源未完全闭合。","部分恢复 · 诊断项"});
#ifdef __aarch64__
    auto memory=read_memory(reinterpret_cast<std::uintptr_t>(&entry_sentinel),12);bool hit=false;std::string ed="检查点仅为本软件 entry_sentinel 的前三条 ARM64 指令。\n";
    if(memory){std::uint32_t words[3]{};std::memcpy(words,memory->data(),12);hit=prism_entry_pattern(words[0],words[1],words[2]);for(auto w:words)ed+=hx(w)+" ";}
    items.push_back({"entry_pattern","ARM64 入口指令模式",memory?"info":"unknown",memory?(hit?"本地检查点匹配 B/BRK/BR 模式":"本地检查点未匹配入口模式"):"无法读取检查点指令",ed+"\n没有原始全量检查点名单；匹配可能是合法跳板，不能据此认定 Hook。","部分恢复 · 单点观察"});
#else
    items.push_back({"entry_pattern","ARM64 入口指令模式","na","此项需要 ARM64 设备","不在 x86_64 上解释 ARM64 指令。","部分恢复"});
#endif
}
void classes(JNIEnv* e,jstring config,std::vector<Item>& items){
    std::string raw=text(e,config);ch::JsonValue list;list.type=32;std::istringstream in(raw);std::string line;std::vector<std::string> names;
    while(std::getline(in,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();if(line.empty())continue;if(names.size()>=128 || line.size()>256)throw std::runtime_error("Class list exceeds 128 entries / 256 bytes per name");ch::JsonValue v;v.type=16;v.valuestring=line;list.children.push_back(v);names.push_back(line);}
    if(names.empty()){items.push_back({"classes","类可见性 · event22","na","尚未配置类名单","原任务接收外部类名单，现有证据没有固定名单。可在设置中输入 JNI slash 类名，每行一个。名单为空不代表未发现 Xposed。",original});return;}
    JavaVM* vm=nullptr;e->GetJavaVM(&vm);auto r=ch::probe_classes_jni(&list,vm);
    items.push_back({"classes","类可见性 · event22",r.complete?"info":"unknown","查询 "+std::to_string(r.queried)+" 项，可见 "+std::to_string(r.visible.size())+" 项","输入（保序保重复）：\n"+join(names)+"\n可见：\n"+join(r.visible)+"\n清除异常="+std::to_string(r.cleared)+"\ndiagnostic="+std::to_string(r.diagnostic)+"\n基于当前 JNI/类加载器上下文，不扫描其他进程。名单由使用者配置。",original});
}
}
extern "C" JNIEXPORT jstring JNICALL Java_na1xue_prism_detector_NativeBridge_nativeScan(JNIEnv* e,jclass,jobject ctx,jstring config,jboolean active,jboolean online){
    std::lock_guard<std::mutex> lock(scan_mutex);std::vector<detector::Item> items;
    auto guard=[&](const char* id,const char* title,auto fn){if(e->PushLocalFrame(128)<0){if(e->ExceptionCheck())e->ExceptionClear();items.push_back({id,title,"unknown","JNI 本地帧分配失败","","采集失败"});return;}try{fn();}catch(const std::exception& ex){if(e->ExceptionCheck())e->ExceptionClear();items.push_back({id,title,"unknown","采集失败",ex.what(),"采集失败"});}catch(...){if(e->ExceptionCheck())e->ExceptionClear();items.push_back({id,title,"unknown","采集失败","unhandled native exception","采集失败"});}e->PopLocalFrame(nullptr);};
    guard("packages_error","安装包信息",[&]{packages(e,ctx,items);});
    guard("accessibility_error","无障碍服务",[&]{accessibility(e,ctx,items);});
    guard("ime_error","输入法服务",[&]{inputmethods(e,ctx,items);});
    guard("identity","设备身份",[&]{auto id=prism::collect_android_identity();items.push_back({"identity","设备 ID",id.value.empty()?"unknown":"info",id.value.empty()?"设备 ID 获取失败":id.value,"来源："+std::string(id.from_drm?"Widevine deviceUniqueId 派生":"boot_id 回退派生")+"\n设备 ID："+id.value+"\n采用原固定盐与 SHA-256 派生。应用作用域可能不同；boot_id 回退随设备重启变化。仅本地展示。",original});});
    guard("process_error","进程检测",[&]{process_checks(active,items);});
    guard("integrity_error","库完整性",[&]{libraries(items);});
    guard("classes_error","类可见性",[&]{classes(e,config,items);});
    if(online)guard("time_error","北京时间校对",[&]{items.push_back(detector::network_time());});
    else items.push_back({"network_time","北京时间校对","na","网络校时已关闭","在设置中启用；关闭时不发出时间请求。",custom});
    items.push_back({"host_gate","原宿主门控","na","原 5486 字段语义尚未闭合","不为独立检测 APK 伪造宿主条件，不将未知门控判定为通过。","证据缺口"});
    const std::vector<std::string> order={"minecraft_size","minecraft_certificate","network_time","accessibility","input_methods","keymapper_package","tracer","seccomp","sigsys","active_probe","integrity_0","integrity_1","integrity_2","integrity_3","identity","classes","environment_events","event20","entry_pattern","host_features","host_gate"};
    std::stable_sort(items.begin(),items.end(),[&](const Item& a,const Item& b){return std::find(order.begin(),order.end(),a.id)<std::find(order.begin(),order.end(),b.id);});
#ifdef __aarch64__
    const char* abi="arm64-v8a";
#else
    const char* abi="x86_64 (platform/UI test adapter)";
#endif
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto json=detector::serialize(items,abi,now,getpid(),static_cast<int>(syscall(SYS_gettid)));
    __android_log_print(ANDROID_LOG_INFO,"PrismDetector","scan complete: %zu items; pid=%d tid=%ld abi=%s",items.size(),getpid(),syscall(SYS_gettid),abi);
    return e->NewStringUTF(json.c_str());
}
