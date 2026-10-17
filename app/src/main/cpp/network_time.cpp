#include "rules.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
namespace detector {
static double real_now(){return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();}
static double steady_now(){return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();}
static NtpSample sample(const char* host){
    NtpSample s;s.host=host;
    addrinfo hints{};hints.ai_socktype=SOCK_DGRAM;hints.ai_family=AF_INET;addrinfo* addresses=nullptr;
    int err=getaddrinfo(host,"123",&hints,&addresses);
    if(err){s.error=std::string("DNS: ")+gai_strerror(err);return s;}
    struct Free{addrinfo* p;~Free(){freeaddrinfo(p);}} free{addresses};
    if(!addresses){s.error="DNS returned no address";return s;}
    int fd=socket(addresses->ai_family,SOCK_DGRAM|SOCK_CLOEXEC,0);
    if(fd<0){s.error="socket unavailable";return s;}
    struct Close{int n;~Close(){close(n);}} closefd{fd};
    if(connect(fd,addresses->ai_addr,addresses->ai_addrlen)){s.error="UDP connect failed";return s;}
    NtpPacket q{};q[0]=0x23;double t1=real_now(),m1=steady_now();put_ntp_timestamp(q,40,t1);
    if(send(fd,q.data(),q.size(),0)!=48){s.error="UDP send failed";return s;}
    pollfd p{fd,POLLIN,0};if(poll(&p,1,1400)<=0){s.error="UDP/123 timeout";return s;}
    std::array<std::uint8_t,512> bytes{};auto n=recv(fd,bytes.data(),bytes.size(),0);double t4=real_now(),m4=steady_now();
    if(n<48){s.error="short NTP packet / network error";return s;}
    NtpPacket r{};std::copy_n(bytes.begin(),48,r.begin());s=validate_ntp(r,q,t1,t4,m4-m1);s.host=host;return s;
}
static std::string beijing(double t){time_t sec=static_cast<time_t>(t)+8*3600;tm out{};gmtime_r(&sec,&out);char b[64]{};strftime(b,sizeof(b),"%Y-%m-%d %H:%M:%S UTC+08:00",&out);return b;}
Item network_time(){
    Item i{"network_time","北京时间校对","unknown","正在获取网络时间","","自定义 · 双源 SNTP"};
    std::vector<NtpSample> ok;std::ostringstream d;d<<"网络源：ntp.aliyun.com / time.cloudflare.com / ntp.tencent.com\n时差阈值：120 秒；双源允许差异：2 秒\n";
    for(const char* host:{"ntp.aliyun.com","time.cloudflare.com","ntp.tencent.com"}){
        auto s=sample(host);d<<host<<": ";if(s.valid){ok.push_back(s);d<<std::fixed<<std::setprecision(3)<<"网络−本机="<<s.offset<<" s，RTT="<<s.rtt<<" s\n";}else d<<s.error<<"\n";
        if(ok.size()==2)break;
    }
    double now=real_now();d<<"本机北京时间："<<beijing(now)<<"\n";
    auto decision=time_decision(ok);
    if(decision==TimeDecision::Unavailable)i.summary="无法取得网络参考时间";
    else {
        double offset=ok[0].offset;if(ok.size()==2)offset=(offset+ok[1].offset)/2;
        d<<"参考北京时间："<<beijing(now+offset)<<"\n";
        if(decision==TimeDecision::SingleSource)i.summary="仅取得单一时间源，未形成结论";
        else if(decision==TimeDecision::Disagreement)i.summary="两个时间源不一致";
        else {i.state=decision==TimeDecision::Deviated?"warn":"pass";i.summary=i.state=="warn"?"设备时间偏差超过 120 秒":"设备时间与网络参考一致";}
    }
    d<<"参考为公共 NTP 服务，不代表国家授时认证；SNTP 未认证。离线、丢包或双源失败不判异常。此项为新增时钟偏差检查，不是原样本变速检测。";i.details=d.str();return i;
}
}
