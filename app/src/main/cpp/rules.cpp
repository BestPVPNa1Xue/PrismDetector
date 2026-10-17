#include "rules.hpp"
#include "certificate_baseline.hpp"
#include <cmath>
#include <iomanip>
#include <sstream>
namespace detector {
bool apk_size_abnormal(std::uint64_t size) { return size <= apk_limit; }
bool keymapper_accessibility(const std::string& c) {
    return c == "io.github.sds100.keymapper/io.github.sds100.keymapper.system.accessibility.MyAccessibilityService" ||
           c == "io.github.sds100.keymapper/.system.accessibility.MyAccessibilityService";
}
bool keymapper_ime(const std::string& s) { return s == "io.github.sds100.keymapper.system.inputmethod.KeyMapperImeService"; }
std::string service_state(bool complete, const std::vector<std::string>& services, bool accessibility) {
    if(!complete)return "unknown";
    for(const auto& s:services)if(accessibility?keymapper_accessibility(s):keymapper_ime(s))return "danger";
    return services.empty()?"pass":"suspicious";
}
bool matches_minecraft_certificate(const std::vector<std::string>& signers) {
    return signers.size()==1 && signers[0]==minecraft_certificate_sha256;
}
std::string quote(const std::string& s) {
    std::ostringstream o; o << '"';
    for(unsigned char c:s) {
        if(c=='"' || c=='\\') o << '\\' << c;
        else if(c<32) o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << unsigned(c) << std::dec;
        else o << c;
    }
    return o.str()+'"';
}
std::string serialize(const std::vector<Item>& items, const std::string& abi, std::int64_t timestamp,int pid,int tid) {
    std::string s="{\"schema\":2,\"app\":\"PrismDetector\",\"version\":\"1.2.0\",\"abi\":"+quote(abi)+",\"timestamp_ms\":"+std::to_string(timestamp)+",\"pid\":"+std::to_string(pid)+",\"tid\":"+std::to_string(tid)+",\"items\":[";
    bool comma=false;
    for(const auto& i:items) {
        if(comma)s+=',';
        comma=true;
        s+="{\"id\":"+quote(i.id)+",\"title\":"+quote(i.title)+",\"state\":"+quote(i.state)+",\"summary\":"+quote(i.summary)+",\"details\":"+quote(i.details)+",\"origin\":"+quote(i.origin)+",\"rows\":[";
        bool rowcomma=false;for(const auto& r:i.rows){if(rowcomma)s+=',';rowcomma=true;s+="{\"text\":"+quote(r.text)+",\"state\":"+quote(r.state)+"}";}
        s+="]}";
    }
    return s+"]}";
}
void put_ntp_timestamp(NtpPacket& p,int at,double t) {
    double nt=t+2208988800.0; auto sec=static_cast<std::uint64_t>(std::floor(nt));
    auto frac=static_cast<std::uint32_t>((nt-std::floor(nt))*4294967296.0);
    for(int j=0;j<4;++j){p[at+j]=static_cast<std::uint8_t>(sec>>(24-8*j));p[at+4+j]=static_cast<std::uint8_t>(frac>>(24-8*j));}
}
static double decode(const NtpPacket& p,int at,double near) {
    std::uint32_t s=0,f=0;for(int j=0;j<4;++j){s=(s<<8)|p[at+j];f=(f<<8)|p[at+4+j];}
    double v=double(s)+double(f)/4294967296.0-2208988800.0;
    return v+std::round((near-v)/4294967296.0)*4294967296.0;
}
NtpSample validate_ntp(const NtpPacket& r,const NtpPacket& q,double t1,double t4,double elapsed) {
    NtpSample s;
    auto fail=[&](const char* e){s.error=e;return s;};
    unsigned version=(r[0]>>3)&7;
    if((r[0]>>6)==3 || (r[0]&7)!=4 || version<3 || version>4 || r[1]==0 || r[1]>15) return fail("NTP header / stratum invalid");
    for(int j=0;j<8;++j) if(r[24+j]!=q[40+j])return fail("originate timestamp mismatch");
    bool a=false,b=false;for(int j=0;j<8;++j){a|=r[32+j]!=0;b|=r[40+j]!=0;}
    if(!a || !b)return fail("zero server timestamp");
    if(elapsed<0 || elapsed>3 || std::abs((t4-t1)-elapsed)>0.1)return fail("clock changed during sample or RTT too large");
    double t2=decode(r,32,t1),t3=decode(r,40,t1);
    if(t3<t2 || t3-t2>3)return fail("server timestamps inconsistent");
    s.rtt=(t4-t1)-(t3-t2);
    if(s.rtt < -0.01 || s.rtt>3)return fail("invalid network delay");
    s.offset=((t2-t1)+(t3-t4))/2;s.server=t3;s.valid=true;return s;
}
TimeDecision time_decision(const std::vector<NtpSample>& samples) {
    std::vector<double> offsets;
    for(const auto& s:samples)if(s.valid&&std::isfinite(s.offset))offsets.push_back(s.offset);
    if(offsets.empty())return TimeDecision::Unavailable;
    if(offsets.size()==1)return TimeDecision::SingleSource;
    if(std::abs(offsets[0]-offsets[1])>2)return TimeDecision::Disagreement;
    return std::abs((offsets[0]+offsets[1])/2)>120?TimeDecision::Deviated:TimeDecision::Normal;
}
}
