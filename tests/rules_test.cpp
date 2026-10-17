#include "../app/src/main/cpp/rules.hpp"
#include "../app/src/main/cpp/certificate_baseline.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
using namespace detector;
int main(){
    assert(apk_size_abnormal(0));assert(apk_size_abnormal(apk_limit-1));assert(apk_size_abnormal(apk_limit));assert(!apk_size_abnormal(apk_limit+1));assert(!apk_size_abnormal(UINT64_MAX));
    assert(keymapper_accessibility("io.github.sds100.keymapper/.system.accessibility.MyAccessibilityService"));
    assert(keymapper_accessibility("io.github.sds100.keymapper/io.github.sds100.keymapper.system.accessibility.MyAccessibilityService"));
    assert(!keymapper_accessibility("other/io.github.sds100.keymapper.system.accessibility.MyAccessibilityService"));
    assert(!keymapper_accessibility("io.github.sds100.keymapper.fake/.system.accessibility.MyAccessibilityService"));
    assert(keymapper_ime("io.github.sds100.keymapper.system.inputmethod.KeyMapperImeService"));assert(!keymapper_ime("io.github.sds100.keymapper.system.inputmethod.KeyMapperImeServiceFake"));
    assert(service_state(true,{},true)=="pass");
    assert(service_state(true,{"test.service/Reader"},true)=="suspicious");
    assert(service_state(true,{"test.service/Reader","io.github.sds100.keymapper/.system.accessibility.MyAccessibilityService"},true)=="danger");
    assert(service_state(false,{"io.github.sds100.keymapper/.system.accessibility.MyAccessibilityService"},true)=="unknown");
    assert(service_state(true,{"com.android.inputmethod.latin.LatinIME"},false)=="suspicious");
    assert(service_state(true,{"io.github.sds100.keymapper.system.inputmethod.KeyMapperImeService"},false)=="danger");
    assert(matches_minecraft_certificate({minecraft_certificate_sha256}));
    assert(!matches_minecraft_certificate({}));assert(!matches_minecraft_certificate({"OTHER_CERT"}));
    assert(!matches_minecraft_certificate({minecraft_certificate_sha256,"OTHER_CERT"}));
    assert(!matches_minecraft_certificate({minecraft_certificate_sha256,minecraft_certificate_sha256}));
    auto report=serialize({{"accessibility","无障碍检测","danger","KeyMapper","detail","custom",{{"component","danger"},{"other","suspicious"}}}},"test",1,1,1);
    assert(report.find("\"rows\":[{\"text\":\"component\",\"state\":\"danger\"},{\"text\":\"other\",\"state\":\"suspicious\"}]")!=std::string::npos);
    assert(quote("a\n\"\\\t")=="\"a\\u000a\\\"\\\\\\u0009\"");
    NtpPacket q{},r{};q[0]=0x23;r[0]=0x24;r[1]=2;double t=1792252800.0;put_ntp_timestamp(q,40,t);std::copy(q.begin()+40,q.end(),r.begin()+24);
    put_ntp_timestamp(r,32,t+10.05);put_ntp_timestamp(r,40,t+10.06);auto s=validate_ntp(r,q,t,t+0.11,0.11);assert(s.valid&&std::abs(s.offset-10)<0.001&&std::abs(s.rtt-0.1)<0.001);
    auto bad=r;bad[24]^=1;assert(!validate_ntp(bad,q,t,t+0.11,0.11).valid);
    bad=r;bad[0]=0xE4;assert(!validate_ntp(bad,q,t,t+0.11,0.11).valid);
    bad=r;bad[1]=0;assert(!validate_ntp(bad,q,t,t+0.11,0.11).valid);
    bad=r;bad[0]=0x23;assert(!validate_ntp(bad,q,t,t+0.11,0.11).valid);
    bad=r;std::fill(bad.begin()+40,bad.end(),0);assert(!validate_ntp(bad,q,t,t+0.11,0.11).valid);
    assert(!validate_ntp(r,q,t,t+5,0.11).valid);assert(!validate_ntp(r,q,t,t+4,4).valid);
    // Era rollover after 2036 must not turn a valid timestamp into 1900.
    t=2208988810.0;put_ntp_timestamp(q,40,t);std::copy(q.begin()+40,q.end(),r.begin()+24);put_ntp_timestamp(r,32,t+0.05);put_ntp_timestamp(r,40,t+0.06);s=validate_ntp(r,q,t,t+0.11,0.11);assert(s.valid&&std::abs(s.offset)<0.001);
    assert(time_decision({})==TimeDecision::Unavailable);assert(time_decision({s})==TimeDecision::SingleSource);
    NtpSample a=s,b=s;a.offset=120;b.offset=120;assert(time_decision({a,b})==TimeDecision::Normal);
    a.offset=120.001;b.offset=120.001;assert(time_decision({a,b})==TimeDecision::Deviated);
    a.offset=-121;b.offset=-121;assert(time_decision({a,b})==TimeDecision::Deviated);
    a.offset=1;b.offset=3;assert(time_decision({a,b})==TimeDecision::Normal);
    b.offset=3.001;assert(time_decision({a,b})==TimeDecision::Disagreement);
    a.valid=false;assert(time_decision({a,b})==TimeDecision::SingleSource);
    std::cout<<"PASS: APK boundaries, exact components, JSON escaping, SNTP validity/clock-step/era cases\n";
}
