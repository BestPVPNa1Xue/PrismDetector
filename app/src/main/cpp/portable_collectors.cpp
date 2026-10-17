// x86_64 UI/test adapter only. ARM64 builds use the original direct-svc collector.
#include "vendor/research/chain_closure_20261018/src/android_collectors.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <sstream>
namespace prism::chains::android {
static ReadObservation read_once(const char* leaf,std::size_t cap){ReadObservation r;std::string path="/proc/"+std::to_string(getpid())+"/"+leaf;int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC);if(fd<0){r.opened=false;return r;}r.bytes.resize(cap-1);auto n=read(fd,r.bytes.data(),cap-1);close(fd);if(n<0){r.read_failed=true;r.bytes.clear();}else r.bytes.resize(n);return r;}
ReadObservation read_tracer_status(){return read_once("status",2048);}
ReadObservation read_seccomp_status(){return read_once("status",4096);}
ReadObservation read_cmdline(){return read_once("cmdline",256);}
MapsObservation read_maps(std::string_view name,bool exclude){std::ifstream in("/proc/self/maps");std::ostringstream s;s<<in.rdbuf();auto r=filter_maps(s.str(),name,exclude,in.is_open(),true);if(in.bad())r.complete=false;return r;}
HandlerInfo query_sigsys(){struct sigaction a{};bool ok=sigaction(SIGSYS,nullptr,&a)==0;auto addr=reinterpret_cast<std::uintptr_t>(a.sa_sigaction);return locate_sigsys_handler(ok,addr,addr>1?read_maps("",true):MapsObservation{});}
CurrentSeccomp inspect_seccomp(std::uint32_t layer,bool){CurrentSeccomp o;o.status=seccomp_status(read_seccomp_status());o.handler=query_sigsys();o.cmdline=cmdline_first(read_cmdline());o.result=evaluate_seccomp(o.status,o.handler,layer,o.cmdline);return o;}
}
