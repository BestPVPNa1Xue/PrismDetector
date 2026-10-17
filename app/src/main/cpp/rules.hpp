#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
namespace detector {
constexpr std::uint64_t apk_limit = 1073741824ULL;
bool apk_size_abnormal(std::uint64_t size);
bool keymapper_accessibility(const std::string& component);
bool keymapper_ime(const std::string& service);
std::string quote(const std::string& s);
struct DetailRow { std::string text, state; };
struct Item { std::string id, title, state, summary, details, origin; std::vector<DetailRow> rows{}; };
std::string service_state(bool complete, const std::vector<std::string>& services, bool accessibility);
bool matches_minecraft_certificate(const std::vector<std::string>& current_signers);
std::string serialize(const std::vector<Item>& items, const std::string& abi, std::int64_t timestamp, int pid, int tid);
using NtpPacket = std::array<std::uint8_t,48>;
struct NtpSample { bool valid=false; double offset=0, rtt=0, server=0; std::string error, host; };
void put_ntp_timestamp(NtpPacket& p, int at, double unix_seconds);
NtpSample validate_ntp(const NtpPacket& response, const NtpPacket& request, double t1, double t4, double elapsed);
enum class TimeDecision { Unavailable, SingleSource, Disagreement, Normal, Deviated };
TimeDecision time_decision(const std::vector<NtpSample>& samples);
Item network_time();
}
