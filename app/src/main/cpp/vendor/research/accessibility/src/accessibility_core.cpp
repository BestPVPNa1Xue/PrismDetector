#include "accessibility_core.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace prism::accessibility {
namespace {
std::uint32_t crc_byte(std::uint32_t crc, unsigned char value) {
    crc ^= value;
    for (unsigned i = 0; i < 8; ++i)
        crc = (crc >> 1) ^ ((0U - (crc & 1U)) & 0xedb88320U);
    return crc;
}
bool byte_less(const std::string& a, const std::string& b) {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(),
        [](char x, char y) { return static_cast<unsigned char>(x) < static_cast<unsigned char>(y); });
}
} // namespace

std::uint32_t snapshot_hash(std::vector<std::string> ids) {
    std::sort(ids.begin(), ids.end(), byte_less);
    std::uint32_t crc = 0xffffffffU;
    for (const auto& id : ids) {
        for (unsigned char byte : id) crc = crc_byte(crc, byte);
        crc = crc_byte(crc, 0);
    }
    crc ^= 0xffffffffU;
    return (crc >> 24) | ((crc >> 8) & 0x0000ff00U) |
           ((crc << 8) & 0x00ff0000U) | (crc << 24);
}

Result evaluate_snapshot(State& state, bool was_initialized,
                         const std::vector<std::string>& ids, bool env_available) {
    Result result;
    if (!env_available) {
        result.kind = ResultKind::Error;
        result.error_code = 0xbba;
        return result; // no changes to either state field
    }
    // 0x6cf3ec -> c_str -> cJSON_CreateString; preserve source list order.
    std::vector<std::string> payload;
    payload.reserve(ids.size());
    for (const auto& id : ids) payload.emplace_back(id.c_str());
    const auto hash = snapshot_hash(ids);
    if (!was_initialized) {
        state.initialized.store(true, std::memory_order_seq_cst);
        state.previous_hash.store(hash, std::memory_order_seq_cst);
        result.event_type = 25;
    } else {
        if (hash == state.previous_hash.load(std::memory_order_seq_cst)) return result;
        state.previous_hash.store(hash, std::memory_order_seq_cst);
        result.event_type = 33;
    }
    result.kind = ResultKind::Event;
    result.payload = std::move(payload);
    return result;
}

Result evaluate(State& state, const std::vector<std::string>& ids, bool env_available) {
    return evaluate_snapshot(state, state.initialized.load(std::memory_order_seq_cst), ids, env_available);
}

std::string payload_json(const Result& result) {
    if (result.kind != ResultKind::Event) return "null";
    constexpr char hex[] = "0123456789abcdef";
    std::string out = "[";
    bool first = true;
    for (const auto& id : result.payload) {
        if (!first) out += ',';
        first = false;
        out += '"';
        for (unsigned char c : id) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
                else out += static_cast<char>(c);
            }
        }
        out += '"';
    }
    out += ']';
    return out;
}
} // namespace prism::accessibility

namespace {
std::vector<std::string> unpack(const A11yBytes* ids, std::size_t count) {
    if (count && !ids) throw std::invalid_argument("ids");
    std::vector<std::string> values;
    values.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (ids[i].size && !ids[i].data) throw std::invalid_argument("data");
        values.emplace_back(ids[i].size ? reinterpret_cast<const char*>(ids[i].data) : "", ids[i].size);
    }
    return values;
}
}
std::uint32_t a11y_snapshot_hash(const A11yBytes* ids, std::size_t count) {
    try { return prism::accessibility::snapshot_hash(unpack(ids, count)); }
    catch (...) { return 0; } // test ABI: caller must supply valid inputs
}
int a11y_evaluate(std::uint32_t previous_hash, std::uint32_t initialized,
                  const A11yBytes* ids, std::size_t count, int env_available,
                  A11yModelResult* output, char* payload, std::size_t capacity) {
    if (!output) return -1;
    try {
        prism::accessibility::State state;
        state.previous_hash.store(previous_hash);
        state.initialized.store((initialized & 1U) != 0);
        auto result = prism::accessibility::evaluate(state, unpack(ids, count), env_available != 0);
        *output = {static_cast<std::uint32_t>(result.kind), result.event_type, result.error_code,
                   state.previous_hash.load(), state.initialized.load() ? 1U : 0U};
        const auto text = prism::accessibility::payload_json(result);
        if (!payload || capacity <= text.size()) return -2;
        std::memcpy(payload, text.c_str(), text.size() + 1);
        return 0;
    } catch (...) { return -3; }
}
