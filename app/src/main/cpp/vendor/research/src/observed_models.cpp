#include "observed_models.h"

#include <cstring>

// Consumer predicate at 0x4106f8; status-file parsing is outside this model.
bool prism_tracer_positive(std::int32_t tracer_pid) noexcept {
    return tracer_pid > 0;
}

// 0x47e0a4..0x47e0c8: 32-bit wraparound, followed by signed comparison.
bool prism_filter_exceeds(std::int32_t observed, std::uint32_t layer) noexcept {
    const std::uint32_t bits = layer + 1u;
    std::int32_t bound = 0;
    std::memcpy(&bound, &bits, sizeof(bound));
    return observed > bound;
}

// 0x47f2c8: reason classifier, not a full seccomp or handler check.
bool prism_reason_accepted(std::uint8_t reason) noexcept {
    return reason < 10;
}

// 0x47df58 flag updates; inputs stand for acquisition/classifier results.
void prism_filter_policy(bool status_failed, std::int32_t observed,
                         std::uint32_t layer, bool handler_failed,
                         std::uint8_t reason, PrismFilterFlags* output) noexcept {
    *output = {};
    output->acceptable = 1;
    output->observed = -1;
    if (status_failed) {
        output->status_failed = 1;
        output->acceptable = 0;
    } else {
        output->observed = observed;
        if (prism_filter_exceeds(observed, layer) || (layer == 0 && observed > 1)) {
            output->excessive_count = 1;
            output->acceptable = 0;
        }
    }
    if (!handler_failed) {
        output->reason = reason;
        if (!prism_reason_accepted(reason)) {
            output->suspicious_handler = 1;
            output->acceptable = 0;
        }
    }
}
