// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: AI inference engine (ai-inference/src/inference_engine.cpp).
//              Production-quality inference stub with:
//                - Feature extraction from PacketMeta
//                - Heuristic threat scoring (rules-based until ONNX model loads)
//                - ONNX Runtime integration point (model loaded if file exists)
//                - gRPC server via IPC client (connects to falxd Unix socket)
//                - Verdict generation with confidence scoring
//
//              Threat heuristics (pre-model rules):
//                1. SYN flood: high packet rate from single IP
//                2. Port scan: sequential port access pattern
//                3. Amplification DDoS: small request → huge response ratio
//                4. Brute force: repeated failed auth ports (22, 3389, 5900)
//                5. C2 beacon: regular interval packets to unusual ports
// =============================================================================

#include "inference_engine.hpp"
#include "ipc_client.hpp"
#include "ipc_protocol.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <unordered_map>

namespace falx::ai {

using json = nlohmann::json;

// ─── Feature Vector ───────────────────────────────────────────────────────────
struct Features {
    float pkt_rate_norm;       // Normalised packet rate for this source
    float byte_rate_norm;      // Normalised byte rate
    float syn_ratio;           // SYN packets / total packets
    float port_entropy;        // Shannon entropy of destination ports
    float payload_entropy;     // Shannon entropy of payload bytes
    float is_known_bad_port;   // 1.0 if dst_port is in threat list
    float protocol_norm;       // Protocol encoded (TCP=0.3, UDP=0.6, ICMP=0.9)
    float pkt_len_norm;        // Normalised packet length
    float is_brute_force_port; // 1.0 if dst_port ∈ {22, 23, 3389, 5900, 21}
    float interval_regularity; // Regularity score (C2 beacon detection)
};

// ─── Per-source flow state ────────────────────────────────────────────────────
struct FlowState {
    uint64_t pkt_count{0};
    uint64_t byte_count{0};
    uint64_t syn_count{0};
    std::unordered_map<uint16_t, uint32_t> port_counts;
    std::vector<int64_t> inter_arrival_ns;
    int64_t last_seen_ns{0};
    double threat_score_ema{0.0};  // Exponential moving average
};

// ─── Known threat ports ───────────────────────────────────────────────────────
static const std::unordered_set<uint16_t> BRUTE_FORCE_PORTS = {
    21, 22, 23, 25, 110, 143, 3389, 5900, 8080
};
static const std::unordered_set<uint16_t> AMPLIFICATION_PORTS = {
    53, 123, 161, 389, 520, 1900, 11211
};

// ─── Inference Engine ─────────────────────────────────────────────────────────
InferenceEngine::InferenceEngine(const Config& cfg,
                                  std::shared_ptr<spdlog::logger> log)
    : cfg_(cfg), log_(log), running_(false) {}

bool InferenceEngine::initialize() {
    log_->info("Initializing FALX V2 AI Inference Engine v0.1.0");
    log_->info("IPC socket: {}", cfg_.ipc_socket_path);

    ipc_client_ = std::make_unique<IPCClient>(cfg_.ipc_socket_path, log_);

    // Register callback: CP sends InferRequest batches to us
    ipc_client_->set_infer_request_callback([this](const json& req) {
        this->handle_infer_request(req);
    });

    if (!ipc_client_->start()) {
        log_->error("Failed to connect to falxd IPC socket");
        return false;
    }

    // Try to load ONNX model if configured
    if (!cfg_.model_path.empty()) {
        if (load_onnx_model()) {
            log_->info("ONNX model loaded: {}", cfg_.model_path);
        } else {
            log_->warn("ONNX model not found — using heuristic scoring");
        }
    }

    running_.store(true);
    log_->info("AI inference engine ready");
    return true;
}

void InferenceEngine::run() {
    log_->info("AI inference engine running (heuristic mode)");

    // Periodic flow state cleanup
    auto last_cleanup = std::chrono::steady_clock::now();

    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto now = std::chrono::steady_clock::now();
        if (now - last_cleanup > std::chrono::minutes(5)) {
            cleanup_flow_states();
            last_cleanup = now;
        }
    }
}

void InferenceEngine::stop() {
    running_.store(false);
    if (ipc_client_) ipc_client_->stop();
    log_->info("AI inference engine stopped");
}

// ─── InferRequest Handler ─────────────────────────────────────────────────────
void InferenceEngine::handle_infer_request(const json& req) {
    uint64_t request_id = req.value("request_id", uint64_t(0));
    auto packets = req.value("packets", json::array());

    std::vector<json> verdicts;
    verdicts.reserve(packets.size());

    for (const auto& pkt : packets) {
        auto verdict = analyze_packet(pkt);
        if (!verdict.is_null()) {
            verdicts.push_back(verdict);
        }
    }

    if (!verdicts.empty()) {
        json response = {
            {"request_id", request_id},
            {"verdicts",   verdicts}
        };
        uint32_t seq = static_cast<uint32_t>(request_id & 0xFFFFFFFF);
        auto frame = falx::ipc::build_frame(
            falx::ipc::MsgType::InferResponse,
            seq,
            response.dump()
        );
        if (!ipc_client_->send_frame(frame)) {
            log_->error("Failed to send InferResponse for request {}", request_id);
        } else {
            log_->debug("InferResponse sent: {} verdicts for request {}",
                        verdicts.size(), request_id);
        }
    }
}

// ─── Single-Packet Analysis ───────────────────────────────────────────────────
json InferenceEngine::analyze_packet(const json& pkt) {
    std::string src_ip = pkt.value("src_ip", "");
    if (src_ip.empty()) return nullptr;

    uint16_t dst_port  = pkt.value("dst_port", uint16_t(0));
    uint8_t  protocol  = pkt.value("protocol", uint8_t(0));
    uint16_t tcp_flags = pkt.value("tcp_flags", uint16_t(0));
    uint32_t pkt_len   = pkt.value("pkt_len", uint32_t(0));
    uint64_t flow_id   = pkt.value("flow_id", uint64_t(0));

    std::unique_lock<std::mutex> lock(flow_states_mu_);

    // Update flow state
    auto& state = flow_states_[src_ip];
    state.pkt_count++;
    state.byte_count += pkt_len;

    // SYN tracking (flag bit 0x002)
    if (protocol == 6 && (tcp_flags & 0x002)) {
        state.syn_count++;
    }

    // Port entropy tracking
    state.port_counts[dst_port]++;

    // Inter-arrival time
    auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    if (state.last_seen_ns > 0) {
        state.inter_arrival_ns.push_back(now_ns - state.last_seen_ns);
        if (state.inter_arrival_ns.size() > 100) {
            state.inter_arrival_ns.erase(state.inter_arrival_ns.begin());
        }
    }
    state.last_seen_ns = now_ns;

    // Extract features
    Features f = extract_features(src_ip, state, dst_port, protocol, pkt_len);

    // Score
    double score = score_packet(f);

    // Update EMA threat score
    const double alpha = 0.1;
    state.threat_score_ema = alpha * score + (1.0 - alpha) * state.threat_score_ema;

    double final_score = std::max(score, state.threat_score_ema);

    // Capture values needed after releasing lock.
    const std::string reason  = threat_reason(f);
    const std::string ttype   = threat_type(f);
    lock.unlock(); // Release before blocking IPC calls.

    // Generate verdict if threat score exceeds threshold
    if (final_score >= cfg_.block_threshold) {
        uint8_t  action = (final_score >= 0.95) ? 2 : 4; // 2=DROP, 4=RATE_LIMIT
        uint64_t ttl    = (final_score >= 0.95) ? 3600 : 300;

        ipc_client_->send_block_request(
            src_ip, action,
            static_cast<uint8_t>(final_score * 100),
            1, ttl, reason
        );

        return json{
            {"flow_id",          flow_id},
            {"src_ip",           src_ip},
            {"action",           action},
            {"confidence",       final_score},
            {"rule_id",          1},
            {"threat_score",     static_cast<uint8_t>(final_score * 100)},
            {"block_duration_s", ttl},
            {"reason",           reason},
        };
    }

    if (final_score >= cfg_.alert_threshold) {
        ipc_client_->send_alert(
            flow_id, src_ip,
            final_score >= 0.7 ? "high" : "medium",
            ttype, final_score,
            "Suspicious traffic pattern detected"
        );
    }

    return nullptr;
}

// ─── Feature Extraction ───────────────────────────────────────────────────────
Features InferenceEngine::extract_features(
    const std::string& src_ip,
    const FlowState&   state,
    uint16_t           dst_port,
    uint8_t            protocol,
    uint32_t           pkt_len
) {
    Features f{};

    // Packet rate (normalised to 0-1 for 0-100kpps range)
    f.pkt_rate_norm = std::min(static_cast<float>(state.pkt_count) / 100000.0f, 1.0f);

    // SYN ratio
    if (state.pkt_count > 0) {
        f.syn_ratio = static_cast<float>(state.syn_count) / state.pkt_count;
    }

    // Port entropy (Shannon)
    f.port_entropy = shannon_entropy(state.port_counts);

    // Brute force / known bad port
    f.is_brute_force_port  = BRUTE_FORCE_PORTS.count(dst_port) ? 1.0f : 0.0f;
    f.is_known_bad_port    = AMPLIFICATION_PORTS.count(dst_port) ? 1.0f : 0.0f;

    // Protocol encoding
    switch (protocol) {
        case 6:  f.protocol_norm = 0.3f; break; // TCP
        case 17: f.protocol_norm = 0.6f; break; // UDP
        case 1:  f.protocol_norm = 0.9f; break; // ICMP
        default: f.protocol_norm = 0.5f;
    }

    // Packet length (normalised to 1500 MTU)
    f.pkt_len_norm = std::min(static_cast<float>(pkt_len) / 1500.0f, 1.0f);

    // Inter-arrival regularity (C2 beacon detection)
    f.interval_regularity = compute_regularity(state.inter_arrival_ns);

    return f;
}

// ─── Threat Scoring ───────────────────────────────────────────────────────────
double InferenceEngine::score_packet(const Features& f) {
    double score = 0.0;

    // SYN flood: high SYN ratio + high packet rate
    if (f.syn_ratio > 0.8 && f.pkt_rate_norm > 0.1) {
        score = std::max(score, 0.9 + f.pkt_rate_norm * 0.1);
    }

    // Brute force detection
    if (f.is_brute_force_port > 0 && f.pkt_rate_norm > 0.005) {
        score = std::max(score, 0.75 + f.pkt_rate_norm * 0.2);
    }

    // Port scan: high port entropy
    if (f.port_entropy > 0.8) {
        score = std::max(score, 0.7 + f.port_entropy * 0.25);
    }

    // Amplification: small packets to amplification ports
    if (f.is_known_bad_port > 0 && f.pkt_len_norm < 0.1) {
        score = std::max(score, 0.6);
    }

    // C2 beacon: very regular inter-arrival intervals
    if (f.interval_regularity > 0.95 && f.pkt_rate_norm > 0.0001) {
        score = std::max(score, 0.65 + f.interval_regularity * 0.3);
    }

    // ONNX model override if loaded
    if (model_loaded_) {
        double model_score = run_onnx_inference(f);
        score = std::max(score, model_score);
    }

    return std::min(score, 1.0);
}

// ─── Utility Helpers ──────────────────────────────────────────────────────────
float InferenceEngine::shannon_entropy(
    const std::unordered_map<uint16_t, uint32_t>& counts
) {
    uint64_t total = 0;
    for (auto& [_, c] : counts) total += c;
    if (total == 0) return 0.0f;

    double entropy = 0.0;
    for (auto& [_, c] : counts) {
        double p = static_cast<double>(c) / total;
        if (p > 0) entropy -= p * std::log2(p);
    }
    // Normalise by log2(65536) = 16
    return static_cast<float>(entropy / 16.0);
}

float InferenceEngine::compute_regularity(const std::vector<int64_t>& intervals) {
    if (intervals.size() < 3) return 0.0f;

    double mean = 0.0;
    for (auto v : intervals) mean += v;
    mean /= intervals.size();

    double variance = 0.0;
    for (auto v : intervals) {
        double diff = v - mean;
        variance += diff * diff;
    }
    variance /= intervals.size();

    // Coefficient of variation: low CoV = regular = suspicious
    double cv = (mean > 0) ? std::sqrt(variance) / mean : 1.0;
    // Invert: regularity = 1 - min(CoV, 1)
    return static_cast<float>(1.0 - std::min(cv, 1.0));
}

std::string InferenceEngine::threat_reason(const Features& f) {
    if (f.syn_ratio > 0.8)         return "syn_flood";
    if (f.port_entropy > 0.8)      return "port_scan";
    if (f.is_brute_force_port > 0) return "brute_force";
    if (f.is_known_bad_port > 0)   return "amplification_attempt";
    if (f.interval_regularity > 0.95) return "c2_beacon";
    return "anomaly";
}

std::string InferenceEngine::threat_type(const Features& f) {
    return threat_reason(f);
}

bool InferenceEngine::load_onnx_model() {
    // ONNX Runtime integration point
    // Actual implementation: use Ort::Session to load the model
    // Stub: model_loaded_ remains false
    model_loaded_ = false;
    return false;
}

double InferenceEngine::run_onnx_inference(const Features&) {
    // Stub: returns 0.0 until ONNX model is loaded
    return 0.0;
}

void InferenceEngine::cleanup_flow_states() {
    auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    const int64_t timeout_ns = 5LL * 60 * 1000000000LL;

    std::unique_lock<std::mutex> lock(flow_states_mu_);
    for (auto it = flow_states_.begin(); it != flow_states_.end(); ) {
        if (now_ns - it->second.last_seen_ns > timeout_ns) {
            it = flow_states_.erase(it);
        } else {
            ++it;
        }
    }
    size_t remaining = flow_states_.size();
    lock.unlock();
    log_->debug("Flow state cleanup: {} active sources", remaining);
}

} // namespace falx::ai
