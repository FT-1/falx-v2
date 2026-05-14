// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Inference engine header (ai-inference/src/inference_engine.hpp)
// =============================================================================

#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <spdlog/logger.h>

namespace falx::ai {

class IPCClient;
struct Features;
struct FlowState;

class InferenceEngine {
public:
    struct Config {
        std::string ipc_socket_path = "/var/run/falx/ai.sock";
        std::string model_path;           // Optional ONNX model path
        double      block_threshold = 0.85;
        double      alert_threshold = 0.50;
    };

    explicit InferenceEngine(const Config& cfg,
                             std::shared_ptr<spdlog::logger> log);

    bool initialize();
    void run();    // Blocking
    void stop();

private:
    Config   cfg_;
    std::shared_ptr<spdlog::logger> log_;
    std::unique_ptr<IPCClient>      ipc_client_;
    std::atomic<bool>               running_;
    bool                            model_loaded_{false};

    // flow_states_ is written by the IPC receive thread and read/cleaned by
    // the run() loop — must be guarded.
    mutable std::mutex                          flow_states_mu_;
    std::unordered_map<std::string, FlowState> flow_states_;

    void   handle_infer_request(const nlohmann::json& req);
    nlohmann::json analyze_packet(const nlohmann::json& pkt);
    Features extract_features(const std::string& src_ip,
                               const FlowState& state,
                               uint16_t dst_port,
                               uint8_t  protocol,
                               uint32_t pkt_len);
    double score_packet(const Features& f);
    float  shannon_entropy(const std::unordered_map<uint16_t,uint32_t>& counts);
    float  compute_regularity(const std::vector<int64_t>& intervals);
    std::string threat_reason(const Features& f);
    std::string threat_type(const Features& f);
    bool   load_onnx_model();
    double run_onnx_inference(const Features& f);
    void   cleanup_flow_states();
};

} // namespace falx::ai
