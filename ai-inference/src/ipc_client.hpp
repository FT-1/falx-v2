// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: AI engine IPC client header (ai-inference/src/ipc_client.hpp).
// =============================================================================

#pragma once

#include "ipc_protocol.hpp"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <nlohmann/json_fwd.hpp>
#include <spdlog/spdlog.h>

namespace falx::ai {

class IPCClient {
public:
    explicit IPCClient(const std::string& socket_path,
                       std::shared_ptr<spdlog::logger> log);
    ~IPCClient();

    // Delete copy
    IPCClient(const IPCClient&) = delete;
    IPCClient& operator=(const IPCClient&) = delete;

    // ── Lifecycle ────────────────────────────────────────────────────────
    bool start();
    void stop();
    bool is_running() const { return running_.load(); }

    // ── AI → CP: Send block/alert ─────────────────────────────────────
    bool send_block_request(
        const std::string& src_ip,
        uint8_t  action,
        uint8_t  threat_score,
        uint8_t  rule_id,
        uint64_t ttl_seconds,
        const std::string& reason
    );

    bool send_alert(
        uint64_t   flow_id,
        const std::string& src_ip,
        const std::string& severity,
        const std::string& threat_type,
        double     confidence,
        const std::string& description
    );

    // ── AI → CP: Send a raw frame (InferResponse, etc.) ──────────────
    bool send_frame(const falx::ipc::Frame& frame) {
        return enqueue_frame(falx::ipc::Frame(frame));
    }

    // ── CP → AI: Callback registration ───────────────────────────────
    using InferRequestCb = std::function<void(const nlohmann::json&)>;
    void set_infer_request_callback(InferRequestCb cb) {
        infer_request_cb_ = std::move(cb);
    }

private:
    std::string                      socket_path_;
    std::shared_ptr<spdlog::logger>  log_;
    int                              fd_;
    std::atomic<bool>                running_;
    std::atomic<uint32_t>            seq_counter_{1};

    // Threads
    std::thread recv_thread_;
    std::thread send_thread_;
    std::thread hb_thread_;

    // Send queue
    std::mutex                       send_mutex_;
    std::condition_variable          send_cv_;
    std::queue<falx::ipc::Frame>     send_queue_;

    // Callback
    InferRequestCb infer_request_cb_;

    // Internal
    bool    connect();
    void    recv_loop();
    void    send_loop();
    void    heartbeat_loop();
    void    dispatch(const falx::ipc::Frame& frame);
    bool    enqueue_frame(falx::ipc::Frame&& frame);
    uint32_t next_seq();
    ssize_t recv_exact(uint8_t* buf, size_t n);
    bool    write_all(const uint8_t* buf, size_t n);
};

} // namespace falx::ai
