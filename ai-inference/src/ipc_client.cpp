// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: AI engine IPC client (ai-inference/src/ipc_client.cpp).
//              Connects to the falxd Unix socket, sends MapUpdateReq messages
//              when the AI model decides to block an IP, and receives
//              InferRequest batches for analysis.
//
//              Threading model:
//                - recv_thread: reads frames from socket → dispatch
//                - send_thread: drains send_queue → writes frames
//                - heartbeat_thread: sends Heartbeat every 5s
//                All threads share the socket fd (guarded by send_mutex).
// =============================================================================

#include "ipc_client.hpp"
#include "ipc_protocol.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <queue>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace falx::ai {

using json = nlohmann::json;
using namespace falx::ipc;

// ─── Constructor ──────────────────────────────────────────────────────────────
IPCClient::IPCClient(const std::string& socket_path,
                     std::shared_ptr<spdlog::logger> log)
    : socket_path_(socket_path), log_(log), fd_(-1), running_(false) {}

IPCClient::~IPCClient() {
    stop();
}

// ─── Connect ──────────────────────────────────────────────────────────────────
bool IPCClient::connect() {
    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) {
        log_->error("socket() failed: {}", std::strerror(errno));
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        log_->error("connect({}) failed: {}", socket_path_, std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    log_->info("Connected to falxd IPC socket: {}", socket_path_);
    return true;
}

// ─── Start ────────────────────────────────────────────────────────────────────
bool IPCClient::start() {
    if (!connect()) return false;

    running_.store(true);

    recv_thread_ = std::thread([this] { recv_loop(); });
    send_thread_ = std::thread([this] { send_loop(); });
    hb_thread_   = std::thread([this] { heartbeat_loop(); });

    return true;
}

// ─── Stop ─────────────────────────────────────────────────────────────────────
void IPCClient::stop() {
    running_.store(false);
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
    send_cv_.notify_all();

    if (recv_thread_.joinable()) recv_thread_.join();
    if (send_thread_.joinable()) send_thread_.join();
    if (hb_thread_.joinable())   hb_thread_.join();
}

// ─── Send MapUpdateReq (AI → CP) ─────────────────────────────────────────────
bool IPCClient::send_block_request(
    const std::string& src_ip,
    uint8_t  action,
    uint8_t  threat_score,
    uint8_t  rule_id,
    uint64_t ttl_seconds,
    const std::string& reason
) {
    json payload = {
        {"src_ip",       src_ip},
        {"action",       action},
        {"threat_score", threat_score},
        {"rule_id",      rule_id},
        {"ttl_s",        ttl_seconds},
        {"reason",       reason},
        {"actor",        "ai-engine"},
    };

    auto frame = build_frame(
        MsgType::MapUpdateReq,
        next_seq(),
        payload.dump()
    );

    return enqueue_frame(std::move(frame));
}

// ─── Send Alert (AI → CP) ─────────────────────────────────────────────────────
bool IPCClient::send_alert(
    uint64_t   flow_id,
    const std::string& src_ip,
    const std::string& severity,
    const std::string& threat_type,
    double     confidence,
    const std::string& description
) {
    json payload = {
        {"flow_id",     flow_id},
        {"src_ip",      src_ip},
        {"severity",    severity},
        {"threat_type", threat_type},
        {"confidence",  confidence},
        {"description", description},
    };

    auto frame = build_frame(MsgType::Alert, next_seq(), payload.dump());
    return enqueue_frame(std::move(frame));
}

// ─── Receive Loop ─────────────────────────────────────────────────────────────
void IPCClient::recv_loop() {
    std::vector<uint8_t> buf(HEADER_SIZE + MAX_PAYLOAD_SIZE);

    while (running_.load()) {
        // Read header
        ssize_t n = recv_exact(buf.data(), HEADER_SIZE);
        if (n <= 0) break;

        // Parse header to get payload length
        Frame frame;
        try {
            // Read payload length from bytes 12-15
            uint32_t payload_len =
                static_cast<uint32_t>(buf[12])        |
                (static_cast<uint32_t>(buf[13]) << 8) |
                (static_cast<uint32_t>(buf[14]) << 16)|
                (static_cast<uint32_t>(buf[15]) << 24);

            if (payload_len > MAX_PAYLOAD_SIZE) {
                log_->error("Payload too large: {}", payload_len);
                break;
            }

            // Read payload
            if (payload_len > 0) {
                n = recv_exact(buf.data() + HEADER_SIZE, payload_len);
                if (n <= 0) break;
            }

            frame = parse_frame(buf.data(), HEADER_SIZE + payload_len);
        } catch (const std::exception& e) {
            log_->error("Frame parse error: {}", e.what());
            continue;
        }

        dispatch(frame);
    }

    log_->info("IPC recv loop exiting");
    running_.store(false);
}

// ─── Dispatch Received Frame ──────────────────────────────────────────────────
void IPCClient::dispatch(const Frame& frame) {
    MsgType type = static_cast<MsgType>(frame.header.type);

    switch (type) {
    case MsgType::InferRequest: {
        // CP → AI: packet batch for inference
        std::string json_str(frame.payload.begin(), frame.payload.end());
        try {
            auto req = json::parse(json_str);
            if (infer_request_cb_) {
                infer_request_cb_(req);
            }
        } catch (const std::exception& e) {
            log_->error("InferRequest parse error: {}", e.what());
        }
        break;
    }

    case MsgType::Heartbeat: {
        // Reply with HeartbeatAck using same seq
        auto ack = build_frame(MsgType::HeartbeatAck, frame.header.seq, 0, nullptr, 0);
        enqueue_frame(std::move(ack));
        break;
    }

    case MsgType::HeartbeatAck:
        log_->debug("Heartbeat ACK received (seq={})", frame.header.seq);
        break;

    case MsgType::Error: {
        std::string json_str(frame.payload.begin(), frame.payload.end());
        log_->warn("Error from falxd: {}", json_str);
        break;
    }

    default:
        log_->warn("Unknown msg type: 0x{:02x}", frame.header.type);
    }
}

// ─── Send Loop ────────────────────────────────────────────────────────────────
void IPCClient::send_loop() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(send_mutex_);
        send_cv_.wait(lock, [this] {
            return !send_queue_.empty() || !running_.load();
        });

        while (!send_queue_.empty()) {
            auto bytes = serialise(send_queue_.front());
            send_queue_.pop();
            lock.unlock();

            if (!write_all(bytes.data(), bytes.size())) {
                log_->error("Send failed — disconnecting");
                running_.store(false);
                return;
            }
            lock.lock();
        }
    }
}

// ─── Heartbeat Loop ───────────────────────────────────────────────────────────
void IPCClient::heartbeat_loop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (!running_.load()) break;

        auto frame = build_frame(MsgType::Heartbeat, next_seq(), 0, nullptr, 0);
        enqueue_frame(std::move(frame));
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
bool IPCClient::enqueue_frame(Frame&& frame) {
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        if (send_queue_.size() > 4096) {
            log_->warn("Send queue full — frame dropped");
            return false;
        }
        send_queue_.push(std::move(frame));
    }
    send_cv_.notify_one();
    return true;
}

uint32_t IPCClient::next_seq() {
    return seq_counter_.fetch_add(1, std::memory_order_relaxed);
}

ssize_t IPCClient::recv_exact(uint8_t* buf, size_t n) {
    size_t received = 0;
    while (received < n && running_.load()) {
        ssize_t r = ::recv(fd_, buf + received, n - received, 0);
        if (r <= 0) return r;
        received += r;
    }
    return static_cast<ssize_t>(received);
}

bool IPCClient::write_all(const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = ::send(fd_, buf + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) return false;
        sent += w;
    }
    return true;
}

} // namespace falx::ai
