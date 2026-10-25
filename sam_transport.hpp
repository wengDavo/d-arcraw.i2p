// Production I2P transport over SAM v3 (STREAM style, length-framed).
//
// One request per stream, matching how the netDb uses Transport: send() opens a
// STREAM CONNECT, writes one framed message, reads one framed reply, and closes. The
// accept loop reads one framed message, calls the handler, writes the reply, closes.
//
// This has to be validated against a live router: the SAM dialogue cannot be exercised
// without one. address() is the full base64 destination (what STREAM CONNECT needs);
// b32() is the display name. One hardening item before production: keep several
// STREAM ACCEPTs outstanding so concurrent inbound connections are not dropped.
#pragma once
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

#include "darcraw/hash.hpp"
#include "darcraw/transport.hpp"

namespace darcraw {

// --- I2P base64 (alphabet A-Z a-z 0-9 - ~) and RFC4648 base32 lowercase ----
inline Bytes i2p_b64_decode(const std::string& s) {
    static const std::string A =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
    int rev[256];
    for (int i = 0; i < 256; i++) rev[i] = -1;
    for (int i = 0; i < (int)A.size(); i++) rev[(unsigned char)A[i]] = i;
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : s) {
        int v = rev[(unsigned char)c];
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xff));
        }
    }
    return out;
}

inline std::string i2p_b32_address(const Bytes& destination) {
    static const char* A = "abcdefghijklmnopqrstuvwxyz234567";
    Bytes h = sha256(destination);
    std::string out;
    int buf = 0, bits = 0;
    for (uint8_t b : h) {
        buf = (buf << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(A[(buf >> bits) & 31]);
        }
    }
    if (bits > 0) out.push_back(A[(buf << (5 - bits)) & 31]);
    return out + ".b32.i2p";
}

// --- small socket helpers ---------------------------------------------------
namespace sam_detail {

inline int dial(const std::string& host, int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket()");
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); throw std::runtime_error("inet_pton"); }
    if (::connect(fd, (sockaddr*)&a, sizeof a) != 0) { ::close(fd); throw std::runtime_error("connect SAM bridge"); }
    return fd;
}
inline void write_all(int fd, const char* p, size_t n) {
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w <= 0) throw std::runtime_error("write");
        p += w;
        n -= (size_t)w;
    }
}
inline void write_all(int fd, const std::string& s) { write_all(fd, s.data(), s.size()); }
inline std::string read_line(int fd) {
    std::string line;
    char c;
    while (::read(fd, &c, 1) == 1) {
        if (c == '\n') break;
        line.push_back(c);
    }
    return line;
}
inline void write_framed(int fd, const std::string& msg) {
    char len[4];
    uint32_t n = (uint32_t)msg.size();
    for (int i = 0; i < 4; i++) len[i] = (char)((n >> (8 * (3 - i))) & 0xff);
    write_all(fd, len, 4);
    write_all(fd, msg);
}
inline std::string read_framed(int fd) {
    unsigned char len[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t r = ::read(fd, len + got, 4 - got);
        if (r <= 0) throw std::runtime_error("read len");
        got += (size_t)r;
    }
    uint32_t n = (len[0] << 24) | (len[1] << 16) | (len[2] << 8) | len[3];
    std::string out;
    out.resize(n);
    got = 0;
    while (got < n) {
        ssize_t r = ::read(fd, &out[got], n - got);
        if (r <= 0) throw std::runtime_error("read body");
        got += (size_t)r;
    }
    return out;
}
inline bool result_ok(const std::string& line) { return line.find("RESULT=OK") != std::string::npos; }
inline std::string field(const std::string& line, const std::string& key) {
    auto p = line.find(key + "=");
    if (p == std::string::npos) return "";
    p += key.size() + 1;
    auto e = line.find_first_of(" \n", p);
    return line.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

}  // namespace sam_detail

class SAMTransport : public Transport {
public:
    SAMTransport(const std::string& session_id, const std::string& sam_host = "127.0.0.1",
                 int sam_port = 7656)
        : id_(session_id), host_(sam_host), port_(sam_port) {
        using namespace sam_detail;
        control_ = dial(host_, port_);
        hello(control_);
        write_all(control_, "SESSION CREATE STYLE=STREAM ID=" + id_ +
                                " DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n");
        std::string r = read_line(control_);
        if (!result_ok(r)) throw std::runtime_error("SESSION CREATE: " + r);
        dest_ = field(r, "DESTINATION");
        b32_ = i2p_b32_address(i2p_b64_decode(dest_));
    }

    ~SAMTransport() override {
        running_ = false;
        if (control_ >= 0) ::close(control_);
        if (accept_thread_.joinable()) accept_thread_.join();
    }

    const std::string& address() const override { return dest_; }   // base64 destination
    const std::string& b32() const { return b32_; }

    std::string send(const std::string& dest, const std::string& msg) override {
        using namespace sam_detail;
        int fd = dial(host_, port_);
        try {
            hello(fd);
            write_all(fd, "STREAM CONNECT ID=" + id_ + " DESTINATION=" + dest + " SILENT=false\n");
            std::string r = read_line(fd);
            if (!result_ok(r)) throw std::runtime_error("STREAM CONNECT: " + r);
            write_framed(fd, msg);
            std::string resp = read_framed(fd);
            ::close(fd);
            return resp;
        } catch (...) {
            ::close(fd);
            throw;
        }
    }

    void serve(RpcHandler handler) override {
        handler_ = std::move(handler);
        running_ = true;
        accept_thread_ = std::thread([this]() { accept_loop(); });
    }

private:
    void hello(int fd) {
        using namespace sam_detail;
        write_all(fd, "HELLO VERSION MIN=3.0 MAX=3.1\n");
        if (!result_ok(read_line(fd))) throw std::runtime_error("SAM HELLO failed");
    }

    void accept_loop() {
        using namespace sam_detail;
        while (running_) {
            int fd = -1;
            try {
                fd = dial(host_, port_);
                hello(fd);
                write_all(fd, "STREAM ACCEPT ID=" + id_ + " SILENT=false\n");
                if (!result_ok(read_line(fd))) { ::close(fd); continue; }
                std::string peer = read_line(fd);          // inbound peer destination
                std::string msg = read_framed(fd);
                std::string resp = handler_ ? handler_(peer, msg) : std::string();
                write_framed(fd, resp);
                ::close(fd);
            } catch (...) {
                if (fd >= 0) ::close(fd);
            }
        }
    }

    std::string id_, host_;
    int port_;
    int control_ = -1;
    std::string dest_, b32_;
    RpcHandler handler_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
};

}  // namespace darcraw
