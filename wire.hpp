// Compact binary framing for RPC messages. Integers are big-endian (network order)
// and byte strings carry a 32-bit length prefix. A hand-rolled binary format rather
// than JSON: it is smaller and faster on the wire, which is the point of the netDb's
// hot path.
#pragma once
#include <cstdint>
#include <string>
#include <stdexcept>

#include "darcraw/hash.hpp"

namespace darcraw {

class Writer {
public:
    void u8(uint8_t v) { buf_.push_back((char)v); }
    void u64(uint64_t v) {
        for (int i = 7; i >= 0; i--) buf_.push_back((char)((v >> (8 * i)) & 0xff));
    }
    void i64(int64_t v) { u64((uint64_t)v); }
    void bytes(const uint8_t* d, size_t n) {
        if (n > 0xffffffffULL) throw std::length_error("field too large");
        u32((uint32_t)n);
        buf_.append(reinterpret_cast<const char*>(d), n);
    }
    void bytes(const Bytes& b) { bytes(b.data(), b.size()); }
    void str(const std::string& s) {
        bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    const std::string& str_view() const { return buf_; }
    std::string take() { return std::move(buf_); }

private:
    void u32(uint32_t v) {
        for (int i = 3; i >= 0; i--) buf_.push_back((char)((v >> (8 * i)) & 0xff));
    }
    std::string buf_;
};

class Reader {
public:
    // Owns its buffer by value, so a Reader built from an rpc() temporary stays valid.
    explicit Reader(std::string buf) : buf_(std::move(buf)) {}

    uint8_t u8() {
        need(1);
        return (uint8_t)buf_[pos_++];
    }
    uint64_t u64() {
        need(8);
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (uint8_t)buf_[pos_++];
        return v;
    }
    int64_t i64() { return (int64_t)u64(); }
    Bytes bytes() {
        uint32_t n = u32();
        need(n);
        Bytes out(buf_.begin() + pos_, buf_.begin() + pos_ + n);
        pos_ += n;
        return out;
    }
    std::string str() {
        uint32_t n = u32();
        need(n);
        std::string out(buf_, pos_, n);
        pos_ += n;
        return out;
    }
    bool eof() const { return pos_ >= buf_.size(); }

private:
    uint32_t u32() {
        need(4);
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) v = (v << 8) | (uint8_t)buf_[pos_++];
        return v;
    }
    void need(size_t n) {
        if (pos_ + n > buf_.size()) throw std::out_of_range("wire underrun");
    }
    std::string buf_;
    size_t pos_ = 0;
};

}  // namespace darcraw
