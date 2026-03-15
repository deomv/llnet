#pragma once

// POSIX headers before wolfSSL to avoid macro conflicts
#include <sys/random.h>
#include <time.h>

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/sha.h>
#else
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

#include <llnet/detail/inplace_function.h>
#include <llnet/tls_socket.h>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

namespace llnet
{

  // WsSocket — WebSocket (RFC 6455) framing over TlsSocket.
  //
  // recv_padding: extra readable bytes allocated beyond kRecvCap and reported
  // in the `capacity` argument of MsgCb.  Pass your parser's required padding
  // here so the message buffer can be used zero-copy without a separate
  // allocation.  Example (simdjson): WsSocket ws{simdjson::SIMDJSON_PADDING};
  //
  // Frame masking uses a SplitMix64 PRNG seeded from getrandom() at construction
  // (one syscall).  Per RFC 6455 the mask prevents proxy cache poisoning; TLS
  // provides actual confidentiality, so a fast PRNG is appropriate here.
  //
  // Usage:
  //   ws.set_io_service(loop);
  //   ws.set_on_connect([&]{ ws.send_text(msg, len); });
  //   ws.set_on_message([&](uint64_t recv_ns, const char* d, size_t n, size_t cap){ ... });
  //   ws.resolve("stream.binance.com", 9443, "/ws/btcusdt@bookTicker");
  //   ws.connect();

  class WsSocket
  {
   public:
    static constexpr size_t kRecvCap = 256 * 1024;
    static constexpr size_t kSendCap = 64  * 1024;

   private:
    // ── RFC 6455 frame constants ───────────────────────────────────────────────
    static constexpr uint8_t  kFin            = 0x80;  // FIN bit in byte 0
    static constexpr uint8_t  kMask           = 0x80;  // MASK bit in byte 1
    static constexpr uint8_t  kOpcodeMask     = 0x0F;  // opcode nibble in byte 0
    static constexpr uint8_t  kPayloadLenMask = 0x7F;  // payload len field in byte 1
    static constexpr uint8_t  kPayloadLen16   = 126;   // marker: next 2 bytes are length
    static constexpr uint8_t  kPayloadLen64   = 127;   // marker: next 8 bytes are length
    static constexpr size_t   kMinHdrSize     = 2;     // FIN+opcode byte + length byte
    static constexpr size_t   kHdrSize16      = 4;     // +2 bytes for 16-bit extended length
    static constexpr size_t   kHdrSize64      = 10;    // +8 bytes for 64-bit extended length
    static constexpr size_t   kMaskKeySize    = 4;     // masking-key field size
    static constexpr size_t   kPayloadLen16Max= 65536; // max payload for 16-bit length field
    static constexpr size_t   kMaxFrameOverhead = kMinHdrSize + 8 + kMaskKeySize; // 14 bytes

    // ── handshake constants ────────────────────────────────────────────────────
    static constexpr size_t   kWsNonceLen        = 16;  // random bytes for Sec-WebSocket-Key
    static constexpr size_t   kSha1Len           = 20;  // SHA-1 digest size
    static constexpr size_t   kWsKeyB64Len       = 32;  // base64(16 bytes) + NUL
    static constexpr size_t   kUpgradeReqLen     = 512; // HTTP upgrade request buffer
    static constexpr size_t   kHttpSwitchingLen  = 12;  // len of "HTTP/1.1 101"

    // ── allocation constants ───────────────────────────────────────────────────
    static constexpr size_t   kBufAlign          = 64;  // cache-line alignment for buffers

    // aligned_alloc requires size to be a multiple of alignment.
    static constexpr size_t align_up(size_t n, size_t a) noexcept { return (n + a - 1) & ~(a - 1); }

   public:

    using ConnCb = detail::inplace_function<void(),                                          32>;
    using MsgCb  = detail::inplace_function<void(uint64_t, const char*, size_t, size_t),     32>;
    using DiscCb = detail::inplace_function<void(),                                          32>;

    explicit WsSocket(size_t recv_padding = 0, LogFn log = noop_log) noexcept
      : client_{log}, log_{log}, recv_padding_{recv_padding}
    {
      ws_recv_buf_ = static_cast<char*>(std::aligned_alloc(kBufAlign, align_up(kRecvCap + recv_padding_, kBufAlign)));
      ws_send_buf_ = static_cast<char*>(std::aligned_alloc(kBufAlign, kSendCap));
      frag_buf_    = static_cast<char*>(std::aligned_alloc(kBufAlign, align_up(kRecvCap + recv_padding_, kBufAlign)));
      if (!ws_recv_buf_ || !ws_send_buf_ || !frag_buf_)
        log_("[llnet::WsSocket] buffer allocation failed");
      // Seed the frame-masking PRNG once — avoids a getrandom() syscall per send.
      ::getrandom(&mask_rng_state_, sizeof(mask_rng_state_), 0);

      client_.set_on_connect   ([this]                         { on_tcp_connect(); });
      client_.set_on_data      ([this](const char* d, size_t n){ on_tcp_data(d, n); });
      client_.set_on_disconnect([this]                         { on_tcp_disc(); });
    }

    ~WsSocket()
    {
      std::free(ws_recv_buf_);
      std::free(ws_send_buf_);
      std::free(frag_buf_);
    }

    WsSocket(const WsSocket&)            = delete;
    WsSocket& operator=(const WsSocket&) = delete;
    WsSocket(WsSocket&&)                 = delete;
    WsSocket& operator=(WsSocket&&)      = delete;

    void set_on_connect   (ConnCb cb) { on_connect_ = std::move(cb); }
    void set_on_message   (MsgCb  cb) { on_message_ = std::move(cb); }
    void set_on_disconnect(DiscCb cb) { on_disc_    = std::move(cb); }

    void set_io_service(EpollLoop& svc)                { client_.set_io_service(svc); }
    void set_verify_peer(bool enabled)                 { client_.set_verify_peer(enabled); }
    [[nodiscard]] bool set_ca_file(const char* p)      { return client_.set_ca_file(p); }
    [[nodiscard]] bool set_min_rsa_key_bits(uint16_t b){ return client_.set_min_rsa_key_bits(b); }
    [[nodiscard]] bool set_min_ecc_key_bits(uint16_t b){ return client_.set_min_ecc_key_bits(b); }

    [[nodiscard]] bool resolve(const char* host, uint16_t port, const char* path)
    {
      host_ = host;
      path_ = path;
      return client_.resolve(host, port);
    }

    [[nodiscard]] bool connect()
    {
      if (!ws_recv_buf_ || !ws_send_buf_ || !frag_buf_)
      { log_("[llnet::WsSocket] connect() with failed buffer allocation"); return false; }
      ws_state_    = WsState::Tcp;
      ws_recv_len_ = 0;
      frag_len_    = 0;
      return client_.connect();
    }

    void disconnect() noexcept
    {
      if (ws_state_ == WsState::Closed) return;
      client_.disconnect();
      on_tcp_disc();  // reset ws_state_, clear buffers, fire on_disc_
    }
    [[nodiscard]] bool is_connected() const noexcept { return ws_state_ == WsState::Open; }

    [[nodiscard]] bool send_text(const char* data, size_t len)
    {
      if (ws_state_ != WsState::Open) return false;
      if (len + kMaxFrameOverhead > kSendCap) { log_("[llnet::WsSocket] send payload too large"); return false; }
      size_t frame_len = build_frame(static_cast<uint8_t>(WsOpcode::Text), data, len);
      return client_.send_raw({ws_send_buf_, frame_len});
    }

    void send_ping()
    {
      size_t frame_len = build_frame(static_cast<uint8_t>(WsOpcode::Ping), nullptr, 0);
      if (frame_len > 0) (void)client_.send_raw({ws_send_buf_, frame_len});
    }

   private:
    enum class WsState  : uint8_t { Tcp, Handshake, Open, Closed };
    enum class WsOpcode : uint8_t
    {
      Continuation = 0x0, Text = 0x1, Binary = 0x2,
      Close = 0x8, Ping = 0x9, Pong = 0xA,
    };

    // ── TCP callbacks ─────────────────────────────────────────────────────────

    void on_tcp_connect()
    {
      ws_state_ = WsState::Handshake;
      send_upgrade_request();
    }

    void on_tcp_data(const char* data, size_t len)
    {
      timespec ts{};
      ::clock_gettime(CLOCK_REALTIME, &ts);
      tcp_recv_ns_ = static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL
                   + static_cast<uint64_t>(ts.tv_nsec);

      if (ws_recv_len_ + len > kRecvCap)
      {
        protocol_error("[llnet::WsSocket] recv buffer overflow — dropping connection");
        return;
      }
      std::memcpy(ws_recv_buf_ + ws_recv_len_, data, len);
      ws_recv_len_ += len;

      if      (ws_state_ == WsState::Handshake) parse_upgrade_response();
      else if (ws_state_ == WsState::Open)       dispatch_frames();
    }

    void on_tcp_disc()
    {
      ws_state_    = WsState::Closed;
      ws_recv_len_ = 0;
      frag_len_    = 0;
      if (on_disc_) on_disc_();
    }

    // Called on unrecoverable protocol or I/O errors.  Closes the connection
    // and notifies the WsSocket layer (fires on_disc_ callback, resets state).
    // client_.disconnect() alone is not enough — it tears down the TCP/TLS
    // socket but does NOT call on_tcp_disc(), so ws_state_ would stay stale.
    void protocol_error(const char* msg)
    {
      log_(msg);
      if (ws_state_ == WsState::Closed) return;  // avoid re-entrancy
      client_.disconnect();
      on_tcp_disc();
    }

    // ── WebSocket upgrade ─────────────────────────────────────────────────────

    void send_upgrade_request()
    {
      // getrandom here is fine — one-time call during connection setup, not hot path.
      uint8_t nonce[kWsNonceLen];
      if (::getrandom(nonce, sizeof(nonce), 0) != static_cast<ssize_t>(sizeof(nonce)))
      {
        protocol_error("[llnet::WsSocket] getrandom failed — aborting upgrade");
        return;
      }
      char key_b64[kWsKeyB64Len];
      base64_encode(nonce, kWsNonceLen, key_b64, sizeof(key_b64));
      ws_key_ = key_b64;

      char req[kUpgradeReqLen];
      int n = std::snprintf(req, sizeof(req),
                            "GET %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Key: %s\r\n"
                            "Sec-WebSocket-Version: 13\r\n"
                            "\r\n",
                            path_.c_str(), host_.c_str(), key_b64);
      if (n < 0 || n >= static_cast<int>(sizeof(req)))
      {
        // n >= sizeof(req) means snprintf truncated: the true length exceeds the
        // buffer, so passing n to send_raw would read past the stack allocation.
        protocol_error("[llnet::WsSocket] upgrade request too large — host/path too long");
        return;
      }
      if (!client_.send_raw({req, static_cast<size_t>(n)}))
        log_("[llnet::WsSocket] send_raw failed during upgrade");
    }

    void parse_upgrade_response()
    {
      const char* end = static_cast<const char*>(
          ::memmem(ws_recv_buf_, ws_recv_len_, "\r\n\r\n", 4));
      if (!end) return;

      size_t header_len = static_cast<size_t>(end - ws_recv_buf_) + 4;
      if (header_len < kHttpSwitchingLen || std::memcmp(ws_recv_buf_, "HTTP/1.1 101", kHttpSwitchingLen) != 0)
      {
        protocol_error("[llnet::WsSocket] upgrade rejected");
        return;
      }
      if (!verify_accept(ws_recv_buf_, header_len))
      {
        protocol_error("[llnet::WsSocket] invalid Sec-WebSocket-Accept");
        return;
      }

      ws_state_ = WsState::Open;
      if (on_connect_) on_connect_();

      size_t remaining = ws_recv_len_ - header_len;
      if (remaining > 0) std::memmove(ws_recv_buf_, ws_recv_buf_ + header_len, remaining);
      ws_recv_len_ = remaining;
      if (ws_recv_len_ > 0) dispatch_frames();
    }

    // ── frame parsing ─────────────────────────────────────────────────────────

    void dispatch_frames()
    {
      while (ws_recv_len_ >= kMinHdrSize)
      {
        const uint8_t* buf = reinterpret_cast<const uint8_t*>(ws_recv_buf_);
        bool     fin        = (buf[0] & kFin)            != 0;
        uint8_t  op         =  buf[0] & kOpcodeMask;
        bool     masked     = (buf[1] & kMask)           != 0;
        uint64_t payload_len =  buf[1] & kPayloadLenMask;

        size_t hdr = kMinHdrSize;
        if (payload_len == kPayloadLen16)
        {
          if (ws_recv_len_ < kHdrSize16) return;
          payload_len = (static_cast<uint64_t>(buf[2]) << 8) | buf[3];
          hdr = kHdrSize16;
        }
        else if (payload_len == kPayloadLen64)
        {
          if (ws_recv_len_ < kHdrSize64) return;
          payload_len = 0;
          for (int i = 0; i < 8; ++i) payload_len = (payload_len << 8) | buf[2 + i];
          hdr = kHdrSize64;
        }

        if (payload_len > kRecvCap)
        {
          protocol_error("[llnet::WsSocket] oversized frame — dropping connection");
          return;
        }

        size_t mask_len  = masked ? kMaskKeySize : 0;
        size_t frame_len = hdr + mask_len + static_cast<size_t>(payload_len);
        if (ws_recv_len_ < frame_len) return;

        const uint8_t* mask_key = masked ? buf + hdr : nullptr;
        char* payload = ws_recv_buf_ + hdr + mask_len;
        if (masked)
        {
          for (uint64_t i = 0; i < payload_len; ++i)
            payload[i] ^= mask_key[i & 3];
        }

        handle_frame(op, fin, payload, static_cast<size_t>(payload_len));
        if (ws_state_ != WsState::Open) return;  // protocol_error() was called

        size_t remaining = ws_recv_len_ - frame_len;
        if (remaining > 0) std::memmove(ws_recv_buf_, ws_recv_buf_ + frame_len, remaining);
        ws_recv_len_ = remaining;
      }
    }

    void handle_frame(uint8_t op, bool fin, const char* payload, size_t len)
    {
      switch (static_cast<WsOpcode>(op))
      {
        case WsOpcode::Text:
        case WsOpcode::Binary:
          if (!fin)
          {
            if (frag_len_ > 0)
            { protocol_error("[llnet::WsSocket] new fragment started while one is in progress"); return; }
            std::memcpy(frag_buf_, payload, len);
            frag_len_ = len;
            return;
          }
          if (frag_len_ > 0)
          { protocol_error("[llnet::WsSocket] complete frame received while fragment is in progress"); return; }
          emit_message(payload, len,
                       static_cast<size_t>((ws_recv_buf_ + kRecvCap + recv_padding_) - payload));
          break;

        case WsOpcode::Continuation:
          if (frag_len_ == 0)
          { protocol_error("[llnet::WsSocket] continuation frame without initial fragment"); return; }
          if (frag_len_ + len > kRecvCap)
          { protocol_error("[llnet::WsSocket] fragmented message exceeds kRecvCap"); return; }
          std::memcpy(frag_buf_ + frag_len_, payload, len);
          frag_len_ += len;
          if (fin)
          {
            std::memset(frag_buf_ + frag_len_, 0, recv_padding_);
            emit_message(frag_buf_, frag_len_, frag_len_ + recv_padding_);
            frag_len_ = 0;
          }
          break;

        case WsOpcode::Close:
          send_close();
          disconnect();  // resets ws_state_, fires on_disc_
          break;

        case WsOpcode::Ping:
          send_pong(payload, len);
          break;

        case WsOpcode::Pong:
          break;

        default:
          break;
      }
    }

    void emit_message(const char* payload, size_t len, size_t capacity)
    {
      if (on_message_) on_message_(tcp_recv_ns_, payload, len, capacity);
    }

    // ── frame building ────────────────────────────────────────────────────────

    // SplitMix64 — fast PRNG for frame masking keys.  Seeded from getrandom()
    // once at construction.  RFC 6455 masking prevents proxy cache poisoning;
    // TLS handles actual confidentiality, so a non-cryptographic PRNG is fine.
    static uint64_t splitmix64(uint64_t& state) noexcept
    {
      uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
      z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
      z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
      return z ^ (z >> 31);
    }

    size_t build_frame(uint8_t opcode, const char* payload, size_t payload_len)
    {
      if (payload_len + kMaxFrameOverhead > kSendCap) { log_("[llnet::WsSocket] frame too large"); return 0; }

      uint8_t* buf = reinterpret_cast<uint8_t*>(ws_send_buf_);
      size_t pos = 0;

      buf[pos++] = kFin | opcode;

      const uint32_t mask_key = static_cast<uint32_t>(splitmix64(mask_rng_state_));

      if (payload_len < kPayloadLen16)
      {
        buf[pos++] = kMask | static_cast<uint8_t>(payload_len);
      }
      else if (payload_len < kPayloadLen16Max)
      {
        buf[pos++] = kMask | kPayloadLen16;
        buf[pos++] = static_cast<uint8_t>(payload_len >> 8);
        buf[pos++] = static_cast<uint8_t>(payload_len);
      }
      else
      {
        buf[pos++] = kMask | kPayloadLen64;
        for (int i = 7; i >= 0; --i)
          buf[pos++] = static_cast<uint8_t>(payload_len >> (8 * i));
      }

      std::memcpy(buf + pos, &mask_key, kMaskKeySize);
      const uint8_t* mk = buf + pos;
      pos += kMaskKeySize;

      for (size_t i = 0; i < payload_len; ++i)
        buf[pos++] = static_cast<uint8_t>(payload[i]) ^ mk[i & 3];

      return pos;
    }

    void send_pong(const char* p, size_t n)
    {
      size_t f = build_frame(static_cast<uint8_t>(WsOpcode::Pong), p, n);
      if (f) (void)client_.send_raw({ws_send_buf_, f});
    }

    void send_close()
    {
      size_t f = build_frame(static_cast<uint8_t>(WsOpcode::Close), nullptr, 0);
      if (f) (void)client_.send_raw({ws_send_buf_, f});
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    bool verify_accept(const char* headers, size_t header_len)
    {
      static constexpr char guid[]       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      static constexpr char accept_key[] = "Sec-WebSocket-Accept";
      std::string input = ws_key_ + guid;

      uint8_t sha1_out[kSha1Len];
      SHA1(reinterpret_cast<const uint8_t*>(input.data()), input.size(), sha1_out);

      char expected[kWsKeyB64Len];
      base64_encode(sha1_out, kSha1Len, expected, sizeof(expected));
      const size_t exp_len = std::strlen(expected);

      const char* p       = headers;
      const char* end_hdr = headers + header_len;
      while (p < end_hdr)
      {
        const char* line_end = static_cast<const char*>(::memmem(p, end_hdr - p, "\r\n", 2));
        if (!line_end || line_end == p) break;

        const char* colon = static_cast<const char*>(std::memchr(p, ':', line_end - p));
        if (colon)
        {
          size_t name_len = static_cast<size_t>(colon - p);
          if (name_len == sizeof(accept_key) - 1)
          {
            bool match = true;
            for (size_t i = 0; i < name_len && match; ++i)
              match = (std::tolower(static_cast<unsigned char>(p[i])) ==
                       std::tolower(static_cast<unsigned char>(accept_key[i])));
            if (match)
            {
              const char* v = colon + 1;
              while (v < line_end && (*v == ' ' || *v == '\t')) ++v;
              const char* ve = line_end;
              while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) --ve;
              return static_cast<size_t>(ve - v) == exp_len && std::memcmp(v, expected, exp_len) == 0;
            }
          }
        }
        p = line_end + 2;
      }
      return false;
    }

    static void base64_encode(const uint8_t* in, size_t len, char* out, size_t out_cap)
    {
      static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      size_t pos = 0;
      for (size_t i = 0; i < len && pos + 4 < out_cap; i += 3)
      {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        if (i + 1 < len) v |= static_cast<uint32_t>(in[i + 1]) << 8;
        if (i + 2 < len) v |= static_cast<uint32_t>(in[i + 2]);
        out[pos++] = tbl[(v >> 18) & 0x3F];
        out[pos++] = tbl[(v >> 12) & 0x3F];
        out[pos++] = (i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=';
        out[pos++] = (i + 2 < len) ? tbl[v & 0x3F]        : '=';
      }
      out[pos] = '\0';
    }

    // ── members ───────────────────────────────────────────────────────────────

    TlsSocket   client_;
    LogFn       log_;
    size_t      recv_padding_ = 0;
    WsState     ws_state_     = WsState::Tcp;
    std::string host_;
    std::string path_;
    std::string ws_key_;

    char*    ws_recv_buf_ = nullptr;
    char*    ws_send_buf_ = nullptr;
    char*    frag_buf_    = nullptr;  // fixed reassembly buffer for fragmented messages
    size_t   ws_recv_len_ = 0;
    size_t   frag_len_    = 0;
    uint64_t tcp_recv_ns_ = 0;
    uint64_t mask_rng_state_ = 0;   // SplitMix64 state for frame masking

    ConnCb on_connect_;
    MsgCb  on_message_;
    DiscCb on_disc_;
  };

} // namespace llnet
