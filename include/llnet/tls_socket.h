#pragma once

// POSIX headers before wolfSSL to avoid macro conflicts
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef USE_WOLFSSL
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#else
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#include <llnet/detail/inplace_function.h>
#include <llnet/epoll_loop.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace llnet
{

  // TlsSocket — non-blocking TCP + TLS client stream.
  //
  // I/O events dispatched by EpollLoop. WsSocket sits on top.
  //
  // Errors are reported by returning false / calling on_disconnect,
  // and optionally via the LogFn passed at construction.

  class TlsSocket
  {
   public:
    static constexpr size_t kRecvCap = 256 * 1024;
    static constexpr size_t kSendCap = 64  * 1024;
    static constexpr size_t kRawCap  = 64  * 1024;

    using ConnCb = detail::inplace_function<void(),                      32>;
    using DataCb = detail::inplace_function<void(const char*, size_t),   32>;
    using DiscCb = detail::inplace_function<void(),                      32>;

    explicit TlsSocket(LogFn log = noop_log) noexcept : log_{log}
    {
      recv_buf_ = static_cast<char*>(std::aligned_alloc(64, kRecvCap));
      send_buf_ = static_cast<char*>(std::aligned_alloc(64, kSendCap));
      raw_buf_  = static_cast<char*>(std::aligned_alloc(64, kRawCap));
      SSL_library_init();
      ssl_ctx_ = SSL_CTX_new(SSLv23_client_method());
#ifdef USE_WOLFSSL
      if (ssl_ctx_)
      {
        wolfSSL_CTX_SetMinRsaKey_Sz(ssl_ctx_, 0);
        wolfSSL_CTX_SetMinEccKey_Sz(ssl_ctx_, 0);
      }
#endif
    }

    ~TlsSocket()
    {
      cleanup_conn();
      if (ssl_ctx_)
      {
        SSL_CTX_free(ssl_ctx_);
      }
      std::free(recv_buf_);
      std::free(send_buf_);
      std::free(raw_buf_);
    }

    TlsSocket(const TlsSocket&)            = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;
    TlsSocket(TlsSocket&&)                 = delete;
    TlsSocket& operator=(TlsSocket&&)      = delete;

    void set_io_service(EpollLoop& svc)  noexcept { io_svc_ = &svc; }
    void set_on_connect(ConnCb cb)              { on_connect_ = std::move(cb); }
    void set_on_data(DataCb cb)                 { on_data_    = std::move(cb); }
    void set_on_disconnect(DiscCb cb)           { on_disc_    = std::move(cb); }
    void set_verify_peer(bool enabled) noexcept { verify_peer_ = enabled; }

    [[nodiscard]] bool set_ca_file(const char* path)
    {
      if (!path || !*path) return false;
      ca_file_ = path;
      return true;
    }

    [[nodiscard]] bool set_min_rsa_key_bits(uint16_t bits)
    {
#ifdef USE_WOLFSSL
      if (!ssl_ctx_ || bits == 0) return false;
      return wolfSSL_CTX_SetMinRsaKey_Sz(ssl_ctx_, static_cast<short>(bits)) == WOLFSSL_SUCCESS;
#else
      (void)bits; return false;
#endif
    }

    [[nodiscard]] bool set_min_ecc_key_bits(uint16_t bits)
    {
#ifdef USE_WOLFSSL
      if (!ssl_ctx_ || bits == 0) return false;
      return wolfSSL_CTX_SetMinEccKey_Sz(ssl_ctx_, static_cast<short>(bits)) == WOLFSSL_SUCCESS;
#else
      (void)bits; return false;
#endif
    }

    const std::string& host() const noexcept { return host_; }

    // Blocking DNS resolution — call once during init.
    [[nodiscard]] bool resolve(const char* host, uint16_t port)
    {
      host_ = host;
      port_ = port;

      addrinfo hints{}, *res = nullptr;
      hints.ai_family   = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      char portstr[8];
      std::snprintf(portstr, sizeof(portstr), "%u", port);

      if (::getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
      {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "[llnet::TlsSocket] DNS failed for %s", host);
        log_(buf);
        return false;
      }
      std::memcpy(&peer_addr_, res->ai_addr, res->ai_addrlen);
      peer_addr_len_ = static_cast<socklen_t>(res->ai_addrlen);
      ::freeaddrinfo(res);
      return true;
    }

    // Non-blocking connect using pre-resolved address.
    [[nodiscard]] bool connect()
    {
      if (peer_addr_len_ == 0) { log_("[llnet::TlsSocket] connect() before resolve()"); return false; }
      if (!io_svc_)            { log_("[llnet::TlsSocket] connect() before set_io_service()"); return false; }
      ensure_cas_loaded();
      cleanup_conn();

      sockfd_ = ::socket(reinterpret_cast<const sockaddr*>(&peer_addr_)->sa_family,
                         SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (sockfd_ < 0) return false;

      int yes = 1;
      ::setsockopt(sockfd_, IPPROTO_TCP, TCP_NODELAY,   &yes, sizeof(yes));
      ::setsockopt(sockfd_, SOL_SOCKET,  SO_KEEPALIVE,  &yes, sizeof(yes));

      io_svc_->register_fd(sockfd_, EPOLLOUT | EPOLLIN | EPOLLET | EPOLLRDHUP,
                           [this](uint32_t e) { on_fd_events(e); });

      ::connect(sockfd_, reinterpret_cast<const sockaddr*>(&peer_addr_), peer_addr_len_);
      state_ = State::Connecting;
      return true;
    }

    void disconnect() noexcept { cleanup_conn(); }
    [[nodiscard]] bool is_connected() const noexcept { return state_ == State::Connected; }

    [[nodiscard]] bool send_raw(std::span<const char> data)
    {
      if (state_ != State::Connected) return false;
      if (plain_buf_.size() - plain_off_ + data.size() > kRecvCap)
      {
        log_("[llnet::TlsSocket] plaintext send queue overflow");
        return false;
      }
      if (plain_off_ == plain_buf_.size()) { plain_buf_.clear(); plain_off_ = 0; }
      plain_buf_.insert(plain_buf_.end(), data.begin(), data.end());
      if (!flush_plain_send()) return false;
      if (state_ != State::Connected) return false;
      flush_send();
      return true;
    }

   private:
    enum class State : uint8_t { Disconnected, Connecting, TlsHandshake, Connected };
    enum class TlsWriteResult : uint8_t { Ok, Want, Error };

    // ── fd events ────────────────────────────────────────────────────────────

    void on_fd_events(uint32_t e) noexcept
    {
      if (e & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { on_sock_error(); return; }
      switch (state_)
      {
        case State::Connecting:
          if (e & EPOLLOUT) check_connect();
          break;
        case State::TlsHandshake:
          if (e & (EPOLLIN | EPOLLOUT)) do_tls_handshake();
          break;
        case State::Connected:
          if (e & EPOLLIN)
          {
            recv_decrypted();
            if (state_ != State::Connected) return;
          }
          if (e & EPOLLOUT)
          {
            if (!flush_plain_send()) return;
            if (state_ != State::Connected) return;
            flush_send();
          }
          break;
        default: break;
      }
    }

    // ── cleanup ───────────────────────────────────────────────────────────────

    void cleanup_conn()
    {
      if (ssl_)
      {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_  = nullptr;
        bio_r_ = nullptr;
        bio_w_ = nullptr;
      }
      if (sockfd_ >= 0)
      {
        if (io_svc_) io_svc_->unregister_fd(sockfd_);
        ::close(sockfd_);
        sockfd_ = -1;
      }
      state_    = State::Disconnected;
      recv_len_ = send_len_ = send_off_ = raw_len_ = 0;
      plain_buf_.clear();
      plain_off_ = 0;
    }

    void on_sock_error()
    {
      int err = 0; socklen_t l = sizeof(err);
      ::getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &err, &l);
      cleanup_conn();
      if (on_disc_) on_disc_();
    }

    // ── TLS ──────────────────────────────────────────────────────────────────

#ifdef USE_WOLFSSL
    static int cross_cert_cb(int preverify_ok, WOLFSSL_X509_STORE_CTX* store)
    {
      if (preverify_ok) return 1;
      const int err   = wolfSSL_X509_STORE_CTX_get_error(store);
      const int depth = wolfSSL_X509_STORE_CTX_get_error_depth(store);
      if (depth > 0 && (err == X509_V_ERR_INVALID_CA ||
                        err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
                        err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                        err == ASN_NO_SIGNER_E))
        return 1;
      return 0;
    }
#endif

    void ensure_cas_loaded()
    {
      if (cas_loaded_) return;
      cas_loaded_ = true;

      bool loaded = false;
      if (!ca_file_.empty())
      {
        loaded = SSL_CTX_load_verify_locations(ssl_ctx_, ca_file_.c_str(), nullptr) == 1;
      }
      else
      {
        loaded = SSL_CTX_set_default_verify_paths(ssl_ctx_) == 1;
#ifdef USE_WOLFSSL
        if (!loaded) loaded = wolfSSL_CTX_load_system_CA_certs(ssl_ctx_) == 1;
#endif
        if (!loaded)
        {
          static constexpr std::array<const char*, 4> kBundles{
              "/etc/ssl/certs/ca-certificates.crt",
              "/etc/pki/tls/certs/ca-bundle.crt",
              "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
              "/etc/ssl/cert.pem",
          };
          for (const char* p : kBundles)
          {
            if (SSL_CTX_load_verify_locations(ssl_ctx_, p, nullptr) == 1) { loaded = true; break; }
          }
        }
      }

      if (verify_peer_)
      {
#ifdef USE_WOLFSSL
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, cross_cert_cb);
#else
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
#endif
      }
      else
      {
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
      }
      (void)loaded;
    }

    bool setup_tls()
    {
      ssl_  = SSL_new(ssl_ctx_);
      bio_r_ = BIO_new(BIO_s_mem());
      bio_w_ = BIO_new(BIO_s_mem());
      if (!ssl_ || !bio_r_ || !bio_w_) return false;
      SSL_set_bio(ssl_, bio_r_, bio_w_);
      SSL_set_connect_state(ssl_);
      SSL_set_tlsext_host_name(ssl_, host_.c_str());
      if (verify_peer_) SSL_set1_host(ssl_, host_.c_str());
      return true;
    }

    void pump_tls()
    {
      if (raw_len_ > 0)
      {
        int w = BIO_write(bio_r_, raw_buf_, static_cast<int>(raw_len_));
        if (w > 0) { raw_len_ -= w; if (raw_len_) std::memmove(raw_buf_, raw_buf_ + w, raw_len_); }
      }
      char tmp[16384];
      int p;
      while ((p = BIO_pending(bio_w_)) > 0 && send_len_ < kSendCap)
      {
        int r = BIO_read(bio_w_, tmp, std::min<int>(p, std::min<int>((int)sizeof(tmp), (int)(kSendCap - send_len_))));
        if (r > 0) { std::memcpy(send_buf_ + send_len_, tmp, r); send_len_ += r; }
      }
    }

    TlsWriteResult tls_write_some(const char* data, size_t len, size_t& written)
    {
      written = 0;
      int r = SSL_write(ssl_, data, static_cast<int>(len));
      if (r > 0) { written = static_cast<size_t>(r); pump_tls(); return TlsWriteResult::Ok; }
      int e = SSL_get_error(ssl_, r);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) { pump_tls(); return TlsWriteResult::Want; }
      on_sock_error();
      return TlsWriteResult::Error;
    }

    bool flush_plain_send()
    {
      while (plain_off_ < plain_buf_.size())
      {
        size_t wrote = 0;
        auto result = tls_write_some(plain_buf_.data() + plain_off_, plain_buf_.size() - plain_off_, wrote);
        plain_off_ += wrote;
        if (result == TlsWriteResult::Error) return false;
        if (result == TlsWriteResult::Want)  break;
      }
      if (plain_off_ == plain_buf_.size()) { plain_buf_.clear(); plain_off_ = 0; }
      return true;
    }

    // ── I/O ──────────────────────────────────────────────────────────────────

    void recv_raw()
    {
      while (raw_len_ < kRawCap)
      {
        ssize_t n = ::recv(sockfd_, raw_buf_ + raw_len_, kRawCap - raw_len_, 0);
        if (n > 0)      { raw_len_ += n; }
        else if (n == 0){ cleanup_conn(); if (on_disc_) on_disc_(); return; }
        else             break;
      }
    }

    void flush_send()
    {
      while (send_off_ < send_len_)
      {
        ssize_t n = ::send(sockfd_, send_buf_ + send_off_, send_len_ - send_off_, MSG_NOSIGNAL);
        if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          on_sock_error();
          return;
        }
        send_off_ += n;
      }
      if (send_off_ == send_len_) { send_len_ = send_off_ = 0; }
      else if (send_off_ > 0)
      {
        std::memmove(send_buf_, send_buf_ + send_off_, send_len_ - send_off_);
        send_len_ -= send_off_;
        send_off_  = 0;
      }
    }

    void recv_decrypted()
    {
      recv_raw();
      if (state_ != State::Connected) return;
      pump_tls();
      while (recv_len_ < kRecvCap)
      {
        int r = SSL_read(ssl_, recv_buf_ + recv_len_, static_cast<int>(kRecvCap - recv_len_));
        if (r <= 0) break;
        recv_len_ += r;
      }
      pump_tls();
      if (!flush_plain_send()) return;
      if (state_ != State::Connected) return;
      flush_send();
      if (recv_len_ > 0 && on_data_)
      {
        on_data_(recv_buf_, recv_len_);
        recv_len_ = 0;
      }
    }

    // ── state machine ─────────────────────────────────────────────────────────

    void check_connect()
    {
      int err = 0; socklen_t l = sizeof(err);
      ::getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &err, &l);
      if (err == EINPROGRESS || err == EALREADY) return;
      if (err != 0)
      {
        cleanup_conn();
        if (on_disc_) on_disc_();
        return;
      }
      if (!setup_tls())
      {
        log_("[llnet::TlsSocket] TLS setup failed");
        cleanup_conn();
        if (on_disc_) on_disc_();
        return;
      }
      state_ = State::TlsHandshake;
      do_tls_handshake();
    }

    void do_tls_handshake()
    {
      recv_raw();
      pump_tls();
      int r = SSL_do_handshake(ssl_);
      pump_tls();
      flush_send();
      if (r == 1)
      {
        state_ = State::Connected;
        if (on_connect_) on_connect_();
      }
      else
      {
        int e = SSL_get_error(ssl_, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
        {
          cleanup_conn();
          if (on_disc_) on_disc_();
        }
      }
    }

    // ── members ───────────────────────────────────────────────────────────────

    LogFn       log_;
    EpollLoop*  io_svc_  = nullptr;
    State       state_   = State::Disconnected;
    int         sockfd_  = -1;
    SSL_CTX*    ssl_ctx_ = nullptr;
    SSL*        ssl_     = nullptr;
    BIO*        bio_r_   = nullptr;
    BIO*        bio_w_   = nullptr;
    std::string host_;
    uint16_t    port_{};
    sockaddr_storage peer_addr_{};
    socklen_t        peer_addr_len_{};

    char*  recv_buf_ = nullptr;
    char*  send_buf_ = nullptr;
    char*  raw_buf_  = nullptr;
    size_t recv_len_ = 0, send_len_ = 0, send_off_ = 0, raw_len_ = 0;
    std::vector<char> plain_buf_;
    size_t plain_off_ = 0;

    ConnCb on_connect_;
    DataCb on_data_;
    DiscCb on_disc_;

    bool verify_peer_ = true;
    bool cas_loaded_  = false;
    std::string ca_file_;
  };

} // namespace llnet
