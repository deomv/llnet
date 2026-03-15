#pragma once

#include <llnet/detail/inplace_function.h>

#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace llnet
{

  // LogFn — optional error sink injected at construction.
  // Called only on unrecoverable errors (epoll_ctl failure etc.).
  // Default: no-op.
  using LogFn = void(*)(const char* msg);
  inline void noop_log(const char*) noexcept {}

  // EpollLoop — central epoll fd-event dispatcher.
  //
  // Register fds with register_fd(); their callbacks fire from poll().
  // Timers live in llnet::Timer — construct one per timer and pass *this.
  //
  // Not thread-safe: all calls must come from the same thread.

  class EpollLoop
  {
   public:
    using FdCb = detail::inplace_function<void(uint32_t events), 64>;

    explicit EpollLoop(LogFn log = noop_log) noexcept : log_{log}
    {
      epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
      if (epoll_fd_ < 0)
      {
        log_("[llnet::EpollLoop] epoll_create1 failed");
      }
    }

    ~EpollLoop()
    {
      if (epoll_fd_ >= 0)
      {
        ::close(epoll_fd_);
      }
    }

    EpollLoop(const EpollLoop&)            = delete;
    EpollLoop& operator=(const EpollLoop&) = delete;
    EpollLoop(EpollLoop&&)                 = delete;
    EpollLoop& operator=(EpollLoop&&)      = delete;

    void register_fd(int fd, uint32_t events, FdCb cb)
    {
      if (epoll_fd_ < 0) return;
      fd_handlers_[fd] = std::move(cb);
      epoll_event ev{events, {.fd = fd}};
      if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0)
      {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "[llnet::EpollLoop] epoll_ctl ADD fd=%d: %s", fd, strerror(errno));
        log_(buf);
      }
    }

    void unregister_fd(int fd)
    {
      if (epoll_fd_ < 0) { fd_handlers_.erase(fd); return; }
      if (::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) < 0)
      {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "[llnet::EpollLoop] epoll_ctl DEL fd=%d: %s", fd, strerror(errno));
        log_(buf);
      }
      fd_handlers_.erase(fd);
    }

    // Dispatch pending I/O events — call in a tight loop on the event thread.
    void poll()
    {
      if (epoll_fd_ < 0)
      {
        return;
      }
      epoll_event evs[16];
      const int n = ::epoll_wait(epoll_fd_, evs, 16, 0);
      for (int i = 0; i < n; ++i)
      {
        const int fd = evs[i].data.fd;
        // Copy before calling — callback may call unregister_fd().
        auto it = fd_handlers_.find(fd);
        if (it != fd_handlers_.end())
        {
          auto cb = it->second;
          cb(evs[i].events);
        }
      }
    }

    int fd() const noexcept { return epoll_fd_; }

   private:
    int    epoll_fd_ = -1;
    LogFn  log_;
    std::unordered_map<int, FdCb> fd_handlers_;
  };

} // namespace llnet
