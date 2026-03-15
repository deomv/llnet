#pragma once

#include <llnet/detail/inplace_function.h>
#include <llnet/epoll_loop.h>

#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include <cstdint>

namespace llnet
{

  // Timer — periodic or one-shot timerfd, dispatched via EpollLoop.
  //
  // Usage:
  //   llnet::Timer t(loop);
  //   t.set_periodic(1'000'000'000, [](uint64_t now_ns){ ... });  // 1s
  //
  // The callback receives the current CLOCK_REALTIME timestamp in nanoseconds.
  // Cancel by calling cancel() or destroying the Timer.

  class Timer
  {
   public:
    using Cb = detail::inplace_function<void(uint64_t now_ns), 48>;

    explicit Timer(EpollLoop& loop, LogFn log = noop_log) noexcept
      : loop_{loop}, log_{log}
    {}

    ~Timer() { cancel(); }

    Timer(const Timer&)            = delete;
    Timer& operator=(const Timer&) = delete;
    Timer(Timer&&)                 = delete;
    Timer& operator=(Timer&&)      = delete;

    // Set a periodic timer firing every period_ns nanoseconds.
    // Replaces any existing timer on this object.
    void set_periodic(int64_t period_ns, Cb cb)
    {
      cancel();

      timer_fd_ = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
      if (timer_fd_ < 0)
      {
        log_("[llnet::Timer] timerfd_create failed");
        return;
      }

      itimerspec its{};
      its.it_value    = {period_ns / 1'000'000'000LL, period_ns % 1'000'000'000LL};
      its.it_interval = its.it_value;
      ::timerfd_settime(timer_fd_, 0, &its, nullptr);

      cb_ = std::move(cb);
      loop_.register_fd(timer_fd_, EPOLLIN, [this](uint32_t) { on_fd_event(); });
    }

    void cancel()
    {
      if (timer_fd_ >= 0)
      {
        loop_.unregister_fd(timer_fd_);
        ::close(timer_fd_);
        timer_fd_ = -1;
        cb_ = nullptr;
      }
    }

   private:
    void on_fd_event()
    {
      uint64_t expirations = 0;
      (void)::read(timer_fd_, &expirations, sizeof(expirations));
      if (cb_)
      {
        timespec ts{};
        ::clock_gettime(CLOCK_REALTIME, &ts);
        const uint64_t now_ns =
            static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts.tv_nsec);
        cb_(now_ns);
      }
    }

    EpollLoop& loop_;
    LogFn      log_;
    int        timer_fd_ = -1;
    Cb         cb_;
  };

} // namespace llnet
