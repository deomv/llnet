# llnet

Low-latency, header-only C++ networking library for Linux.

Provides non-blocking epoll I/O, TLS, and WebSocket framing with zero heap allocation on the hot path.

**Requires C++23 and Linux.**

## Components

| Header | Class | Description |
|---|---|---|
| `llnet/epoll_loop.h` | `EpollLoop` | Central epoll dispatcher |
| `llnet/timer.h` | `Timer` | Periodic/one-shot timerfd |
| `llnet/tls_socket.h` | `TlsSocket` | Non-blocking TCP + TLS client |
| `llnet/ws_socket.h` | `WsSocket` | WebSocket (RFC 6455) over TLS |

## Dependencies

| Dependency | Role |
|---|---|
| wolfSSL (or OpenSSL) | TLS |
| Linux kernel ≥ 3.9 | `epoll`, `timerfd`, `getrandom` |

When used as a CMake subdirectory the parent must provide a `wolfssl` target.
When built standalone (e.g. for tests) the `CMakeLists.txt` falls back to system OpenSSL.

## CMake integration

```cmake
# In your CMakeLists.txt — wolfssl target must exist before this line
add_subdirectory(third_party/llnet)
target_link_libraries(my_target PRIVATE llnet)
```

Or as a git submodule:

```bash
git submodule add https://github.com/deomv/llnet third_party/llnet
git submodule update --init
```

## Quick start

```cpp
#include <llnet/ws_socket.h>

llnet::EpollLoop loop;
llnet::WsSocket  ws;

ws.set_io_service(loop);
ws.set_on_connect([&]{
    const char* sub = R"({"type":"subscribe","channels":["ticker"]})";
    ws.send_text(sub, std::strlen(sub));
});
ws.set_on_message([](uint64_t recv_ns, const char* data, size_t len, size_t /*cap*/){
    // data[0..len-1] is the complete message
});

ws.resolve("ws-feed.exchange.coinbase.com", 443, "/");
ws.connect();

while (true)
    loop.poll();   // call in a tight loop on the event thread
```

## Aligned receive buffer and zero-copy parsing

`WsSocket` allocates its receive buffer with `std::aligned_alloc(64, kRecvCap + recv_padding)`.

The `MsgCb` callback receives a `capacity` argument equal to the number of readable bytes from
`data` to the end of the buffer. When `recv_padding > 0`, `capacity >= len + recv_padding`, which
lets an in-place parser read up to `recv_padding` bytes past `len` without a separate allocation or
copy.

Pass your parser's required padding at construction:

```cpp
// simdjson requires SIMDJSON_PADDING readable bytes after the last byte
#include <simdjson.h>
llnet::WsSocket ws{simdjson::SIMDJSON_PADDING};

ws.set_on_message([](uint64_t, const char* data, size_t len, size_t cap){
    simdjson::padded_string_view psv{data, len, cap};
    auto doc = parser.iterate(psv);   // zero-copy, no extra allocation
});
```

Fragmented WebSocket messages are reassembled into a `std::vector<char>` that is also padded to
`recv_padding` bytes, so the same zero-copy path works regardless of fragmentation.

## Logging

All classes accept an optional `LogFn` (a plain `void(*)(const char*)` function pointer).
The default is a no-op. Pass your own sink to surface connection errors:

```cpp
auto my_log = [](const char* msg){ std::fputs(msg, stderr); std::fputc('\n', stderr); };
llnet::WsSocket ws{0, my_log};
```

`LogFn` is called only on unrecoverable errors (epoll failures, TLS setup errors, buffer overflows).
It is never called on the hot receive path.

## Periodic timer

```cpp
llnet::EpollLoop loop;
llnet::Timer     heartbeat{loop};

heartbeat.set_periodic(30'000'000'000LL, [](uint64_t now_ns){
    // fires every 30 seconds; now_ns is CLOCK_REALTIME in nanoseconds
});

while (true)
    loop.poll();
```

## Thread safety

All classes are **single-threaded**. All calls — `poll()`, callbacks, `send_text()` — must come
from the same thread.

## Buffer sizes

| Constant | Value | Location |
|---|---|---|
| `TlsSocket::kRecvCap` | 256 KiB | plaintext receive ring |
| `TlsSocket::kSendCap` | 64 KiB | plaintext send queue |
| `TlsSocket::kRawCap` | 64 KiB | raw (pre-TLS) receive ring |
| `WsSocket::kRecvCap` | 256 KiB | WebSocket frame buffer |
| `WsSocket::kSendCap` | 64 KiB | WebSocket send buffer |

All buffers are cache-line aligned (64 bytes).
