// Live BBO test — connects to Binance and prints BTCUSDT best bid/ask updates.
//
// Uses the combined stream endpoint with an explicit SUBSCRIBE message so the
// send_text path is exercised as well as recv.
//
// Endpoint: wss://stream.binance.com:9443/stream
// Subscribe: {"method":"SUBSCRIBE","params":["btcusdt@bookTicker"],"id":1}
//
// Message format (wrapped by combined stream):
//   {"stream":"btcusdt@bookTicker","data":{"u":123,"s":"BTCUSDT",
//    "b":"95000.00","B":"0.5","a":"95001.00","A":"1.2"}}
//   b/B = best bid price/qty, a/A = best ask price/qty
//
// Zero-copy path: WsSocket is constructed with simdjson::SIMDJSON_PADDING extra
// bytes appended to its receive buffer.  For unfragmented frames the callback
// receives a pointer directly into that aligned buffer, so simdjson can parse
// in-place without any copy.
//
// Build: cmake -B build && cmake --build build
// Run:   ./build/llnet_live_binance_bbo_openssl
//        ./build/llnet_live_binance_bbo_wolfssl

#include <llnet/epoll_loop.h>
#include <llnet/ws_socket.h>

#include <simdjson.h>

#include <csignal>
#include <cstdio>
#include <cstring>

static volatile sig_atomic_t g_stop = 0;

int main()
{
  std::signal(SIGINT,  [](int){ g_stop = 1; });
  std::signal(SIGTERM, [](int){ g_stop = 1; });

  auto log = [](const char* msg){ std::fprintf(stderr, "[llnet] %s\n", msg); };

  llnet::EpollLoop loop(log);

  // Pass SIMDJSON_PADDING so the receive buffer has the required padding bytes
  // after the payload — simdjson's on-demand parser reads up to padding bytes
  // past the end of the document and will fault without them.
  llnet::WsSocket ws(simdjson::SIMDJSON_PADDING, log);

  ws.set_io_service(loop);

  ws.set_on_connect([&]{
    std::puts("connected — subscribing to btcusdt@bookTicker");
    static constexpr char sub[] =
        R"({"method":"SUBSCRIBE","params":["btcusdt@bookTicker"],"id":1})";
    if (!ws.send_text(sub, sizeof(sub) - 1))
      std::fputs("subscribe send failed\n", stderr);
  });

  simdjson::ondemand::parser parser;

  ws.set_on_message([&](uint64_t recv_ns, const char* data, size_t len, size_t capacity)
  {
    simdjson::padded_string_view psv(data, len, capacity);

    simdjson::ondemand::document doc;
    if (parser.iterate(psv).get(doc) != simdjson::SUCCESS) {
      std::fprintf(stderr, "json parse error (len=%zu)\n", len);
      return;
    }

    // The combined stream wraps each event: {"stream":"...","data":{...}}
    // Subscription ack has no "data" field — skip silently.
    simdjson::ondemand::object payload;
    if (doc["data"].get(payload) != simdjson::SUCCESS)
      return;

    std::string_view bid, ask;
    if (payload["b"].get(bid) != simdjson::SUCCESS ||
        payload["a"].get(ask) != simdjson::SUCCESS)
      return;

    std::printf("%llu µs  bid=%-14.*s ask=%.*s\n",
                static_cast<unsigned long long>(recv_ns / 1'000),
                static_cast<int>(bid.size()), bid.data(),
                static_cast<int>(ask.size()), ask.data());
  });

  ws.set_on_disconnect([]{
    std::puts("disconnected");
    g_stop = 1;
  });

  if (!ws.resolve("stream.binance.com", 9443, "/stream"))
  {
    std::fputs("resolve failed\n", stderr);
    return 1;
  }
  if (!ws.connect())
  {
    std::fputs("connect failed\n", stderr);
    return 1;
  }

  while (!g_stop)
    loop.poll();

  return 0;
}
