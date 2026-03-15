#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#define private public
#include <llnet/ws_socket.h>
#undef private

#include <gtest/gtest.h>

using namespace llnet;

// ── test helpers ──────────────────────────────────────────────────────────────

// Write an unmasked WebSocket frame into ws.ws_recv_buf_ and advance ws_recv_len_.
// Payload must be < 126 bytes (single-byte length field).
static void enqueue_frame(WsSocket& ws, uint8_t opcode, bool fin,
                           const char* payload = nullptr, size_t len = 0)
{
  auto* p = reinterpret_cast<uint8_t*>(ws.ws_recv_buf_) + ws.ws_recv_len_;
  p[0] = (fin ? 0x80u : 0x00u) | (opcode & 0x0Fu);
  p[1] = static_cast<uint8_t>(len);
  if (payload && len) std::memcpy(p + 2, payload, len);
  ws.ws_recv_len_ += 2 + len;
}

// ── handle_frame: single frames ───────────────────────────────────────────────

TEST(WsSocket, ReassemblesFragmentedTextFramesBeforeDispatch)
{
  WsSocket ws;
  int calls = 0;
  std::string message;
  ws.set_on_message([&](uint64_t, const char* data, size_t len, size_t) {
    ++calls;
    message.assign(data, len);
  });

  ws.handle_frame(0x1, false, "{\"type\":\"ti", 11);
  EXPECT_EQ(calls, 0);

  ws.handle_frame(0x0, false, "cker\",\"price\":", 14);
  EXPECT_EQ(calls, 0);

  ws.handle_frame(0x0, true, "\"100\"}", 6);
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(message, "{\"type\":\"ticker\",\"price\":\"100\"}");
}

TEST(WsSocket, SingleTextFrameFiresCallback)
{
  WsSocket ws;
  int calls = 0;
  std::string msg;
  ws.set_on_message([&](uint64_t, const char* d, size_t n, size_t) {
    ++calls;
    msg.assign(d, n);
  });

  ws.handle_frame(0x1, true, "hello", 5);
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(msg, "hello");
}

TEST(WsSocket, BinaryFrameFiresCallback)
{
  WsSocket ws;
  int calls = 0;
  size_t received_len = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t n, size_t) {
    ++calls;
    received_len = n;
  });

  ws.handle_frame(0x2, true, "\x01\x02\x03\x04", 4);
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(received_len, 4u);
}

TEST(WsSocket, FragmentedBinaryReassembled)
{
  WsSocket ws;
  int calls = 0;
  std::string msg;
  ws.set_on_message([&](uint64_t, const char* d, size_t n, size_t) {
    ++calls;
    msg.assign(d, n);
  });

  ws.handle_frame(0x2, false, "bin", 3);
  EXPECT_EQ(calls, 0);
  ws.handle_frame(0x0, false, "a",   1);
  EXPECT_EQ(calls, 0);
  ws.handle_frame(0x0, true,  "ry",  2);
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(msg, "binary");
}

TEST(WsSocket, PingDoesNotFireMessageCallback)
{
  WsSocket ws;
  int calls = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t, size_t) { ++calls; });

  ws.handle_frame(0x9, true, "", 0);
  EXPECT_EQ(calls, 0);
}

TEST(WsSocket, PeerCloseFrameFiresDiscCallbackAndResetsState)
{
  WsSocket ws;
  int disc_calls = 0;
  ws.set_on_disconnect([&]{ ++disc_calls; });

  ws.handle_frame(0x8, true, "", 0);  // peer-initiated Close

  EXPECT_EQ(disc_calls, 1);
  EXPECT_FALSE(ws.is_connected());
}

TEST(WsSocket, ExplicitDisconnectFiresDiscCallbackAndResetsState)
{
  WsSocket ws;
  // Fake the socket into Open state so disconnect() has something to do.
  ws.ws_state_ = WsSocket::WsState::Open;

  int disc_calls = 0;
  ws.set_on_disconnect([&]{ ++disc_calls; });

  ws.disconnect();

  EXPECT_EQ(disc_calls, 1);
  EXPECT_FALSE(ws.is_connected());
}

// ── handle_frame: protocol errors ─────────────────────────────────────────────

TEST(WsSocket, ContinuationWithoutStartIsProtocolError)
{
  WsSocket ws;
  int calls = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t, size_t) { ++calls; });

  ws.handle_frame(0x0, true, "orphan", 6);  // continuation with no prior fragment
  EXPECT_EQ(calls, 0);
  EXPECT_EQ(ws.frag_len_, 0u);
  EXPECT_FALSE(ws.is_connected());  // protocol_error() must set state to Closed
}

TEST(WsSocket, NewFragmentWhileOneInProgressIsProtocolError)
{
  WsSocket ws;
  int calls = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t, size_t) { ++calls; });

  ws.handle_frame(0x1, false, "start", 5);  // begin fragment
  EXPECT_EQ(ws.frag_len_, 5u);

  ws.handle_frame(0x1, false, "again", 5);  // another start — protocol error
  EXPECT_EQ(calls, 0);
  EXPECT_FALSE(ws.is_connected());
}

TEST(WsSocket, CompleteFrameWhileFragmentInProgressIsProtocolError)
{
  WsSocket ws;
  int calls = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t, size_t) { ++calls; });

  ws.handle_frame(0x1, false, "start",    5);
  ws.handle_frame(0x1, true,  "complete", 8);  // complete frame mid-fragment — protocol error
  EXPECT_EQ(calls, 0);
  EXPECT_FALSE(ws.is_connected());
}

// ── dispatch_frames: full frame-parsing path ──────────────────────────────────

TEST(WsSocket, DispatchSingleFrame)
{
  WsSocket ws;
  ws.ws_state_ = WsSocket::WsState::Open;

  std::string msg;
  ws.set_on_message([&](uint64_t, const char* d, size_t n, size_t) { msg.assign(d, n); });

  enqueue_frame(ws, 0x1, true, "world", 5);
  ws.dispatch_frames();

  EXPECT_EQ(msg, "world");
  EXPECT_EQ(ws.ws_recv_len_, 0u);  // buffer fully consumed
}

TEST(WsSocket, DispatchMultipleFramesInOrder)
{
  WsSocket ws;
  ws.ws_state_ = WsSocket::WsState::Open;

  std::vector<std::string> msgs;
  ws.set_on_message([&](uint64_t, const char* d, size_t n, size_t) {
    msgs.emplace_back(d, n);
  });

  enqueue_frame(ws, 0x1, true, "alpha", 5);
  enqueue_frame(ws, 0x1, true, "beta",  4);
  enqueue_frame(ws, 0x1, true, "gamma", 5);
  ws.dispatch_frames();

  ASSERT_EQ(msgs.size(), 3u);
  EXPECT_EQ(msgs[0], "alpha");
  EXPECT_EQ(msgs[1], "beta");
  EXPECT_EQ(msgs[2], "gamma");
  EXPECT_EQ(ws.ws_recv_len_, 0u);
}

TEST(WsSocket, PartialFrameWaitsForMoreData)
{
  WsSocket ws;
  ws.ws_state_ = WsSocket::WsState::Open;

  int calls = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t, size_t) { ++calls; });

  // Header claims 10-byte payload but we only provide the header.
  auto* buf = reinterpret_cast<uint8_t*>(ws.ws_recv_buf_);
  buf[0] = 0x81;  // FIN + text
  buf[1] = 10;    // 10-byte payload (not present yet)
  ws.ws_recv_len_ = 2;

  ws.dispatch_frames();

  EXPECT_EQ(calls, 0);            // not dispatched yet
  EXPECT_EQ(ws.ws_recv_len_, 2u); // header preserved for next recv
}

TEST(WsSocket, RecvTimestampPassedToCallback)
{
  WsSocket ws;
  ws.ws_state_    = WsSocket::WsState::Open;
  ws.tcp_recv_ns_ = 999'000'000'000ULL;

  uint64_t received_ts = 0;
  ws.set_on_message([&](uint64_t ts, const char*, size_t, size_t) { received_ts = ts; });

  enqueue_frame(ws, 0x1, true, "x", 1);
  ws.dispatch_frames();

  EXPECT_EQ(received_ts, 999'000'000'000ULL);
}

TEST(WsSocket, RecvPaddingReportedInCapacityForDirectFrame)
{
  constexpr size_t kPad = 64;
  WsSocket ws(kPad);
  ws.ws_state_ = WsSocket::WsState::Open;

  size_t cap = 0;
  ws.set_on_message([&](uint64_t, const char*, size_t, size_t c) { cap = c; });

  enqueue_frame(ws, 0x1, true, "hi", 2);
  ws.dispatch_frames();

  // payload at ws_recv_buf_+2; capacity = kRecvCap + kPad - 2
  EXPECT_EQ(cap, WsSocket::kRecvCap + kPad - 2);
}

TEST(WsSocket, RecvPaddingReportedInCapacityForFragmentedMessage)
{
  constexpr size_t kPad = 32;
  WsSocket ws(kPad);

  size_t cap = 0;
  std::string msg;
  ws.set_on_message([&](uint64_t, const char* d, size_t n, size_t c) {
    msg.assign(d, n);
    cap = c;
  });

  ws.handle_frame(0x1, false, "hello", 5);
  ws.handle_frame(0x0, true,  " world", 6);

  EXPECT_EQ(msg, "hello world");
  EXPECT_EQ(cap, 11u + kPad);
}
