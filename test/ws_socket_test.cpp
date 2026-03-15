#include <cstdint>
#include <string>

#define private public
#include <llnet/ws_socket.h>
#undef private

#include <gtest/gtest.h>

using namespace llnet;

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
