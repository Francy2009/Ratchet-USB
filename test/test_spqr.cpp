#include <string>

#include "ratchet/spqr.hpp"
#include "test_support.hpp"

using namespace ratchet;

TEST("Signal SPQR bridge agrees on keys in both directions") {
  SecureBytes<32> secret;
  for (std::size_t i = 0; i < secret.size(); ++i) secret[i] = 17;
  SecureBuffer alice = spqr::initialize(true, secret);
  SecureBuffer bob = spqr::initialize(false, secret);

  for (int turn = 0; turn < 8; ++turn) {
    SecureBuffer& sender = turn % 2 == 0 ? alice : bob;
    SecureBuffer& receiver = turn % 2 == 0 ? bob : alice;
    spqr::Sent sent = spqr::send(sender);
    CHECK(!sent.message.empty());
    spqr::Received received = spqr::receive(receiver, sent.message);
    CHECK(sent.key.equals(received.key));
    sender = std::move(sent.state);
    receiver = std::move(received.state);
  }
}

TEST("Signal SPQR bridge rejects malformed messages") {
  SecureBytes<32> secret;
  for (std::size_t i = 0; i < secret.size(); ++i) secret[i] = 23;
  SecureBuffer alice = spqr::initialize(true, secret);
  SecureBuffer bob = spqr::initialize(false, secret);
  spqr::Sent sent = spqr::send(alice);
  sent.message.clear();
  CHECK_THROWS(spqr::receive(bob, sent.message));
}
