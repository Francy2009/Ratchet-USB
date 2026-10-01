#include "ratchet/triple_ratchet.hpp"
#include "test_support.hpp"

using namespace ratchet;

TEST("Triple Ratchet initial split is deterministic and domain-separated") {
  SecureBytes<32> input;
  for (std::size_t i = 0; i < input.size(); ++i) input[i] = static_cast<uint8_t>(i);
  SecureBytes<32> ec1, pq1, ec2, pq2;
  triple_ratchet::split_initial_secret(input, ec1, pq1);
  triple_ratchet::split_initial_secret(input, ec2, pq2);
  CHECK(ec1.equals(ec2));
  CHECK(pq1.equals(pq2));
  CHECK(!ec1.equals(pq1));
}

TEST("Triple Ratchet hybrid key depends on both cryptographic families") {
  SecureBytes<32> ec;
  SecureBytes<32> pq;
  ec[0] = 1;
  pq[0] = 2;
  SecureBytes<32> baseline, changed_ec, changed_pq;
  triple_ratchet::combine_message_keys(ec, pq, baseline);
  ec[1] = 3;
  triple_ratchet::combine_message_keys(ec, pq, changed_ec);
  ec[1] = 0;
  pq[1] = 4;
  triple_ratchet::combine_message_keys(ec, pq, changed_pq);
  CHECK(!baseline.equals(changed_ec));
  CHECK(!baseline.equals(changed_pq));
  CHECK(!changed_ec.equals(changed_pq));
}
