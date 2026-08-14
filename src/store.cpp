#include "ratchet/store.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>

#include "ratchet/serial.hpp"

namespace ratchet::store {
namespace {

constexpr std::array<uint8_t, 4> kStoreMagic = {'R', 'S', 'T', 'R'};
// Version 1 had no `created_at` on the signed prekey; version 2 added it so
// `unlock` can tell how old the current one is. Version 3 added the same
// field to a skipped message key, so one that is never claimed expires
// instead of sitting in the vault forever. All three are still readable.
constexpr uint8_t kStoreVersion = 3;

void write_signed_prekey(serial::Writer<SecureBuffer>& w,
                         const prekey::SignedPrekey& spk) {
  w.u32(spk.id);
  w.bytes(spk.pub.data(), spk.pub.size());
  w.bytes(spk.sk.data(), spk.sk.size());
  w.bytes(spk.signature.data(), spk.signature.size());
  w.u64(spk.created_at);
}

prekey::SignedPrekey read_signed_prekey(serial::Reader& r, uint8_t version) {
  prekey::SignedPrekey spk;
  spk.id = r.u32();
  r.bytes(spk.pub.data(), spk.pub.size());
  r.bytes(spk.sk.data(), spk.sk.size());
  r.bytes(spk.signature.data(), spk.signature.size());
  if (version >= 2) {
    spk.created_at = r.u64();
  } else {
    // Vaults written before rotation tracking existed have no recorded age;
    // treat the prekey as fresh rather than immediately flagging it stale.
    spk.created_at = static_cast<uint64_t>(std::time(nullptr));
  }
  return spk;
}

void write_one_time_prekey(serial::Writer<SecureBuffer>& w,
                           const prekey::OneTimePrekey& otpk) {
  w.u32(otpk.id);
  w.bytes(otpk.pub.data(), otpk.pub.size());
  w.bytes(otpk.sk.data(), otpk.sk.size());
}

prekey::OneTimePrekey read_one_time_prekey(serial::Reader& r) {
  prekey::OneTimePrekey otpk;
  otpk.id = r.u32();
  r.bytes(otpk.pub.data(), otpk.pub.size());
  r.bytes(otpk.sk.data(), otpk.sk.size());
  return otpk;
}

void write_peer_card(serial::Writer<SecureBuffer>& w, const PeerCard& card) {
  w.u32(card.spk_id);
  w.bytes(card.spk_pub.data(), card.spk_pub.size());
  w.bytes(card.spk_signature.data(), card.spk_signature.size());
  w.u32(static_cast<uint32_t>(card.one_time_prekeys.size()));
  for (const PeerOtpk& o : card.one_time_prekeys) {
    w.u32(o.id);
    w.bytes(o.pub.data(), o.pub.size());
  }
}

PeerCard read_peer_card(serial::Reader& r) {
  PeerCard card;
  card.spk_id = r.u32();
  r.bytes(card.spk_pub.data(), card.spk_pub.size());
  r.bytes(card.spk_signature.data(), card.spk_signature.size());
  const uint32_t count = r.u32();
  card.one_time_prekeys.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    PeerOtpk o;
    o.id = r.u32();
    r.bytes(o.pub.data(), o.pub.size());
    card.one_time_prekeys.push_back(o);
  }
  return card;
}

void write_contact(serial::Writer<SecureBuffer>& w, const Contact& contact) {
  w.str(contact.alias);
  w.bytes(contact.identity_pub.data(), contact.identity_pub.size());
  w.u8(contact.verified ? 1 : 0);
  w.u8(contact.card.has_value() ? 1 : 0);
  if (contact.card) {
    write_peer_card(w, *contact.card);
  }
}

Contact read_contact(serial::Reader& r) {
  Contact contact;
  contact.alias = r.str();
  r.bytes(contact.identity_pub.data(), contact.identity_pub.size());
  contact.verified = r.u8() != 0;
  if (r.u8() != 0) {
    contact.card = read_peer_card(r);
  }
  return contact;
}

void write_skipped_key(serial::Writer<SecureBuffer>& w, const SkippedKey& sk) {
  w.bytes(sk.dh_pub.data(), sk.dh_pub.size());
  w.u32(sk.n);
  w.bytes(sk.message_key.data(), sk.message_key.size());
  w.u64(sk.created_at);
}

SkippedKey read_skipped_key(serial::Reader& r, uint8_t version) {
  SkippedKey sk;
  r.bytes(sk.dh_pub.data(), sk.dh_pub.size());
  sk.n = r.u32();
  r.bytes(sk.message_key.data(), sk.message_key.size());
  if (version >= 3) {
    sk.created_at = r.u64();
  } else {
    // Vaults written before expiry existed have no recorded age. Start the
    // clock now rather than at the epoch: dropping keys the user has been
    // carrying around would silently lose messages that are still in flight.
    sk.created_at = static_cast<uint64_t>(std::time(nullptr));
  }
  return sk;
}

void write_session(serial::Writer<SecureBuffer>& w, const Session& s) {
  w.u32(static_cast<uint32_t>(s.contact_index));
  w.bytes(s.root_key.data(), s.root_key.size());

  w.u8(s.has_dhs ? 1 : 0);
  w.bytes(s.dhs_sk.data(), s.dhs_sk.size());
  w.bytes(s.dhs_pub.data(), s.dhs_pub.size());

  w.u8(s.has_dhr ? 1 : 0);
  w.bytes(s.dhr_pub.data(), s.dhr_pub.size());

  w.u8(s.has_cks ? 1 : 0);
  w.bytes(s.chain_key_send.data(), s.chain_key_send.size());

  w.u8(s.has_ckr ? 1 : 0);
  w.bytes(s.chain_key_recv.data(), s.chain_key_recv.size());

  w.u32(s.ns);
  w.u32(s.nr);
  w.u32(s.pn);

  w.u32(static_cast<uint32_t>(s.skipped.size()));
  for (const SkippedKey& sk : s.skipped) {
    write_skipped_key(w, sk);
  }
}

Session read_session(serial::Reader& r, uint8_t version) {
  Session s;
  s.contact_index = r.u32();
  r.bytes(s.root_key.data(), s.root_key.size());

  s.has_dhs = r.u8() != 0;
  r.bytes(s.dhs_sk.data(), s.dhs_sk.size());
  r.bytes(s.dhs_pub.data(), s.dhs_pub.size());

  s.has_dhr = r.u8() != 0;
  r.bytes(s.dhr_pub.data(), s.dhr_pub.size());

  s.has_cks = r.u8() != 0;
  r.bytes(s.chain_key_send.data(), s.chain_key_send.size());

  s.has_ckr = r.u8() != 0;
  r.bytes(s.chain_key_recv.data(), s.chain_key_recv.size());

  s.ns = r.u32();
  s.nr = r.u32();
  s.pn = r.u32();

  const uint32_t skipped_count = r.u32();
  s.skipped.reserve(skipped_count);
  for (uint32_t i = 0; i < skipped_count; ++i) {
    s.skipped.push_back(read_skipped_key(r, version));
  }
  return s;
}

}  // namespace

int VaultStore::find_contact(std::string_view alias) const {
  for (std::size_t i = 0; i < contacts.size(); ++i) {
    if (contacts[i].alias == alias) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int VaultStore::find_contact_by_identity(const IdentitySigningPublicKey& id) const {
  for (std::size_t i = 0; i < contacts.size(); ++i) {
    if (contacts[i].identity_pub == id) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int VaultStore::find_session(std::size_t contact_index) const {
  for (std::size_t i = 0; i < sessions.size(); ++i) {
    if (sessions[i].contact_index == contact_index) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

SecureBuffer serialize(const VaultStore& store) {
  SecureBuffer out;
  serial::Writer<SecureBuffer> w(out);

  w.bytes(kStoreMagic.data(), kStoreMagic.size());
  w.u8(kStoreVersion);

  w.bytes(store.seed.data(), store.seed.size());

  w.u32(store.next_spk_id);
  w.u32(static_cast<uint32_t>(store.signed_prekeys.size()));
  for (const prekey::SignedPrekey& spk : store.signed_prekeys) {
    write_signed_prekey(w, spk);
  }

  w.u32(store.next_otpk_id);
  w.u32(static_cast<uint32_t>(store.one_time_prekeys.size()));
  for (const prekey::OneTimePrekey& otpk : store.one_time_prekeys) {
    write_one_time_prekey(w, otpk);
  }

  w.u32(static_cast<uint32_t>(store.contacts.size()));
  for (const Contact& c : store.contacts) {
    write_contact(w, c);
  }

  w.u32(static_cast<uint32_t>(store.sessions.size()));
  for (const Session& s : store.sessions) {
    write_session(w, s);
  }

  return out;
}

VaultStore parse(const uint8_t* data, std::size_t len) {
  serial::Reader r(data, len);

  std::array<uint8_t, 4> magic{};
  r.bytes(magic.data(), magic.size());
  if (magic != kStoreMagic) {
    throw Error("internal: vault contents have the wrong internal format");
  }
  const uint8_t version = r.u8();
  if (version < 1 || version > kStoreVersion) {
    throw Error("internal: unsupported vault store version " +
               std::to_string(version));
  }

  VaultStore store;
  r.bytes(store.seed.data(), store.seed.size());

  store.next_spk_id = r.u32();
  const uint32_t spk_count = r.u32();
  store.signed_prekeys.reserve(spk_count);
  for (uint32_t i = 0; i < spk_count; ++i) {
    store.signed_prekeys.push_back(read_signed_prekey(r, version));
  }

  store.next_otpk_id = r.u32();
  const uint32_t otpk_count = r.u32();
  store.one_time_prekeys.reserve(otpk_count);
  for (uint32_t i = 0; i < otpk_count; ++i) {
    store.one_time_prekeys.push_back(read_one_time_prekey(r));
  }

  const uint32_t contact_count = r.u32();
  store.contacts.reserve(contact_count);
  for (uint32_t i = 0; i < contact_count; ++i) {
    store.contacts.push_back(read_contact(r));
  }

  const uint32_t session_count = r.u32();
  store.sessions.reserve(session_count);
  for (uint32_t i = 0; i < session_count; ++i) {
    store.sessions.push_back(read_session(r, version));
  }

  if (!r.at_end()) {
    throw Error("internal: trailing data after the vault contents");
  }

  return store;
}

}  // namespace ratchet::store
