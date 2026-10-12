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
// instead of sitting in the vault forever. Version 4 added the list of X3DH
// handshakes already accepted, so an initial message cannot be replayed. All
// four are still readable: a vault written before the guard existed simply
// starts with an empty list, which is the same state a fresh vault is in.
constexpr uint8_t kStoreVersion = 9;

void write_pq_prekey(serial::Writer<SecureBuffer>& w, const PqPrekey& p) {
  w.u32(p.id);
  w.bytes(p.key.public_key.data(), p.key.public_key.size());
  w.bytes(p.key.private_seed.data(), p.key.private_seed.size());
  w.u64(p.created_at);
}

PqPrekey read_pq_prekey(serial::Reader& r) {
  PqPrekey p;
  p.id = r.u32();
  r.bytes(p.key.public_key.data(), p.key.public_key.size());
  r.bytes(p.key.private_seed.data(), p.key.private_seed.size());
  p.created_at = r.u64();
  const pq::MlKemKeyPair reconstructed =
      pq::ml_kem_768_from_seed(p.key.private_seed);
  if (sodium_memcmp(reconstructed.public_key.data(), p.key.public_key.data(),
                    p.key.public_key.size()) != 0) {
    throw Error("stored ML-KEM public key does not match its private seed");
  }
  return p;
}

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
  w.u8(static_cast<uint8_t>(card.maximum_suite));
  w.u32(card.spk_id);
  w.bytes(card.spk_pub.data(), card.spk_pub.size());
  w.bytes(card.spk_signature.data(), card.spk_signature.size());
  w.u32(static_cast<uint32_t>(card.one_time_prekeys.size()));
  for (const PeerOtpk& o : card.one_time_prekeys) {
    w.u32(o.id);
    w.bytes(o.pub.data(), o.pub.size());
  }
  w.bytes(card.pq_identity_pub.data(), card.pq_identity_pub.size());
  w.u8(card.pq_bundle ? 1 : 0);
  if (card.pq_bundle) {
    const PeerPqBundle& pqb = *card.pq_bundle;
    w.u32(pqb.signed_prekey.id);
    w.bytes(pqb.signed_prekey.pub.data(), pqb.signed_prekey.pub.size());
    w.bytes(pqb.ed_signature.data(), pqb.ed_signature.size());
    w.bytes(pqb.pq_signature.data(), pqb.pq_signature.size());
    w.u32(static_cast<uint32_t>(pqb.one_time_prekeys.size()));
    for (const PeerPqPrekey& p : pqb.one_time_prekeys) {
      w.u32(p.id); w.bytes(p.pub.data(), p.pub.size());
    }
  }
}

PeerCard read_peer_card(serial::Reader& r, uint8_t version) {
  PeerCard card;
  if (version >= 9) {
    const uint8_t suite = r.u8();
    if (suite < 1 || suite > 3) throw Error("invalid card protocol suite");
    card.maximum_suite = static_cast<ProtocolSuite>(suite);
  } else if (version >= 7) {
    card.maximum_suite = ProtocolSuite::HybridPqxdhV1;
  }
  card.spk_id = r.u32();
  r.bytes(card.spk_pub.data(), card.spk_pub.size());
  r.bytes(card.spk_signature.data(), card.spk_signature.size());
  const uint32_t count = r.u32();
  card.one_time_prekeys.reserve(r.bounded_count(count, 4 + 32));
  for (uint32_t i = 0; i < count; ++i) {
    PeerOtpk o;
    o.id = r.u32();
    r.bytes(o.pub.data(), o.pub.size());
    card.one_time_prekeys.push_back(o);
  }
  if (version >= 7) {
    r.bytes(card.pq_identity_pub.data(), card.pq_identity_pub.size());
    if (r.u8() != 0) {
      PeerPqBundle pqb;
      pqb.signed_prekey.id = r.u32();
      r.bytes(pqb.signed_prekey.pub.data(), pqb.signed_prekey.pub.size());
      r.bytes(pqb.ed_signature.data(), pqb.ed_signature.size());
      r.bytes(pqb.pq_signature.data(), pqb.pq_signature.size());
      const uint32_t n = r.u32();
      pqb.one_time_prekeys.reserve(r.bounded_count(n, 4 + pq::kMlKem768PublicKeyBytes));
      for (uint32_t i = 0; i < n; ++i) {
        PeerPqPrekey p; p.id = r.u32();
        r.bytes(p.pub.data(), p.pub.size());
        pqb.one_time_prekeys.push_back(p);
      }
      card.pq_bundle = std::move(pqb);
    }
  }
  return card;
}

void write_contact(serial::Writer<SecureBuffer>& w, const Contact& contact) {
  w.str(contact.alias);
  w.bytes(contact.identity_pub.data(), contact.identity_pub.size());
  w.u8(contact.verified ? 1 : 0);
  w.u8(static_cast<uint8_t>(contact.minimum_suite));
  w.u8(contact.card.has_value() ? 1 : 0);
  if (contact.card) {
    write_peer_card(w, *contact.card);
  }
}

Contact read_contact(serial::Reader& r, uint8_t version) {
  Contact contact;
  contact.alias = r.str();
  if (contact.alias.empty() || contact.alias.size() > kMaxAliasBytes) {
    throw Error("contact alias has an invalid length");
  }
  r.bytes(contact.identity_pub.data(), contact.identity_pub.size());
  contact.verified = r.u8() != 0;
  if (version >= 6) {
    const uint8_t suite = r.u8();
    if (suite < 1 || suite > 3) throw Error("invalid minimum protocol suite");
    contact.minimum_suite = static_cast<ProtocolSuite>(suite);
  }
  if (r.u8() != 0) {
    contact.card = read_peer_card(r, version);
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
  w.u8(static_cast<uint8_t>(s.suite));
  w.u8(static_cast<uint8_t>(s.status));
  w.bytes(s.session_id.data(), s.session_id.size());
  w.u8(s.legacy_read_only ? 1 : 0);
  if (s.spqr_state.size() > std::size_t{8} * 1024u * 1024u) {
    throw Error("SPQR state exceeds the vault limit");
  }
  w.blob(s.spqr_state.data(), s.spqr_state.size());
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
  if (version >= 6) {
    const uint8_t suite = r.u8();
    const uint8_t status = r.u8();
    if (suite < 1 || suite > 3 || status < 1 || status > 3) {
      throw Error("invalid session protocol state");
    }
    s.suite = static_cast<ProtocolSuite>(suite);
    s.status = static_cast<Session::Status>(status);
    r.bytes(s.session_id.data(), s.session_id.size());
    if (version >= 8) s.legacy_read_only = r.u8() != 0;
    if (version >= 9) {
      s.spqr_state = r.secure_blob(std::size_t{8} * 1024u * 1024u);
    }
  }
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

  // dh_pub(32) + n(4) + message_key(32); version 3 adds created_at(8).
  const uint32_t skipped_count = r.u32();
  s.skipped.reserve(r.bounded_count(skipped_count, 32 + 4 + 32));
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

bool VaultStore::handshake_already_accepted(
    const IdentitySigningPublicKey& initiator,
    const x25519::PublicKey& ephemeral_pub) const {
  for (const AcceptedHandshake& h : accepted_handshakes) {
    if (h.ephemeral_pub == ephemeral_pub && h.initiator_identity == initiator) {
      return true;
    }
  }
  return false;
}

void VaultStore::remember_handshake(const IdentitySigningPublicKey& initiator,
                                    const x25519::PublicKey& ephemeral_pub,
                                    uint64_t now) {
  if (handshake_already_accepted(initiator, ephemeral_pub)) {
    return;
  }
  if (accepted_handshakes.size() >= kMaxAcceptedHandshakes) {
    throw Error("accepted-handshake history is full; refusing replay-window eviction");
  }
  AcceptedHandshake h;
  h.initiator_identity = initiator;
  h.ephemeral_pub = ephemeral_pub;
  h.accepted_at = now;
  accepted_handshakes.push_back(h);
}

int VaultStore::find_session(std::size_t contact_index) const {
  for (std::size_t i = 0; i < sessions.size(); ++i) {
    if (sessions[i].contact_index == contact_index) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

Session clone_session(const Session& session) {
  Session out;
  out.contact_index = session.contact_index;
  out.suite = session.suite;
  out.status = session.status;
  out.session_id = session.session_id;
  out.legacy_read_only = session.legacy_read_only;
  out.spqr_state.append(session.spqr_state.data(), session.spqr_state.size());
  out.root_key.assign(session.root_key);

  out.has_dhs = session.has_dhs;
  out.dhs_sk.assign(session.dhs_sk);
  out.dhs_pub = session.dhs_pub;

  out.has_dhr = session.has_dhr;
  out.dhr_pub = session.dhr_pub;

  out.has_cks = session.has_cks;
  out.chain_key_send.assign(session.chain_key_send);

  out.has_ckr = session.has_ckr;
  out.chain_key_recv.assign(session.chain_key_recv);

  out.ns = session.ns;
  out.nr = session.nr;
  out.pn = session.pn;

  out.skipped.reserve(session.skipped.size());
  for (const SkippedKey& sk : session.skipped) {
    SkippedKey copy;
    copy.dh_pub = sk.dh_pub;
    copy.n = sk.n;
    copy.message_key.assign(sk.message_key);
    copy.created_at = sk.created_at;
    out.skipped.push_back(std::move(copy));
  }

  return out;
}

SecureBuffer serialize(const VaultStore& store) {
  SecureBuffer out;
  serial::Writer<SecureBuffer> w(out);

  w.bytes(kStoreMagic.data(), kStoreMagic.size());
  w.u8(kStoreVersion);

  w.bytes(store.vault_id.data(), store.vault_id.size());
  w.u64(store.generation);
  w.bytes(store.previous_digest.data(), store.previous_digest.size());

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

  w.u32(store.next_pq_prekey_id);
  w.u32(static_cast<uint32_t>(store.pq_signed_prekeys.size()));
  for (const PqPrekey& p : store.pq_signed_prekeys) write_pq_prekey(w, p);
  w.u32(static_cast<uint32_t>(store.pq_one_time_prekeys.size()));
  for (const PqPrekey& p : store.pq_one_time_prekeys) write_pq_prekey(w, p);

  w.u32(static_cast<uint32_t>(store.contacts.size()));
  for (const Contact& c : store.contacts) {
    write_contact(w, c);
  }

  w.u32(static_cast<uint32_t>(store.sessions.size()));
  for (const Session& s : store.sessions) {
    write_session(w, s);
  }

  // Appended last, so a version 3 vault is exactly this file minus these
  // bytes and the reader below can tell the two apart on the version alone.
  w.u32(static_cast<uint32_t>(store.accepted_handshakes.size()));
  for (const AcceptedHandshake& h : store.accepted_handshakes) {
    w.bytes(h.initiator_identity.data(), h.initiator_identity.size());
    w.bytes(h.ephemeral_pub.data(), h.ephemeral_pub.size());
    w.u64(h.accepted_at);
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
  if (version >= 5) {
    r.bytes(store.vault_id.data(), store.vault_id.size());
    store.generation = r.u64();
    r.bytes(store.previous_digest.data(), store.previous_digest.size());
  }
  r.bytes(store.seed.data(), store.seed.size());

  // Each reservation below is capped by how many records the remaining bytes
  // could actually contain. The store is authenticated by the time it gets
  // here, so this is defence in depth rather than the front line -- but it is
  // the same Reader the pasted formats use, and a count field is a count field.
  store.next_spk_id = r.u32();
  const uint32_t spk_count = r.u32();
  // id(4) + pub(32) + sk(32) + signature(64); version 2 adds created_at(8).
  store.signed_prekeys.reserve(r.bounded_count(spk_count, 4 + 32 + 32 + 64));
  for (uint32_t i = 0; i < spk_count; ++i) {
    store.signed_prekeys.push_back(read_signed_prekey(r, version));
  }

  store.next_otpk_id = r.u32();
  const uint32_t otpk_count = r.u32();
  // id(4) + pub(32) + sk(32).
  store.one_time_prekeys.reserve(r.bounded_count(otpk_count, 4 + 32 + 32));
  for (uint32_t i = 0; i < otpk_count; ++i) {
    store.one_time_prekeys.push_back(read_one_time_prekey(r));
  }

  if (version >= 7) {
    store.next_pq_prekey_id = r.u32();
    const uint32_t spq = r.u32();
    store.pq_signed_prekeys.reserve(r.bounded_count(spq, 4 + 1184 + 64 + 8));
    for (uint32_t i = 0; i < spq; ++i) store.pq_signed_prekeys.push_back(read_pq_prekey(r));
    const uint32_t opq = r.u32();
    store.pq_one_time_prekeys.reserve(r.bounded_count(opq, 4 + 1184 + 64 + 8));
    for (uint32_t i = 0; i < opq; ++i) store.pq_one_time_prekeys.push_back(read_pq_prekey(r));
  }

  const uint32_t contact_count = r.u32();
  // An empty alias(4) + identity_pub(32) + verified(1) + has_card(1).
  store.contacts.reserve(r.bounded_count(contact_count, 4 + 32 + 1 + 1));
  for (uint32_t i = 0; i < contact_count; ++i) {
    store.contacts.push_back(read_contact(r, version));
  }

  const uint32_t session_count = r.u32();
  // Fixed session fields, before the skipped-key list: 216 bytes.
  store.sessions.reserve(r.bounded_count(session_count, 216));
  for (uint32_t i = 0; i < session_count; ++i) {
    store.sessions.push_back(read_session(r, version));
  }

  if (version >= 4) {
    const uint32_t handshake_count = r.u32();
    // initiator_identity(32) + ephemeral_pub(32) + accepted_at(8).
    store.accepted_handshakes.reserve(
        r.bounded_count(handshake_count, 32 + 32 + 8));
    for (uint32_t i = 0; i < handshake_count; ++i) {
      AcceptedHandshake h;
      r.bytes(h.initiator_identity.data(), h.initiator_identity.size());
      r.bytes(h.ephemeral_pub.data(), h.ephemeral_pub.size());
      h.accepted_at = r.u64();
      store.accepted_handshakes.push_back(h);
    }
  }
  // Older vaults leave the list empty. That is the same state a vault created
  // today starts in, so the guard simply begins protecting from the next
  // handshake onwards; there is no history to reconstruct.

  if (!r.at_end()) {
    throw Error("internal: trailing data after the vault contents");
  }

  return store;
}

}  // namespace ratchet::store
