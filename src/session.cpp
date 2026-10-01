#include "ratchet/session.hpp"

#include <ctime>

#include "ratchet/message.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/x3dh.hpp"

namespace ratchet::session {
namespace {

std::array<uint8_t, 32> session_id_for(const message::Envelope& env) {
  const std::vector<uint8_t> transcript = message::envelope_aad_prefix(env);
  std::array<uint8_t, 32> id{};
  crypto_hash_sha256(id.data(), transcript.data(), transcript.size());
  return id;
}

store::Session& get_or_create_session(store::VaultStore& vault,
                                      std::size_t contact_index) {
  const int existing = vault.find_session(contact_index);
  if (existing >= 0) {
    return vault.sessions[static_cast<std::size_t>(existing)];
  }
  store::Session s;
  s.contact_index = contact_index;
  vault.sessions.push_back(std::move(s));
  return vault.sessions.back();
}

}  // namespace

std::string send(store::VaultStore& vault, const IdentitySigningSecretKey& my_identity_sk,
                 const IdentitySigningPublicKey& my_identity_pk, std::size_t contact_index,
                 const std::string& plaintext) {
  store::Contact& contact = vault.contacts.at(contact_index);
  if (!contact.verified) {
    throw Error("contact fingerprint must be verified before sending");
  }
  if (plaintext.size() > message::kMaxPlaintextBytes) {
    throw Error("message exceeds the 4 MiB plaintext limit");
  }
  if (!contact.card || !contact.card->pq_bundle) {
    throw Error("a hybrid post-quantum contact card is required before sending");
  }
  if (!suite_at_least(ProtocolSuite::HybridPqxdhV1, contact.minimum_suite)) {
    throw Error("the contact requires an unsupported protocol suite");
  }
  store::Session& s = get_or_create_session(vault, contact_index);
  if (s.legacy_read_only) {
    throw Error("legacy sessions are read-only; import a post-quantum contact card");
  }
  if (s.has_dhs && s.suite != ProtocolSuite::HybridPqxdhV1) {
    throw Error("the active session uses an unsupported protocol suite");
  }

  message::Envelope env;
  env.sender_id = message::sender_id_for(my_identity_pk);
  env.suite = ProtocolSuite::HybridPqxdhV1;

  // A session freshly created by get_or_create_session (or one that was never
  // handed a shared secret) has no sending chain yet: that is the signal that
  // X3DH still needs to run before the ratchet can encrypt anything.
  if (!s.has_cks) {
    x3dh::InitiatorResult hs = x3dh::initiate(my_identity_sk, my_identity_pk, contact);
    ratchet::init_sender(s, hs.shared_secret, hs.ephemeral_sk, hs.ephemeral_pk,
                         hs.spk_pub);

    message::InitialFields fields;
    fields.initiator_identity_pub = my_identity_pk;
    fields.spk_id = hs.spk_id;
    fields.otpk_id = hs.otpk_id;
    fields.pq_spk_id = hs.pq_spk_id;
    fields.pq_spk_ciphertext = hs.pq_spk_ciphertext;
    fields.pq_otpk_id = hs.pq_otpk_id;
    fields.pq_otpk_ciphertext = hs.pq_otpk_ciphertext;
    env.initial = fields;
    s.suite = ProtocolSuite::HybridPqxdhV1;
    s.session_id = session_id_for(env);
    s.status = store::Session::Status::Pending;
  } else if (s.status == store::Session::Status::Closed) {
    throw Error("session is closed; import a fresh card before sending");
  }

  ratchet::encrypt(s, plaintext, env.header, env.ciphertext,
                   message::envelope_aad_prefix(env));
  return message::encode(env);
}

ReceiveResult receive(store::VaultStore& vault, const IdentitySigningSecretKey& my_identity_sk,
                      const IdentitySigningPublicKey& my_identity_pk, const std::string& block) {
  const message::Envelope env = message::decode(block);

  if (env.initial) {
    const message::InitialFields& f = *env.initial;

    const int idx = vault.find_contact_by_identity(f.initiator_identity_pub);
    if (idx < 0) {
      throw Error(
          "message from an unknown contact; import their card first "
          "(`add-contact`)");
    }
    const std::size_t contact_index = static_cast<std::size_t>(idx);
    if (!vault.contacts[contact_index].verified) {
      throw Error("contact fingerprint must be verified before receiving messages");
    }
    if (!suite_at_least(env.suite,
                        vault.contacts[contact_index].minimum_suite)) {
      throw Error("message protocol suite is below the contact's minimum");
    }
    if (!f.pq_spk_id || !f.pq_spk_ciphertext) {
      throw Error("hybrid opening is missing its ML-KEM signed prekey");
    }

    // Before anything is looked up, consumed or replaced. Accepting an initial
    // message throws away whatever session already exists with this contact,
    // so a replay that got this far would cost the conversation every message
    // sent after the one being replayed -- see store::AcceptedHandshake.
    //
    // env.header.dh_pub is the initiator's X3DH ephemeral: `initiate` draws a
    // fresh one every time, so this rejects the same handshake arriving twice
    // without ever rejecting a genuine new one.
    if (vault.handshake_already_accepted(f.initiator_identity_pub,
                                         env.header.dh_pub)) {
      throw Error(
          "this opening message has already been received once; ignoring it "
          "(a repeated copy cannot tell us anything new, and acting on it "
          "would discard the conversation you have had since)");
    }

    const prekey::SignedPrekey* spk = nullptr;
    for (const prekey::SignedPrekey& candidate : vault.signed_prekeys) {
      if (candidate.id == f.spk_id) {
        spk = &candidate;
        break;
      }
    }
    if (spk == nullptr) {
      throw Error("message references a signed prekey we no longer have (id " +
                 std::to_string(f.spk_id) + ")");
    }

    const prekey::OneTimePrekey* otpk = nullptr;
    int otpk_vec_index = -1;
    if (f.otpk_id) {
      for (std::size_t i = 0; i < vault.one_time_prekeys.size(); ++i) {
        if (vault.one_time_prekeys[i].id == *f.otpk_id) {
          otpk = &vault.one_time_prekeys[i];
          otpk_vec_index = static_cast<int>(i);
          break;
        }
      }
      if (otpk == nullptr) {
        throw Error(
            "message references a one-time prekey that has already been "
            "used or does not exist");
      }
    }

    const store::PqPrekey* pq_spk = nullptr;
    for (const store::PqPrekey& candidate : vault.pq_signed_prekeys) {
      if (candidate.id == *f.pq_spk_id) { pq_spk = &candidate; break; }
    }
    if (!pq_spk) throw Error("message references an unknown ML-KEM signed prekey");
    const store::PqPrekey* pq_otpk = nullptr;
    int pq_otpk_vec_index = -1;
    if (f.pq_otpk_id) {
      if (!f.pq_otpk_ciphertext) throw Error("message authentication failed");
      for (std::size_t i = 0; i < vault.pq_one_time_prekeys.size(); ++i) {
        if (vault.pq_one_time_prekeys[i].id == *f.pq_otpk_id) {
          pq_otpk = &vault.pq_one_time_prekeys[i];
          pq_otpk_vec_index = static_cast<int>(i); break;
        }
      }
      if (!pq_otpk) throw Error("ML-KEM one-time prekey was already used or is unknown");
    } else if (f.pq_otpk_ciphertext) {
      throw Error("message authentication failed");
    }

    SecureBytes<32> shared = x3dh::respond_hybrid(
        my_identity_sk, my_identity_pk, f.initiator_identity_pub,
        env.header.dh_pub, *spk, otpk, *pq_spk, *f.pq_spk_ciphertext,
        pq_otpk, f.pq_otpk_ciphertext ? &*f.pq_otpk_ciphertext : nullptr);

    store::Session fresh;
    fresh.contact_index = contact_index;
    fresh.suite = ProtocolSuite::HybridPqxdhV1;
    fresh.session_id = session_id_for(env);
    fresh.status = store::Session::Status::Confirmed;
    ratchet::init_receiver(fresh, shared, spk->sk, spk->pub);

    ReceiveResult result;
    result.contact_index = contact_index;
    result.alias = vault.contacts[contact_index].alias;

    // Decrypt while `fresh` is still a local. Everything below this line
    // changes the vault, and none of it should happen for a message that turns
    // out not to be genuine: replacing the session would discard the
    // conversation, and consuming the one-time prekey would let anyone burn
    // through the pool by pasting nonsense. decrypt throws on a bad tag, which
    // leaves all of it untouched.
    result.plaintext = ratchet::decrypt(
        fresh, env.header, env.ciphertext, message::envelope_aad_prefix(env));

    const int existing = vault.find_session(contact_index);
    if (existing >= 0) {
      const store::Session& current =
          vault.sessions[static_cast<std::size_t>(existing)];
      if (current.status == store::Session::Status::Confirmed) {
        throw Error("an established session cannot be replaced by an opening message");
      }
      if (current.status == store::Session::Status::Pending &&
          current.session_id < fresh.session_id) {
        throw Error("simultaneous opening lost the deterministic session tie-break");
      }
      vault.sessions[static_cast<std::size_t>(existing)] = std::move(fresh);
    } else {
      vault.sessions.push_back(std::move(fresh));
    }

    if (otpk_vec_index >= 0) {
      // Single use, and now genuinely used.
      vault.one_time_prekeys.erase(vault.one_time_prekeys.begin() + otpk_vec_index);
    }
    if (pq_otpk_vec_index >= 0) {
      vault.pq_one_time_prekeys.erase(vault.pq_one_time_prekeys.begin() +
                                      pq_otpk_vec_index);
    }
    vault.contacts[contact_index].minimum_suite = ProtocolSuite::HybridPqxdhV1;

    vault.remember_handshake(f.initiator_identity_pub, env.header.dh_pub,
                             static_cast<uint64_t>(std::time(nullptr)));
    result.session_established = true;
    return result;
  }

  for (std::size_t i = 0; i < vault.contacts.size(); ++i) {
    if (message::sender_id_for(vault.contacts[i].identity_pub) == env.sender_id) {
      if (!vault.contacts[i].verified) {
        throw Error("contact fingerprint must be verified before receiving messages");
      }
      const int existing = vault.find_session(i);
      if (existing < 0) {
        throw Error(
            "no session with this contact yet; they need to send an "
            "initial message first");
      }
      store::Session& s = vault.sessions[static_cast<std::size_t>(existing)];
      if (!suite_at_least(env.suite, vault.contacts[i].minimum_suite) ||
          env.suite != s.suite) {
        throw Error("message protocol suite does not match the active session");
      }

      ReceiveResult result;
      result.contact_index = i;
      result.alias = vault.contacts[i].alias;

      // ratchet::decrypt is atomic: it advances `s` only once the AEAD tag has
      // checked out, so a forged or repeated message leaves the session
      // untouched. That guarantee used to live here, as a clone this function
      // remembered to make; it belongs to the ratchet, so it moved there.
      result.plaintext = ratchet::decrypt(
          s, env.header, env.ciphertext, message::envelope_aad_prefix(env));
      s.status = store::Session::Status::Confirmed;

      result.session_established = false;
      return result;
    }
  }

  throw Error("message from an unrecognised sender");
}

std::size_t expire_skipped_keys(store::VaultStore& vault) {
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  std::size_t dropped = 0;
  for (store::Session& s : vault.sessions) {
    dropped += ratchet::expire_skipped_keys(s, now);
  }
  return dropped;
}

}  // namespace ratchet::session
