#include "ratchet/session.hpp"

#include "ratchet/message.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/x3dh.hpp"

namespace ratchet::session {
namespace {

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

std::string send(store::VaultStore& vault, const IdentitySigningSecretKey& my_sk,
                 const IdentitySigningPublicKey& my_pk, std::size_t contact_index,
                 const std::string& plaintext) {
  store::Contact& contact = vault.contacts.at(contact_index);
  store::Session& s = get_or_create_session(vault, contact_index);

  message::Envelope env;
  env.sender_id = message::sender_id_for(my_pk);

  // A session freshly created by get_or_create_session (or one that was never
  // handed a shared secret) has no sending chain yet: that is the signal that
  // X3DH still needs to run before the ratchet can encrypt anything.
  if (!s.has_cks) {
    x3dh::InitiatorResult hs = x3dh::initiate(my_sk, my_pk, contact);
    const x25519::PublicKey bob_dh_pub = contact.card->spk_pub;
    ratchet::init_sender(s, hs.shared_secret, hs.ephemeral_sk, hs.ephemeral_pk,
                         bob_dh_pub);

    message::InitialFields fields;
    fields.initiator_identity_pub = my_pk;
    fields.spk_id = hs.spk_id;
    fields.otpk_id = hs.otpk_id;
    env.initial = fields;
  }

  ratchet::encrypt(s, plaintext, env.header, env.ciphertext);
  return message::encode(env);
}

ReceiveResult receive(store::VaultStore& vault, const IdentitySigningSecretKey& my_sk,
                      const IdentitySigningPublicKey& my_pk, const std::string& block) {
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

    SecureBytes<32> shared = x3dh::respond(my_sk, my_pk, f.initiator_identity_pub,
                                           env.header.dh_pub, *spk, otpk);

    store::Session fresh;
    fresh.contact_index = contact_index;
    ratchet::init_receiver(fresh, shared, spk->sk, spk->pub);

    const int existing = vault.find_session(contact_index);
    if (existing >= 0) {
      vault.sessions[static_cast<std::size_t>(existing)] = std::move(fresh);
    } else {
      vault.sessions.push_back(std::move(fresh));
    }

    if (otpk_vec_index >= 0) {
      // Single use: drop it now so it can never be consumed again, even if
      // this same initial message is replayed later.
      vault.one_time_prekeys.erase(vault.one_time_prekeys.begin() + otpk_vec_index);
    }

    store::Session& s =
        vault.sessions[static_cast<std::size_t>(vault.find_session(contact_index))];
    ReceiveResult result;
    result.contact_index = contact_index;
    result.alias = vault.contacts[contact_index].alias;
    result.plaintext = ratchet::decrypt(s, env.header, env.ciphertext);
    result.session_established = true;
    return result;
  }

  for (std::size_t i = 0; i < vault.contacts.size(); ++i) {
    if (message::sender_id_for(vault.contacts[i].identity_pub) == env.sender_id) {
      const int existing = vault.find_session(i);
      if (existing < 0) {
        throw Error(
            "no session with this contact yet; they need to send an "
            "initial message first");
      }
      store::Session& s = vault.sessions[static_cast<std::size_t>(existing)];
      ReceiveResult result;
      result.contact_index = i;
      result.alias = vault.contacts[i].alias;
      result.plaintext = ratchet::decrypt(s, env.header, env.ciphertext);
      result.session_established = false;
      return result;
    }
  }

  throw Error("message from an unrecognised sender");
}

}  // namespace ratchet::session
