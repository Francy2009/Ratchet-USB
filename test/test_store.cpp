#include <sodium.h>

#include <string>

#include "ratchet/store.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

store::VaultStore make_sample_store() {
  store::VaultStore s;
  randombytes_buf(s.seed.data(), s.seed.size());

  s.next_spk_id = 3;
  prekey::SignedPrekey spk;
  spk.id = 1;
  x25519::generate_keypair(spk.sk, spk.pub);
  randombytes_buf(spk.signature.data(), spk.signature.size());
  spk.created_at = 1700000000;
  s.signed_prekeys.push_back(std::move(spk));

  s.next_otpk_id = 5;
  for (uint32_t i = 1; i <= 3; ++i) {
    prekey::OneTimePrekey otpk;
    otpk.id = i;
    x25519::generate_keypair(otpk.sk, otpk.pub);
    s.one_time_prekeys.push_back(std::move(otpk));
  }

  store::Contact contact;
  contact.alias = "test contact";
  randombytes_buf(contact.identity_pub.data(), contact.identity_pub.size());
  contact.verified = true;
  store::PeerCard card;
  card.spk_id = 7;
  randombytes_buf(card.spk_pub.data(), card.spk_pub.size());
  randombytes_buf(card.spk_signature.data(), card.spk_signature.size());
  store::PeerOtpk peer_otpk;
  peer_otpk.id = 9;
  randombytes_buf(peer_otpk.pub.data(), peer_otpk.pub.size());
  card.one_time_prekeys.push_back(peer_otpk);
  contact.card = card;
  s.contacts.push_back(std::move(contact));

  // A second contact with no card, to exercise the optional field.
  store::Contact bare;
  bare.alias = "no card yet";
  randombytes_buf(bare.identity_pub.data(), bare.identity_pub.size());
  s.contacts.push_back(std::move(bare));

  store::Session session;
  session.contact_index = 0;
  randombytes_buf(session.root_key.data(), session.root_key.size());
  session.has_dhs = true;
  x25519::generate_keypair(session.dhs_sk, session.dhs_pub);
  session.has_dhr = true;
  randombytes_buf(session.dhr_pub.data(), session.dhr_pub.size());
  session.has_cks = true;
  randombytes_buf(session.chain_key_send.data(), session.chain_key_send.size());
  session.has_ckr = true;
  randombytes_buf(session.chain_key_recv.data(), session.chain_key_recv.size());
  session.ns = 4;
  session.nr = 2;
  session.pn = 1;
  store::SkippedKey sk;
  randombytes_buf(sk.dh_pub.data(), sk.dh_pub.size());
  sk.n = 1;
  randombytes_buf(sk.message_key.data(), sk.message_key.size());
  sk.created_at = 1700000000;
  session.skipped.push_back(std::move(sk));
  s.sessions.push_back(std::move(session));

  return s;
}

}  // namespace

TEST("VaultStore serialize/parse round-trips every field") {
  const store::VaultStore original = make_sample_store();
  const SecureBuffer bytes = store::serialize(original);
  const store::VaultStore parsed = store::parse(bytes.data(), bytes.size());

  CHECK(original.seed.equals(parsed.seed));
  CHECK_EQ(original.next_spk_id, parsed.next_spk_id);
  CHECK_EQ(original.signed_prekeys.size(), parsed.signed_prekeys.size());
  CHECK_EQ(original.signed_prekeys[0].id, parsed.signed_prekeys[0].id);
  CHECK(original.signed_prekeys[0].pub == parsed.signed_prekeys[0].pub);
  CHECK(original.signed_prekeys[0].sk.equals(parsed.signed_prekeys[0].sk));
  CHECK(original.signed_prekeys[0].signature == parsed.signed_prekeys[0].signature);
  CHECK_EQ(original.signed_prekeys[0].created_at, parsed.signed_prekeys[0].created_at);

  CHECK_EQ(original.next_otpk_id, parsed.next_otpk_id);
  CHECK_EQ(original.one_time_prekeys.size(), parsed.one_time_prekeys.size());
  for (size_t i = 0; i < original.one_time_prekeys.size(); ++i) {
    CHECK_EQ(original.one_time_prekeys[i].id, parsed.one_time_prekeys[i].id);
    CHECK(original.one_time_prekeys[i].pub == parsed.one_time_prekeys[i].pub);
    CHECK(original.one_time_prekeys[i].sk.equals(parsed.one_time_prekeys[i].sk));
  }

  CHECK_EQ(original.contacts.size(), parsed.contacts.size());
  CHECK_EQ(original.contacts[0].alias, parsed.contacts[0].alias);
  CHECK(original.contacts[0].identity_pub == parsed.contacts[0].identity_pub);
  CHECK_EQ(original.contacts[0].verified, parsed.contacts[0].verified);
  CHECK(parsed.contacts[0].card.has_value());
  CHECK_EQ(original.contacts[0].card->spk_id, parsed.contacts[0].card->spk_id);
  CHECK(original.contacts[0].card->spk_pub == parsed.contacts[0].card->spk_pub);
  CHECK_EQ(original.contacts[0].card->one_time_prekeys.size(),
          parsed.contacts[0].card->one_time_prekeys.size());
  CHECK(!parsed.contacts[1].card.has_value());
  CHECK_EQ(original.contacts[1].alias, parsed.contacts[1].alias);

  CHECK_EQ(original.sessions.size(), parsed.sessions.size());
  const store::Session& os = original.sessions[0];
  const store::Session& ps = parsed.sessions[0];
  CHECK_EQ(os.contact_index, ps.contact_index);
  CHECK(os.root_key.equals(ps.root_key));
  CHECK_EQ(os.has_dhs, ps.has_dhs);
  CHECK(os.dhs_sk.equals(ps.dhs_sk));
  CHECK(os.dhs_pub == ps.dhs_pub);
  CHECK_EQ(os.has_dhr, ps.has_dhr);
  CHECK(os.dhr_pub == ps.dhr_pub);
  CHECK_EQ(os.has_cks, ps.has_cks);
  CHECK(os.chain_key_send.equals(ps.chain_key_send));
  CHECK_EQ(os.has_ckr, ps.has_ckr);
  CHECK(os.chain_key_recv.equals(ps.chain_key_recv));
  CHECK_EQ(os.ns, ps.ns);
  CHECK_EQ(os.nr, ps.nr);
  CHECK_EQ(os.pn, ps.pn);
  CHECK_EQ(os.skipped.size(), ps.skipped.size());
  CHECK(os.skipped[0].dh_pub == ps.skipped[0].dh_pub);
  CHECK_EQ(os.skipped[0].n, ps.skipped[0].n);
  CHECK(os.skipped[0].message_key.equals(ps.skipped[0].message_key));
  CHECK_EQ(os.skipped[0].created_at, ps.skipped[0].created_at);
}

TEST("VaultStore round-trips an entirely empty store") {
  store::VaultStore original;
  randombytes_buf(original.seed.data(), original.seed.size());

  const SecureBuffer bytes = store::serialize(original);
  const store::VaultStore parsed = store::parse(bytes.data(), bytes.size());

  CHECK(original.seed.equals(parsed.seed));
  CHECK(parsed.signed_prekeys.empty());
  CHECK(parsed.one_time_prekeys.empty());
  CHECK(parsed.contacts.empty());
  CHECK(parsed.sessions.empty());
}

TEST("find_contact, find_contact_by_identity and find_session work") {
  const store::VaultStore s = make_sample_store();

  CHECK_EQ(s.find_contact("test contact"), 0);
  CHECK_EQ(s.find_contact("no card yet"), 1);
  CHECK_EQ(s.find_contact("nobody"), -1);

  CHECK_EQ(s.find_contact_by_identity(s.contacts[0].identity_pub), 0);
  CHECK_EQ(s.find_contact_by_identity(s.contacts[1].identity_pub), 1);
  IdentitySigningPublicKey unknown{};
  CHECK_EQ(s.find_contact_by_identity(unknown), -1);

  CHECK_EQ(s.find_session(0), 0);
  CHECK_EQ(s.find_session(1), -1);
}

TEST("parse rejects truncated store bytes") {
  const store::VaultStore original = make_sample_store();
  const SecureBuffer bytes = store::serialize(original);

  CHECK_THROWS(store::parse(bytes.data(), bytes.size() - 1));
  CHECK_THROWS(store::parse(bytes.data(), 3));
}

// clone_session is the one place this project deliberately duplicates key
// material, and its failure mode is silent: a field left out or assigned from
// the wrong source produces a session that still works for a while and then
// diverges, which would look like a corrupt vault rather than a bug here. So
// the check is not "does it compile" but "is the copy indistinguishable from
// the original", compared over the serialised bytes -- the same representation
// the vault is written from, which covers every field the format carries.
TEST("clone_session reproduces a session exactly") {
  const auto fill = [](SecureBytes<32>& b) {
    uint8_t tmp[32];
    randombytes_buf(tmp, sizeof tmp);
    b.assign(tmp, sizeof tmp);
  };

  store::Session original;
  original.contact_index = 7;
  fill(original.root_key);
  // Distinct random material in every slot, so copying the right number of
  // fields from the wrong ones does not slip through.
  original.has_dhs = true;
  fill(original.dhs_sk);
  randombytes_buf(original.dhs_pub.data(), original.dhs_pub.size());
  original.has_dhr = false;  // mixed on purpose: a hardcoded true would pass
  randombytes_buf(original.dhr_pub.data(), original.dhr_pub.size());
  original.has_cks = true;
  fill(original.chain_key_send);
  original.has_ckr = true;
  fill(original.chain_key_recv);
  original.ns = 11;
  original.nr = 22;
  original.pn = 33;

  for (uint32_t i = 0; i < 3; ++i) {
    store::SkippedKey sk;
    randombytes_buf(sk.dh_pub.data(), sk.dh_pub.size());
    sk.n = 100 + i;
    fill(sk.message_key);
    sk.created_at = 1700000000 + i;
    original.skipped.push_back(std::move(sk));
  }

  store::Session copy = store::clone_session(original);

  // Serialise each inside an otherwise identical store and compare the bytes.
  const auto bytes_of = [](store::Session&& s) {
    store::VaultStore v;
    v.sessions.push_back(std::move(s));
    const SecureBuffer buf = store::serialize(v);
    return std::vector<uint8_t>(buf.data(), buf.data() + buf.size());
  };

  const std::vector<uint8_t> a = bytes_of(std::move(original));
  const std::vector<uint8_t> b = bytes_of(std::move(copy));
  CHECK(a == b);
  CHECK(!a.empty());
}

// --- contact aliases ---------------------------------------------------------

TEST("contact_alias_problem accepts ordinary names, including non-ASCII ones") {
  // Accented letters, CJK and an emoji are all fine: they are visible text, and
  // an interface that refused them would be unusable outside English. A word
  // joiner (U+200D, inside an emoji sequence) is not on the list either.
  CHECK(contact_alias_problem("alice") == nullptr);
  CHECK(contact_alias_problem("città") == nullptr);
  CHECK(contact_alias_problem("世界") == nullptr);
  CHECK(contact_alias_problem(std::string("a") + "\U0001F468\u200D\U0001F4BB") ==
        nullptr);
  // A zero-width non-joiner is how a Persian name is spelled; it joins and
  // does not reorder, so it is allowed like the word joiner above.
  CHECK(contact_alias_problem(std::string("می") + "\u200C" + "خواهم") ==
        nullptr);
  CHECK(contact_alias_problem("a b-c_d.e") == nullptr);
}

TEST("contact_alias_problem refuses a right-to-left override") {
  const std::string alias = std::string("photo") + "\u202E" + "gnp.exe";
  CHECK(contact_alias_problem(alias) == kContactAliasFormatCharsError.data());
  CHECK(has_unicode_format_chars(alias));
}

TEST("contact_alias_problem refuses each listed format character") {
  const char* const refused[] = {
      "\u200E", "\u200F", "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",
      "\u2066", "\u2067", "\u2068", "\u2069", "\uFEFF", "\u0080", "\u009F",
      // Invisible but not reordering: the Arabic letter mark, the zero-width
      // space, the word joiner, the line and paragraph separators, and the
      // deprecated format characters.
      "\u061C", "\u200B", "\u2060", "\u2028", "\u2029", "\u206A", "\u206F",
  };
  for (const char* character : refused) {
    const std::string alias = std::string("alice") + character;
    CHECK(contact_alias_problem(alias) ==
          kContactAliasFormatCharsError.data());
  }
}

TEST("contact_alias_problem refuses control characters that would forge lines") {
  // The alias is printed beside the fingerprint and, for the GUI, inside a
  // line-oriented block. A newline would let a sender add a second
  // "fingerprint:" line of their own; ESC would let them move the cursor. Tab
  // is refused too: no alias needs it.
  const char* const refused[] = {
      "\n", "\r", "\t", "\x1b", "\x07", "\x7f",
  };
  for (const char* character : refused) {
    const std::string alias = std::string("alice") + character + "bob";
    CHECK(contact_alias_problem(alias) ==
          kContactAliasControlCharsError.data());
  }
  const std::string forged = "alice\nfingerprint: forged";
  CHECK(contact_alias_problem(forged) ==
        kContactAliasControlCharsError.data());
}

TEST("contact_alias_problem enforces the length limit and rejects emptiness") {
  CHECK(contact_alias_problem("") == kContactAliasEmptyError.data());
  CHECK(contact_alias_problem(std::string(kMaxContactAliasBytes, 'a')) ==
        nullptr);
  CHECK(contact_alias_problem(std::string(kMaxContactAliasBytes + 1, 'a')) ==
        kContactAliasLimitError.data());
}

TEST("the format-character check does not trust malformed UTF-8 to hide one") {
  // A byte that is not valid UTF-8 is not a format character, so it is copied
  // through rather than treated as one -- but a real one after it still is.
  const std::string lone_continuation("\x85");
  CHECK(!has_unicode_format_chars(lone_continuation));
  const std::string overlong("\xC0\xAF");
  CHECK(!has_unicode_format_chars(overlong));
  const std::string hidden = std::string("\xC0\xAF") + "\u202E";
  CHECK(has_unicode_format_chars(hidden));
  CHECK(contact_alias_problem(hidden) ==
        kContactAliasFormatCharsError.data());
}
