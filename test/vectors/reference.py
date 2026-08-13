#!/usr/bin/env python3
"""An independent reference implementation of Ratchet-USB's key schedule.

This exists to answer one question the C++ test suite cannot answer on its
own: is the ratchet *correct*, or is it merely self-consistent? A round-trip
test encrypts and decrypts with the same code, so a key schedule that is wrong
in a coherent way -- swapped HMAC constants, the wrong HKDF salt/IKM order, a
truncated info string -- passes every one of them.

So the derivations are written a second time here, from the specifications
rather than from `src/ratchet.cpp`, in a different language, using only the
Python standard library (`hashlib`, `hmac`) and integer arithmetic. The
outputs are frozen into `vectors.hpp`, which the C++ suite then has to
reproduce byte for byte. When the two disagree, one of them is wrong, and
neither can quietly drag the other along.

Deliberately *not* a claim of libsignal interoperability. Ratchet-USB departs
from the Signal Double Ratchet in ways its README documents (a message key is
used directly as a ChaCha20-Poly1305 key instead of being expanded into
AES-CBC/HMAC/IV material; the AEAD nonce is random and carried in the envelope
rather than derived; the root-key info string is this project's own). Those
choices make byte-compatible libsignal vectors impossible by construction.
What is checked here is that the primitives underneath are the standard ones,
composed in the order the specifications call for.

The primitives are themselves pinned to published test vectors -- RFC 7748 for
X25519, RFC 5869 for HKDF-SHA256 -- and `self_test()` runs those before any
vector is emitted, so a bug in this file cannot silently become the expected
answer.

Usage:
    python3 reference.py --check     # run the self-tests only
    python3 reference.py --emit      # regenerate vectors.hpp on stdout
"""

import argparse
import hashlib
import hmac
import sys

# --------------------------------------------------------------------------
# X25519 (RFC 7748)
# --------------------------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665


def _cswap(swap, a, b):
    dummy = swap * ((a - b) % _P)
    return (a - dummy) % _P, (b + dummy) % _P


def _decode_scalar(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _decode_u(u):
    u = bytearray(u)
    u[31] &= 0x7F
    return int.from_bytes(u, "little")


def x25519(scalar, u_coord):
    """The X25519 function: a Montgomery ladder on Curve25519."""
    k = _decode_scalar(scalar)
    x1 = _decode_u(u_coord)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * ((aa + _A24 * e) % _P) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


_BASE_POINT = (9).to_bytes(32, "little")


def x25519_base(scalar):
    """The public key for a secret scalar: X25519(scalar, 9)."""
    return x25519(scalar, _BASE_POINT)


# --------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)
# --------------------------------------------------------------------------

_HASH_LEN = 32


def hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * _HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    if length == 0 or length > 255 * _HASH_LEN:
        raise ValueError("HKDF-Expand: unsupported output length")
    out = b""
    block = b""
    counter = 0
    while len(out) < length:
        counter += 1
        block = hmac.new(
            prk, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        out += block
    return out[:length]


# --------------------------------------------------------------------------
# The Ratchet-USB key schedule
# --------------------------------------------------------------------------

ROOT_INFO = b"Ratchet-USB/v1/ratchet-root"


def kdf_rk(rk, dh_out):
    """One DH ratchet step: (root key, DH output) -> (new root key, chain key).

    HKDF-SHA256 with the *root key as salt* and the *DH output as IKM* -- that
    order is the whole point, and swapping it yields a schedule that still
    round-trips perfectly while being wrong.
    """
    prk = hkdf_extract(rk, dh_out)
    okm = hkdf_expand(prk, ROOT_INFO, 64)
    return okm[:32], okm[32:]


def kdf_ck(ck):
    """One symmetric ratchet step: chain key -> (next chain key, message key).

    HMAC-SHA256 keyed by the chain key, over a single distinguishing byte:
    0x01 yields the message key, 0x02 the next chain key.
    """
    mk = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    next_ck = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return next_ck, mk


def header_aad(dh_pub, pn, n):
    """The associated data every message's AEAD call is bound to.

    Little-endian uint32 counters, matching serial::Writer::u32.
    """
    return dh_pub + pn.to_bytes(4, "little") + n.to_bytes(4, "little")


def init_sender(shared_secret, ephemeral_sk, bob_dh_pub):
    """Alice's side of session setup: RK and CKs after the first DH step."""
    dh_out = x25519(ephemeral_sk, bob_dh_pub)
    return kdf_rk(shared_secret, dh_out)


def dh_ratchet(root_key, dhs_sk, new_dhr_pub, next_dhs_sk):
    """A full DH ratchet step, in the order src/ratchet.cpp performs it.

    First the receiving chain off the *current* key pair, then a fresh key
    pair, then the sending chain off that. Returns the state after both.
    """
    dh_out = x25519(dhs_sk, new_dhr_pub)
    root_key, chain_key_recv = kdf_rk(root_key, dh_out)

    dh_out = x25519(next_dhs_sk, new_dhr_pub)
    root_key, chain_key_send = kdf_rk(root_key, dh_out)

    return root_key, chain_key_recv, chain_key_send


# --------------------------------------------------------------------------
# Self-tests against published vectors
# --------------------------------------------------------------------------


def _h(s):
    return bytes.fromhex(s)


def self_test():
    """Pins every primitive to its specification's own test vectors."""
    checks = 0

    # RFC 7748 section 5.2 -- the X25519 function itself.
    assert x25519(
        _h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        _h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == _h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    checks += 1

    assert x25519(
        _h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        _h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    ) == _h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    checks += 1

    # RFC 7748 section 6.1 -- a full Diffie-Hellman exchange.
    alice_sk = _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_pk = _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_sk = _h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_pk = _h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = _h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    assert x25519_base(alice_sk) == alice_pk
    assert x25519_base(bob_sk) == bob_pk
    assert x25519(alice_sk, bob_pk) == shared
    assert x25519(bob_sk, alice_pk) == shared
    checks += 4

    # RFC 5869 test case 1 -- HKDF-SHA256 with salt and info.
    prk = hkdf_extract(_h("000102030405060708090a0b0c"), b"\x0b" * 22)
    assert prk == _h(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    assert hkdf_expand(prk, _h("f0f1f2f3f4f5f6f7f8f9"), 42) == _h(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    checks += 2

    # RFC 5869 test case 3 -- empty salt and info, exercising the zero-salt path.
    prk = hkdf_extract(b"", b"\x0b" * 22)
    assert prk == _h(
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    )
    assert hkdf_expand(prk, b"", 42) == _h(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )
    checks += 2

    return checks


# --------------------------------------------------------------------------
# Vector generation
# --------------------------------------------------------------------------


def _seed(tag):
    """Deterministic, arbitrary-looking test input derived from a label.

    Using SHA-256 of a label rather than a hard-coded blob keeps the vectors
    reproducible by anyone reading this file, with no hidden constants.
    """
    return hashlib.sha256(b"Ratchet-USB test vector/" + tag).digest()


def _clamp(scalar):
    """X25519 clamping, applied up front so the C++ and Python sides agree on
    the exact secret-key bytes stored, not merely on the DH result."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def build_vectors():
    v = {}

    # -- KDF_CK: five consecutive symmetric ratchet steps ------------------
    ck = _seed(b"chain-key")
    v["ck_initial"] = ck
    chain = []
    for _ in range(5):
        ck, mk = kdf_ck(ck)
        chain.append((ck, mk))
    v["ck_chain"] = chain

    # -- KDF_RK: one DH ratchet step --------------------------------------
    rk_in = _seed(b"root-key")
    dh_in = _seed(b"dh-output")
    v["rk_in"] = rk_in
    v["rk_dh_in"] = dh_in
    v["rk_out"], v["rk_ck_out"] = kdf_rk(rk_in, dh_in)

    # -- KDF_RK aliasing: rk and new_rk as the same object -----------------
    # src/ratchet.cpp relies on this being safe; the vector pins the result.
    v["rk_alias_out"], v["rk_alias_ck"] = kdf_rk(rk_in, dh_in)

    # -- Session setup, Alice's side (fully deterministic) -----------------
    shared_secret = _seed(b"x3dh-shared-secret")
    alice_eph_sk = _clamp(_seed(b"alice-ephemeral"))
    bob_spk_sk = _clamp(_seed(b"bob-signed-prekey"))
    alice_eph_pk = x25519_base(alice_eph_sk)
    bob_spk_pk = x25519_base(bob_spk_sk)

    v["shared_secret"] = shared_secret
    v["alice_eph_sk"] = alice_eph_sk
    v["alice_eph_pk"] = alice_eph_pk
    v["bob_spk_sk"] = bob_spk_sk
    v["bob_spk_pk"] = bob_spk_pk
    v["dh_alice_bob"] = x25519(alice_eph_sk, bob_spk_pk)

    root_key, chain_key_send = init_sender(shared_secret, alice_eph_sk, bob_spk_pk)
    v["session_root_key"] = root_key
    v["session_cks_0"] = chain_key_send

    # Three messages down Alice's first sending chain.
    sending = []
    ck = chain_key_send
    for _ in range(3):
        ck, mk = kdf_ck(ck)
        sending.append((ck, mk))
    v["session_sending_chain"] = sending

    # -- A DH ratchet step, in the order the implementation performs it ----
    bob_next_sk = _clamp(_seed(b"bob-next-ratchet"))
    v["bob_next_sk"] = bob_next_sk
    v["bob_next_pk"] = x25519_base(bob_next_sk)
    r_rk, r_ckr, r_cks = dh_ratchet(
        root_key, bob_spk_sk, alice_eph_pk, bob_next_sk
    )
    v["ratchet_step_rk"] = r_rk
    v["ratchet_step_ckr"] = r_ckr
    v["ratchet_step_cks"] = r_cks

    # -- Header associated data -------------------------------------------
    v["aad_dh_pub"] = alice_eph_pk
    v["aad_pn"] = 0x01020304
    v["aad_n"] = 0x05060708
    v["aad"] = header_aad(alice_eph_pk, v["aad_pn"], v["aad_n"])

    return v


_HEADER_PREAMBLE = """\
// Generated by test/vectors/reference.py -- do not edit by hand.
//
// Known-answer vectors for the ratchet's key schedule, produced by an
// independent implementation written from the specifications (RFC 7748,
// RFC 5869 and the Signal Double Ratchet's KDF construction) rather than from
// src/ratchet.cpp. A round-trip test proves the code agrees with itself; these
// prove it agrees with something that has never seen it.
//
// To regenerate:
//     python3 test/vectors/reference.py --emit > test/vectors/vectors.hpp
//
// CI regenerates this file and fails if the result differs from what is
// committed, so the two implementations cannot drift apart unnoticed.

#ifndef RATCHET_TEST_VECTORS_HPP
#define RATCHET_TEST_VECTORS_HPP

#include <cstdint>
#include <string_view>

namespace ratchet::test::vectors {

"""


def _cpp_bytes(name, data):
    return f'inline constexpr std::string_view {name} =\n    "{data.hex()}";\n'


def emit(v, out):
    out.write(_HEADER_PREAMBLE)

    out.write("// --- KDF_CK: five consecutive symmetric ratchet steps ---\n")
    out.write(_cpp_bytes("kCkInitial", v["ck_initial"]))
    out.write("\ninline constexpr std::string_view kCkChain[5][2] = {\n")
    for ck, mk in v["ck_chain"]:
        out.write(f'    {{"{ck.hex()}",\n     "{mk.hex()}"}},\n')
    out.write("};\n\n")

    out.write("// --- KDF_RK: one DH ratchet step ---\n")
    for name, key in [
        ("kRkIn", "rk_in"),
        ("kRkDhIn", "rk_dh_in"),
        ("kRkOut", "rk_out"),
        ("kRkCkOut", "rk_ck_out"),
        ("kRkAliasOut", "rk_alias_out"),
        ("kRkAliasCk", "rk_alias_ck"),
    ]:
        out.write(_cpp_bytes(name, v[key]))

    out.write("\n// --- Session setup, Alice's side ---\n")
    for name, key in [
        ("kSharedSecret", "shared_secret"),
        ("kAliceEphSk", "alice_eph_sk"),
        ("kAliceEphPk", "alice_eph_pk"),
        ("kBobSpkSk", "bob_spk_sk"),
        ("kBobSpkPk", "bob_spk_pk"),
        ("kDhAliceBob", "dh_alice_bob"),
        ("kSessionRootKey", "session_root_key"),
        ("kSessionCks0", "session_cks_0"),
    ]:
        out.write(_cpp_bytes(name, v[key]))

    out.write("\ninline constexpr std::string_view kSessionSendingChain[3][2] = {\n")
    for ck, mk in v["session_sending_chain"]:
        out.write(f'    {{"{ck.hex()}",\n     "{mk.hex()}"}},\n')
    out.write("};\n\n")

    out.write("// --- A full DH ratchet step ---\n")
    for name, key in [
        ("kBobNextSk", "bob_next_sk"),
        ("kBobNextPk", "bob_next_pk"),
        ("kRatchetStepRk", "ratchet_step_rk"),
        ("kRatchetStepCkr", "ratchet_step_ckr"),
        ("kRatchetStepCks", "ratchet_step_cks"),
    ]:
        out.write(_cpp_bytes(name, v[key]))

    out.write("\n// --- Header associated data ---\n")
    out.write(_cpp_bytes("kAadDhPub", v["aad_dh_pub"]))
    out.write(f'inline constexpr uint32_t kAadPn = {v["aad_pn"]}u;\n')
    out.write(f'inline constexpr uint32_t kAadN = {v["aad_n"]}u;\n')
    out.write(_cpp_bytes("kAad", v["aad"]))

    out.write("\n// --- The wire-contract info string ---\n")
    out.write(f'inline constexpr std::string_view kRootInfo = "{ROOT_INFO.decode()}";\n')

    out.write("\n}  // namespace ratchet::test::vectors\n\n")
    out.write("#endif  // RATCHET_TEST_VECTORS_HPP\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="run the self-tests and exit"
    )
    parser.add_argument(
        "--emit", action="store_true", help="write vectors.hpp to stdout"
    )
    args = parser.parse_args()

    if not args.check and not args.emit:
        parser.error("pass --check or --emit")

    checks = self_test()

    if args.check:
        print(f"reference.py: {checks} published test vectors reproduced", file=sys.stderr)

    if args.emit:
        emit(build_vectors(), sys.stdout)

    return 0


if __name__ == "__main__":
    sys.exit(main())
