#!/usr/bin/env python3
"""End-to-end test of the terminal interface, driven through a real pty.

The unit tests cover the interface's state machine, which is pure and knows
nothing about a terminal.  This covers what they cannot: raw mode, the frame
actually reaching the screen, the passphrase prompts that step outside the
frame, bracketed paste, and the whole path from a keystroke to a sealed vault.

A conversation is carried out entirely through the interface -- import a card,
verify it, write a message -- and then read on the other side.  What comes out
has to be the plaintext that went in.

Usage: test/smoke_ui.py build/ratchet-usb
"""

import fcntl
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ratchet-usb")
# Argon2 at its default cost would make this test take minutes for no extra
# coverage: what is being tested here is the interface, not the KDF.
CHEAP = ["--argon2-mem-kb", "65536", "--argon2-time", "3"]

failures = []


def step(text):
    """Logs one labelled phase of the scripted conversation."""
    print("  ui-smoke: %s" % text)


def fail(text):
    """Records a failed expectation without stopping the run."""
    print("  ui-smoke: FAIL -- %s" % text)
    failures.append(text)


def cli(args, stdin=""):
    """Runs the ordinary command line, for the setup this test is not testing."""
    result = subprocess.run([BIN] + args, input=stdin, capture_output=True,
                            text=True)
    if result.returncode != 0:
        raise SystemExit("setup command failed: %s\n%s" % (args, result.stderr))
    return result.stdout


def generated_words(init_output):
    """Pulls the generated vault passphrase out of an `init` run.

    `init` shows the words once, in a numbered grid, between its own heading
    and the note that follows it. The recovery phrase uses the same grid, so
    the heading is what tells the two apart.
    """
    match = re.search(
        r"Vault passphrase \(write.*?\n(.*?)These words unlock",
        init_output, re.S)
    if not match:
        raise SystemExit("could not find the generated vault passphrase")
    return re.findall(r"[0-9]+\.\s+([a-z]+)", match.group(1))


def init_vault(drive):
    """Creates a vault the way a person would, and returns its words."""
    # The generated passphrase is shown on stderr, so both streams are searched
    # for the grid; the recovery phrase stays on stdout.
    result = subprocess.run([BIN, "init", "--usb-path", drive] + CHEAP,
                            input="", capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("init failed: %s" % result.stderr)
    words = generated_words(result.stdout + result.stderr)
    if len(words) != 12:
        raise SystemExit("expected a 12-word passphrase, got %r" % (words,))
    return words


def feed(words):
    """The passphrase as the program now reads it: one word per line."""
    return "".join(word + "\n" for word in words)


class Ui:
    """The interface running on a pty, with a way to read the screen back."""

    def __init__(self, drive, extra=None, env_extra=None):
        """Start the terminal UI in a private pty for the supplied vault."""
        self.buffer = bytearray()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            env = dict(os.environ, TERM="xterm-256color", LANG="C", LC_ALL="C")
            if not env_extra or "NO_COLOR" not in env_extra:
                env.pop("NO_COLOR", None)
            env.update(env_extra or {})
            os.execve(BIN, [BIN, "ui", "--usb-path", drive] + (extra or []), env)
        # A window big enough that a message block is not scrolled: this test
        # reads blocks off the screen, the way a person copies one out.
        # With hybrid PQXDH handshakes, a group block carries one initial
        # wrapper per new member, so give the pty room for the whole block.
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 200, 100, 0, 0))
        self.pump(1.0)

    def pump(self, seconds):
        """Drains whatever the child wrote during `seconds`."""
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.buffer.extend(chunk)

    def send(self, data, wait=0.5):
        """Types `data`, streaming large pastes in 1 KiB chunks."""
        payload = data.encode() if isinstance(data, str) else data
        # Hybrid cards are tens of KiB. A single blocking write can fill the
        # pty while the child is also trying to redraw; stream it as a real
        # terminal paste would deliver it.
        for offset in range(0, len(payload), 1024):
            os.write(self.fd, payload[offset:offset + 1024])
            self.pump(0.01)
        self.pump(wait)

    def paste(self, text, wait=0.8):
        """Sends `text` the way a terminal delivers a paste."""
        self.send("\x1b[200~" + text + "\x1b[201~", wait)

    def raw(self):
        """Returns the screen buffer including escape sequences."""
        return self.buffer.decode("utf-8", "replace")

    def text(self):
        """The screen with the escape sequences taken out."""
        return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\x1b[=>]", "",
                      self.raw())

    def expect(self, needle, label):
        """Checks `needle` is on screen, logging `label` either way."""
        if needle in self.text():
            step(label)
        else:
            fail("%s -- never saw %r" % (label, needle))
            print("---- last 2000 characters of the screen ----")
            print(self.text()[-2000:])

    def quit(self):
        """Asks the interface to exit and returns its status."""
        self.send("q", 0.8)
        return self.reap()

    def reap(self):
        """Waits for the child, refusing to hang if it does not leave.

        The pty is left open until the child is reaped: closing it first sends
        a SIGHUP, and the status would be that rather than the program's own.
        """
        deadline = time.time() + 10
        while time.time() < deadline:
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                os.close(self.fd)
                return status
            self.pump(0.2)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        os.close(self.fd)
        fail("the interface did not exit when asked to")
        return -1

    def unlock(self, words):
        """Enters the vault passphrase the way the prompt asks."""
        # The passphrase is entered one word per line and ended with Ctrl-D,
        # exactly as the prompt asks.
        self.send("".join(word + "\n" for word in words) + "\x04", 3.0)


def block_from(text, label):
    """Pulls an armoured block off the screen, the way a person selects one."""
    lines = [line.strip() for line in text.splitlines()]
    begin = end = None
    for i, line in enumerate(lines):
        if line.startswith("-----BEGIN RATCHET %s" % label):
            begin = i
        elif begin is not None and line.startswith("-----END RATCHET %s" % label):
            end = i
            break
    if begin is None or end is None:
        return None
    return "\n".join(lines[begin:end + 1])


def main():
    """Drives a full two-vault conversation through the real interface."""
    work = tempfile.mkdtemp(prefix="ratchet-ui-smoke-")
    alice = os.path.join(work, "alice")
    bob = os.path.join(work, "bob")
    carol = os.path.join(work, "carol")
    os.makedirs(alice)
    os.makedirs(bob)
    os.makedirs(carol)

    try:
        step("setting up two vaults with the command line")
        alice_words = init_vault(alice)
        bob_words = init_vault(bob)
        bob_card = cli(["card", "--usb-path", bob], stdin=feed(bob_words))
        alice_card = cli(["card", "--usb-path", alice], stdin=feed(alice_words))
        # Bob gets Alice through the command line; his side of this test is
        # about reading a message, not about importing a card twice. The card
        # goes in as a file so that stdin is left for the passphrase.
        card_file = os.path.join(work, "alice.card")
        with open(card_file, "w", encoding="utf-8") as handle:
            handle.write(alice_card)
        cli(["add", "--usb-path", bob, "alice", "--card", card_file],
            stdin=feed(bob_words))
        # --confirmed: trust without a terminal, after the fingerprint it just
        # printed; this script never compares it, so the flag is only to keep
        # the test non-interactive. The default path is covered by smoke.sh.
        cli(["trust", "--usb-path", bob, "alice", "--confirmed"],
            stdin=feed(bob_words))

        # Carol only needs a vault and a card: Alice imports her for the group
        # test, and Carol does not have to read the message back.
        carol_words = init_vault(carol)
        carol_card = cli(["card", "--usb-path", carol], stdin=feed(carol_words))

        # --- Alice does everything through the interface --------------------
        step("opening the interface on Alice's drive")
        ui = Ui(alice)
        ui.unlock(alice_words)
        ui.expect("Your fingerprint", "the vault opened")
        ui.expect("no contacts yet", "an empty contact list says so")

        step("changing the passphrase from the interface")
        ui.send("p")
        ui.expect("Vault passphrase", "it shows a new passphrase once")
        ui.send("\n", 3.0)  # acknowledge the write-down; the vault re-encrypts
        ui.expect("passphrase changed", "the change is reported")

        step("adding Bob by pasting his card")
        ui.send("a")
        ui.expect("call this contact", "it asks what to call him")
        ui.send("bob")
        ui.send("\n")
        ui.expect("contact card here", "it asks for the card")
        ui.paste(bob_card)
        ui.expect("characters received", "the paste was counted, not drawn")
        if bob_card.strip().splitlines()[1][:20] in ui.text():
            fail("the pasted card was drawn on the screen")
        ui.send("\x04", 2.0)  # Ctrl-D
        ui.expect("bob added", "Bob is in the contact list")
        ui.expect("NOT verified", "and he is marked unverified")

        step("verifying him")
        ui.send("\n")  # open the contact
        ui.expect("Fingerprint:", "his fingerprint is shown to check")
        ui.send("t", 2.0)
        ui.expect("marked as verified", "he is verified now")

        step("writing him a message")
        ui.send("\n")
        ui.send("w")
        ui.expect("Writing to bob", "the compose screen is up")
        ui.send("ciao bob")
        ui.send("\x04", 4.0)  # Ctrl-D sends
        ui.expect("BEGIN RATCHET MESSAGE", "the encrypted block is shown to copy")

        message = block_from(ui.text(), "MESSAGE")
        if message is None:
            fail("could not read the message block off the screen")
            raise SystemExit(1)
        if "ciao bob" in ui.text().split("BEGIN RATCHET MESSAGE")[0][-400:]:
            fail("the plaintext was still on screen next to the ciphertext")

        ui.send("q", 0.5)   # `q` closes the block, as in any pager

        step("adding Carol for a group message")
        ui.send("a")
        ui.expect("call this contact", "it asks what to call her")
        ui.send("carol")
        ui.send("\n")
        ui.expect("contact card here", "it asks for her card")
        ui.paste(carol_card)
        ui.send("\x04", 2.0)  # Ctrl-D
        ui.expect("carol added", "Carol is in the contact list")
        ui.expect("NOT verified", "and she is marked unverified")

        step("verifying Carol")
        ui.send("\x1b[B")  # move to Carol
        ui.send("\n")
        ui.expect("Fingerprint:", "her fingerprint is shown to check")
        ui.send("t", 2.0)
        ui.expect("marked as verified", "she is verified now")

        step("writing a group message to Bob and Carol")
        ui.send("\x1b")     # back to the contact list, Carol selected
        ui.send(" ")        # mark Carol
        ui.send("\x1b[A")   # move up to Bob
        ui.send(" ")        # mark Bob
        ui.send("g")
        ui.expect("Writing to group", "the group compose screen is up")
        ui.expect("bob", "the first member is named")
        ui.expect("carol", "the second member is named")
        ui.send("ciao gruppo")
        ui.send("\x04", 4.0)  # Ctrl-D sends
        ui.expect("BEGIN RATCHET GROUP", "the encrypted group block is shown")

        group_message = block_from(ui.text(), "GROUP")
        if group_message is None:
            fail("could not read the group block off the screen")
            raise SystemExit(1)
        ui.send("q", 0.5)   # close the block pager
        status = ui.quit()
        if status != 0:
            fail("quitting returned %d" % status)
        else:
            step("quitting exits cleanly")

        # --- Bob reads it, also through the interface ------------------------
        step("opening the interface on Bob's drive")
        ui = Ui(bob)
        ui.unlock(bob_words)
        ui.expect("Your fingerprint", "his vault opened")

        step("reading the message")
        ui.send("r")
        ui.expect("Paste the block here", "it asks for the block")
        ui.paste(message)
        ui.send("\x04", 3.0)
        ui.expect("Message from alice", "the sender is named")
        ui.expect("ciao bob", "the plaintext came back")
        ui.expect("opened a new session", "and it opened the session")

        step("reading the group message")
        ui.send("\x1b", 0.5)  # back to the contact list
        ui.send("r")
        ui.expect("Paste the block here", "it asks for the group block")
        ui.paste(group_message)
        ui.send("\x04", 3.0)
        ui.expect("Group message from alice", "the group sender is named")
        ui.expect("ciao gruppo", "the group plaintext came back")
        ui.send("\x1b", 0.5)  # back to the contact list

        step("the drawing itself")
        if "\x1b[36m" not in ui.raw() and "\x1b[1;36m" not in ui.raw():
            fail("no colour reached the terminal, though it is a tty")

        step("locking clears what was on screen")
        before = len(ui.text())
        ui.send("\x1b", 0.5)  # back to the contact list
        ui.send("l", 1.0)
        after = ui.text()[before:]
        if "ciao bob" in after or "Your fingerprint" in after.split("Locked")[-1]:
            fail("locking left the vault's contents on the screen")
        ui.expect("Locked", "the interface says it is locked")

        raw = ui.raw()
        ui.quit()

        # --- what the interface must never emit -------------------------------
        step("the banner comes back once the vault is closed")
        if "|_| \\_\\" not in ui.text():
            fail("the banner was not drawn on the way back out")

        step("checking what was written to the terminal")
        if "\x1b]" in raw:
            fail("an OSC sequence was emitted -- a window title would show up "
                 "in the taskbar and in any screen share")
        if "\x1b[?1000" in raw or "\x1b[?1006" in raw:
            fail("mouse reporting was enabled")
        if "\x1b[?1049h" not in raw:
            fail("the alternate screen was never entered, so the session would "
                 "be left in the scrollback")

        # --- NO_COLOR is honoured ---------------------------------------------
        step("NO_COLOR turns the colour off")
        plain = Ui(bob, env_extra={"NO_COLOR": "1"})
        plain.pump(0.6)
        if "\x1b[36m" in plain.raw() or "\x1b[1;36m" in plain.raw():
            fail("colour was emitted even though NO_COLOR was set")
        else:
            step("nothing was painted")
        os.kill(plain.pid, 15)
        plain.reap()

    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    if failures:
        print("ui-smoke: %d check(s) failed" % len(failures))
        return 1
    print("ui-smoke: the interface passed every end-to-end check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
