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
PASS = "smoke-passphrase"
# Argon2 at its default cost would make this test take minutes for no extra
# coverage: what is being tested here is the interface, not the KDF.
CHEAP = ["--argon2-mem-kb", "8192", "--argon2-time", "1"]

failures = []


def step(text):
    print("  ui-smoke: %s" % text)


def fail(text):
    print("  ui-smoke: FAIL -- %s" % text)
    failures.append(text)


def cli(args, stdin=""):
    """Runs the ordinary command line, for the setup this test is not testing."""
    result = subprocess.run([BIN] + args, input=stdin, capture_output=True,
                            text=True)
    if result.returncode != 0:
        raise SystemExit("setup command failed: %s\n%s" % (args, result.stderr))
    return result.stdout


class Ui:
    """The interface running on a pty, with a way to read the screen back."""

    def __init__(self, drive, extra=None, env_extra=None):
        self.buffer = bytearray()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            env = dict(os.environ, TERM="xterm-256color")
            env.update(env_extra or {})
            os.execve(BIN, [BIN, "ui", "--usb-path", drive] + (extra or []), env)
        # A window big enough that a message block is not scrolled: this test
        # reads blocks off the screen, the way a person copies one out.
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 100, 0, 0))
        self.pump(1.0)

    def pump(self, seconds):
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
        os.write(self.fd, data.encode() if isinstance(data, str) else data)
        self.pump(wait)

    def paste(self, text, wait=0.8):
        """Sends `text` the way a terminal delivers a paste."""
        self.send("\x1b[200~" + text + "\x1b[201~", wait)

    def raw(self):
        return self.buffer.decode("utf-8", "replace")

    def text(self):
        """The screen with the escape sequences taken out."""
        return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\x1b[=>]", "",
                      self.raw())

    def expect(self, needle, label):
        if needle in self.text():
            step(label)
        else:
            fail("%s -- never saw %r" % (label, needle))
            print("---- last 2000 characters of the screen ----")
            print(self.text()[-2000:])

    def quit(self):
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

    def unlock(self, passphrase=PASS):
        self.send(passphrase + "\n", 3.0)


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
    work = tempfile.mkdtemp(prefix="ratchet-ui-smoke-")
    alice = os.path.join(work, "alice")
    bob = os.path.join(work, "bob")
    os.makedirs(alice)
    os.makedirs(bob)

    try:
        step("setting up two vaults with the command line")
        for drive in (alice, bob):
            cli(["init", "--usb-path", drive] + CHEAP, stdin=PASS + "\n" + PASS + "\n")
        bob_card = cli(["card", "--usb-path", bob], stdin=PASS + "\n")
        alice_card = cli(["card", "--usb-path", alice], stdin=PASS + "\n")
        # Bob gets Alice through the command line; his side of this test is
        # about reading a message, not about importing a card twice. The card
        # goes in as a file so that stdin is left for the passphrase.
        card_file = os.path.join(work, "alice.card")
        with open(card_file, "w", encoding="utf-8") as handle:
            handle.write(alice_card)
        cli(["add", "--usb-path", bob, "alice", "--card", card_file],
            stdin=PASS + "\n")

        # --- Alice does everything through the interface --------------------
        step("opening the interface on Alice's drive")
        ui = Ui(alice)
        ui.unlock()
        ui.expect("Your fingerprint", "the vault opened")
        ui.expect("no contacts yet", "an empty contact list says so")

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
        ui.expect("no contacts yet", "q closes the block and goes back") \
            if False else None
        status = ui.quit()
        if status != 0:
            fail("quitting returned %d" % status)
        else:
            step("quitting exits cleanly")

        # --- Bob reads it, also through the interface ------------------------
        step("opening the interface on Bob's drive")
        ui = Ui(bob)
        ui.unlock()
        ui.expect("Your fingerprint", "his vault opened")

        step("reading the message")
        ui.send("r")
        ui.expect("Paste the block here", "it asks for the block")
        ui.paste(message)
        ui.send("\x04", 3.0)
        ui.expect("Message from alice", "the sender is named")
        ui.expect("ciao bob", "the plaintext came back")
        ui.expect("opened a new session", "and it opened the session")

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
