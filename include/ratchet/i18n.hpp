#ifndef RATCHET_I18N_HPP
#define RATCHET_I18N_HPP

#include <cstddef>
#include <string_view>

// The text the terminal interface shows, in English and Italian.
//
// Only the interface is translated. Error messages from the core, the usage
// text, the README and SECURITY.md stay in English: they are the project's
// public face and its wire contract, and translating them would double the
// amount of text that has to be reviewed for accuracy without helping the
// person the interface exists for.
//
// The two languages are declared side by side in one list, so a string added
// in one and forgotten in the other does not compile. There is no message
// catalogue and no file to load: the strings are in the binary, because a
// translation file would be state on the host disk, and this program keeps
// none.
namespace ratchet::i18n {

// id, English, Italian
#define RATCHET_I18N_STRINGS(X)                                                \
  X(Subtitle, "encrypted messages, no server",                                 \
    "messaggi cifrati, senza server")                                          \
  X(ErrorPrefix, "error", "errore")                                            \
  /* choosing a drive */                                                       \
  X(ChooseDrive, "Choose the drive to use:", "Scegli l'unita' da usare:")       \
  X(NoDrivesFound, "No removable drive was found.",                            \
    "Non e' stata trovata nessuna unita' rimovibile.")                          \
  X(DriveHasVault, "vault", "vault")                                           \
  X(DriveEmpty, "empty", "vuota")                                              \
  X(TypePath, "Path of the drive:", "Percorso dell'unita':")                    \
  X(KeysDrive, "up/down choose   Enter use   p type a path   q quit",          \
    "su/giu' scegli   Invio usa   p scrivi un percorso   q esci")               \
  /* a drive with no vault on it */                                            \
  X(NoVaultHere, "There is no vault on this drive.",                           \
    "Su questa unita' non c'e' nessun vault.")                                  \
  X(SetupNew, "n   set up a new identity here",                                \
    "n   crea qui una nuova identita'")                                         \
  X(SetupRestore, "r   restore an identity from its 12 recovery words",        \
    "r   ripristina un'identita' dalle sue 12 parole")                          \
  X(KeysSetup, "n new   r restore   Esc back", "n nuova   r ripristina   Esc indietro") \
  /* the contact list */                                                       \
  X(YourFingerprint, "Your fingerprint:", "La tua impronta:")                  \
  X(Contacts, "Contacts:", "Contatti:")                                        \
  X(NoContacts, "You have no contacts yet.", "Non hai ancora nessun contatto.") \
  X(NoContactsHint, "Press a to add one, once somebody has given you a card.", \
    "Premi a per aggiungerne uno, quando qualcuno ti ha dato una card.")        \
  X(Verified, "verified", "verificato")                                        \
  X(Unverified, "NOT verified", "NON verificato")                              \
  X(HasSession, "session open", "sessione aperta")                             \
  X(NoSession, "no session yet", "nessuna sessione")                           \
  X(KeysHome,                                                                  \
    "up/down  Enter open  a add  c card  r read  l lock  q quit",              \
    "su/giu'  Invio apri  a aggiungi  c card  r leggi  l blocca  q esci")      \
  /* one contact */                                                            \
  X(Fingerprint, "Fingerprint:", "Impronta:")                                  \
  X(VerifyHint,                                                                \
    "Read this out to them in person or by phone. If it matches, press t.",    \
    "Leggigliela di persona o al telefono. Se combacia, premi t.")              \
  X(KeysContact, "w write   t mark as verified   Esc back",                    \
    "w scrivi   t segna come verificato   Esc indietro")                        \
  /* writing a message */                                                      \
  X(WritingTo, "Writing to", "Stai scrivendo a")                               \
  X(ComposeHint, "Type your message. Enter starts a new line.",                \
    "Scrivi il messaggio. Invio va a capo.")                                    \
  X(KeysCompose, "Ctrl-D send   Esc cancel", "Ctrl-D invia   Esc annulla")      \
  /* showing a block to copy */                                                \
  X(CopyBlock, "Select all of this and send it however you like:",             \
    "Seleziona tutto questo e mandalo come preferisci:")                        \
  X(YourCard, "Your contact card", "La tua card")                              \
  X(MessageBlock, "Your encrypted message", "Il tuo messaggio cifrato")         \
  X(KeysBlock, "up/down scroll   Esc back", "su/giu' scorri   Esc indietro")    \
  /* pasting something in */                                                    \
  X(PasteBlock, "Paste the block here, then press Ctrl-D.",                    \
    "Incolla qui il blocco, poi premi Ctrl-D.")                                 \
  X(PasteCard, "Paste their contact card here, then press Ctrl-D.",            \
    "Incolla qui la sua card, poi premi Ctrl-D.")                               \
  X(CharsReceived, "characters received", "caratteri ricevuti")                \
  X(NothingPasted, "nothing pasted yet", "non hai ancora incollato niente")     \
  X(KeysPaste, "Ctrl-D confirm   Esc cancel", "Ctrl-D conferma   Esc annulla")  \
  /* naming a new contact */                                                   \
  X(AliasPrompt, "What do you want to call this contact?",                     \
    "Come vuoi chiamare questo contatto?")                                      \
  X(KeysText, "Enter confirm   Esc cancel", "Invio conferma   Esc annulla")     \
  /* a message that came in */                                                 \
  X(MessageFrom, "Message from", "Messaggio da")                               \
  X(SessionOpened, "This message opened a new session.",                       \
    "Questo messaggio ha aperto una nuova sessione.")                           \
  X(WarnUnverified,                                                            \
    "This contact is NOT verified: you have not checked their fingerprint.",   \
    "Questo contatto NON e' verificato: non hai ancora controllato la sua impronta.") \
  /* status lines */                                                           \
  X(Deriving, "Opening the vault with Argon2id, this takes a moment...",       \
    "Sto aprendo il vault con Argon2id, ci vuole un attimo...")                 \
  X(WrongPassphrase, "Wrong passphrase, or the file has been altered.",        \
    "Passphrase sbagliata, oppure il file e' stato modificato.")                \
  X(Locked, "Locked. The vault is closed and the keys are gone from memory.",  \
    "Bloccato. Il vault e' chiuso e le chiavi non sono piu' in memoria.")        \
  X(IdleLocked, "Locked automatically after being left idle.",                 \
    "Bloccato da solo dopo un po' di inattivita'.")                             \
  X(ContactAdded, "added. Check their fingerprint before you trust it.",       \
    "aggiunto. Controlla la sua impronta prima di fidarti.")                    \
  X(MarkedVerified, "marked as verified.", "segnato come verificato.")          \
  X(MessageReady, "Message encrypted.", "Messaggio cifrato.")                   \
  X(EmptyMessage, "An empty message is not sent.",                             \
    "Un messaggio vuoto non viene inviato.")                                    \
  X(NothingToRead, "Nothing was pasted, so there is nothing to read.",         \
    "Non hai incollato niente, quindi non c'e' niente da leggere.")             \
  X(HostDiskWarning,                                                           \
    "warning: this looks like the computer's own disk, not a removable drive.",\
    "attenzione: sembra il disco del computer, non un'unita' rimovibile.")      \
  X(PressEnter, "Press ENTER to carry on.", "Premi INVIO per andare avanti.")

enum class Str : std::size_t {
#define RATCHET_I18N_ENUM(id, en, it) id,
  RATCHET_I18N_STRINGS(RATCHET_I18N_ENUM)
#undef RATCHET_I18N_ENUM
      Count
};

enum class Lang { En, It };

// The string for `id` in `lang`.
std::string_view t(Lang lang, Str id);

// Picks a language from an explicit choice, falling back to the environment.
// `choice` is what --lang carried, empty when it was not given; anything other
// than "it" or "en" is an error the caller reports.
//
// Without a choice, LANG and LC_ALL are read -- and only compared against a
// prefix, never parsed. An Italian locale gets Italian; everything else gets
// English, which is what the rest of the project speaks.
Lang detect(std::string_view choice);

// Whether `choice` names a language. Used by the argument parser so a typo is
// refused at the command line rather than silently falling back.
bool is_valid_choice(std::string_view choice);

}  // namespace ratchet::i18n

#endif  // RATCHET_I18N_HPP
