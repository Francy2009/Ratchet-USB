#ifndef RATCHET_I18N_HPP
#define RATCHET_I18N_HPP

#include <cstddef>
#include <cstdint>
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
  X(PressPForPath, "Press p to type in the path of one.",                      \
    "Premi p per scrivere il percorso di una.")                    \
  X(KeysDrive, "up/down list   left/right menu   Enter choose",                \
    "su/giu' elenco   sinistra/destra menu   Invio scegli")                      \
  /* a drive with no vault on it */                                            \
  X(NoVaultHere, "There is no vault on this drive.",                           \
    "Su questa unita' non c'e' nessun vault.")                                  \
  X(SetupNew, "n   set up a new identity here",                                \
    "n   crea qui una nuova identita'")                                         \
  X(SetupRestore, "r   restore an identity from its 12 recovery words",        \
    "r   ripristina un'identita' dalle sue 12 parole")                          \
  X(KeysSetup, "left/right menu   Enter choose   Esc back",                     \
    "sinistra/destra menu   Invio scegli   Esc indietro")                        \
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
  X(KeysHome, "up/down contacts   left/right menu   Enter choose",             \
    "su/giu' contatti   sinistra/destra menu   Invio scegli")                    \
  /* one contact */                                                            \
  X(Fingerprint, "Fingerprint:", "Impronta:")                                  \
  X(VerifyHint,                                                                \
    "Read this out to them in person or by phone. If it matches, press t.",    \
    "Leggigliela di persona o al telefono. Se combacia, premi t.")              \
  X(KeysContact, "left/right menu   Enter choose   Esc back",                   \
    "sinistra/destra menu   Invio scegli   Esc indietro")                        \
  /* writing a message */                                                      \
  X(WritingTo, "Writing to", "Stai scrivendo a")                               \
  X(ComposeHint, "Type your message. Enter starts a new line.",                \
    "Scrivi il messaggio. Invio va a capo.")                                    \
  X(KeysCompose, "Ctrl-D send   Esc cancel   Ctrl-C quit",                      \
    "Ctrl-D invia   Esc annulla   Ctrl-C esci")      \
  /* showing a block to copy */                                                \
  X(CopyBlock, "Select all of this and send it however you like:",             \
    "Seleziona tutto questo e mandalo come preferisci:")                        \
  X(YourCard, "Your contact card", "La tua card")                              \
  X(MessageBlock, "Your encrypted message", "Il tuo messaggio cifrato")         \
  X(KeysBlock, "up/down scroll   Esc or q back",                               \
    "su/giu' scorri   Esc o q indietro")    \
  /* pasting something in */                                                    \
  X(PasteBlock, "Paste the block here, then press Ctrl-D.",                    \
    "Incolla qui il blocco, poi premi Ctrl-D.")                                 \
  X(PasteCard, "Paste their contact card here, then press Ctrl-D.",            \
    "Incolla qui la sua card, poi premi Ctrl-D.")                               \
  X(CharsReceived, "characters received", "caratteri ricevuti")                \
  X(NothingPasted, "nothing pasted yet", "non hai ancora incollato niente")     \
  X(KeysPaste, "Ctrl-D confirm   Esc cancel   Ctrl-C quit",                     \
    "Ctrl-D conferma   Esc annulla   Ctrl-C esci")  \
  /* naming a new contact */                                                   \
  X(AliasPrompt, "What do you want to call this contact?",                     \
    "Come vuoi chiamare questo contatto?")                                      \
  X(KeysText, "Enter confirm   Esc back   Ctrl-C quit",                        \
    "Invio conferma   Esc indietro   Ctrl-C esci")     \
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
  X(PressEnter, "Press ENTER to carry on.", "Premi INVIO per andare avanti.")   \
  /* The menu. Every entry stands for a key that already worked on its own, so \
     the two can never mean different things: choosing an entry presses the    \
     key. The letters keep working for anyone who has learnt them. */          \
  X(MenuOpen, "Open", "Apri")                                                  \
  X(MenuAdd, "Add contact", "Aggiungi")                          \
  X(MenuCard, "My card", "La mia card")                                        \
  X(MenuRead, "Read message", "Leggi")                          \
  X(MenuWrite, "Write", "Scrivi")                                              \
  X(MenuVerify, "Mark as verified", "Segna verificato")                        \
  X(MenuLock, "Lock", "Blocca")                                                \
  X(MenuQuit, "Quit", "Esci")                                                  \
  X(MenuUseDrive, "Use this drive", "Usa questa unita'")                        \
  X(MenuTypePath, "Type a path", "Scrivi un percorso")                         \
  X(MenuNewIdentity, "Set up a new identity", "Crea una nuova identita'")       \
  X(MenuRestore, "Restore from words", "Ripristina dalle parole")              \
  X(MenuBack, "Back", "Indietro")   \
  /* the prompts that run outside the frame */                                 \
  X(PassphrasePrompt, "Vault passphrase: ", "Passphrase del vault: ")          \
  X(PassphraseNew, "Choose a passphrase for the vault: ",                      \
    "Scegli una passphrase per il vault: ")                                     \
  X(PassphraseAgain, "Type it again: ", "Riscrivila: ")                        \
  X(RecoveryWordsPrompt, "The 12 recovery words, separated by spaces: ",       \
    "Le 12 parole di recupero, separate da spazi: ")                            \
  X(WroteDownWords, "Press ENTER once you have written them down... ",         \
    "Premi INVIO quando le hai scritte... ")                                    \
  X(SettingUp, "Setting up a new identity on", "Sto creando una nuova identita' su") \
  X(RestoringIdentity, "Restoring an identity from its recovery words on",     \
    "Sto ripristinando un'identita' dalle sue parole su")                       \
  X(RestoreNote,                                                               \
    "The words rebuild the identity only: this vault starts with no contacts " \
    "and no chat history, because those only ever lived in the old vault.bin.",\
    "Le parole ricostruiscono solo l'identita': questo vault parte senza "      \
    "contatti e senza cronologia, perche' quelli stavano solo nel vecchio "     \
    "vault.bin.")                                                               \
  /* The mnemonic screen. The English column is the exact text `init` has     \
     always printed, so the command line keeps producing the same bytes while \
     the interface can say it in the reader's language -- and this is the one \
     screen where being understood matters most: it is the only time the      \
     words are ever shown. */                                                 \
  X(RecoveryHeading, "Recovery phrase (12 words, BIP-39):",                   \
    "Frase di recupero (12 parole, BIP-39):")                                  \
  X(RecoveryNote,                                                              \
    "Write these words down on paper, in order. They are the only\n"           \
    "way to recover the seed and identity if the drive is lost; a\n"           \
    "vault restored from them alone starts with no prekeys, no\n"              \
    "contacts and no sessions -- those live only in vault.bin.",               \
    "Scrivi queste parole su un foglio, in ordine. Sono l'unico modo\n"        \
    "per recuperare il seme e l'identita' se perdi l'unita'; un vault\n"       \
    "ricostruito solo da queste parte senza prekey, senza contatti e\n"        \
    "senza sessioni -- quelli stanno solo dentro vault.bin.")                  \
  X(VaultCreated, "Vault created. Unlocking it now.",                          \
    "Vault creato. Ora lo apro.")                                               \
  X(DerivingKey, "Deriving the vault key with Argon2id...",                    \
    "Sto derivando la chiave del vault con Argon2id...")

enum class Str : std::uint8_t {
#define RATCHET_I18N_ENUM(id, en, it) id,
  RATCHET_I18N_STRINGS(RATCHET_I18N_ENUM)
#undef RATCHET_I18N_ENUM
      Count
};

enum class Lang : std::uint8_t { En, It };

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
