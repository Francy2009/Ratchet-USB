# Ratchet-USB

[English](README.md) · **Italiano**

[![CI](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml/badge.svg)](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml)

Un piccolo strumento a riga di comando per messaggi cifrati senza server.
Cifri sul tuo computer, copi il testo che stampa, lo incolli dove vuoi:
WhatsApp, email, un forum. L'altra persona lo incolla nello strumento per
leggerlo. Quello che passa nel mezzo vede solo roba a caso.

Chiavi, contatti, cronologia — tutto vive su una chiavetta USB o un altro
disco removibile, mai sul computer. Lo strumento trova la chiavetta da solo
quasi sempre; `--usb-path` c'è per quando preferisci non lasciarlo indovinare.

Fase 2, al momento: puoi crearti un'identità, aggiungere contatti, mandare e
ricevere messaggi con cifratura forward-secret. Ancora niente chat di gruppo,
niente stessa identità da due macchine, niente elenco pubblico delle chiavi.
Più giù ne parlo meglio.

Una cosa da dire chiaramente prima di affidarci qualcosa di vero: non ha
avuto una revisione di sicurezza indipendente. L'ho scritto con cura e
testato parecchio, ma non è la stessa cosa di qualcun altro che lo controlla
e non sono io. Se sei il tipo di persona che rischierebbe grosso per un
messaggio letto — un giornalista, un attivista, chiunque — non farne il tuo
unico livello. Usalo accanto a strumenti che sono stati davvero verificati, e
scrivimi se prima vuoi ragionare sulla tua situazione.

## Piattaforme

Girato per davvero solo su **Linux**. `setup.sh` conosce dnf, apt, pacman e
zypper; altrove installa a mano il pacchetto di sviluppo di libsodium, CMake
e un compilatore C++20, e passa `--no-deps`.

**macOS** probabilmente compila — niente qui è specifico di Linux a livello
di API — ma non l'ho provato, quindi non lo prometto. Due cose morderebbero:
il rilevamento della chiavetta legge `/proc/mounts`, che lì non esiste,
quindi ti servirebbe `--usb-path` sempre; e `fsync` su macOS non forza una
scrittura vera su disco senza `F_FULLFSYNC`, il che conta se stacchi la
chiavetta a metà scrittura.

**Windows** non compila, e non è colpa della crittografia — quella è
portabile. È `termios` per spegnere l'eco del terminale, ed `fsync` sia sul
file sia sulla directory per una scrittura durevole, e nessuno dei due esiste
lì. Portare `src/terminal.cpp` e `src/vault.cpp` sono forse un paio di
centinaia di righe, ma entrambi sono codice dove un errore sottile fallisce
in silenzio: sbagli l'eco e la passphrase finisce sullo schermo, sbagli la
scrittura durevole e i vault si corrompono. WSL funziona già oggi, per questo
progetto è semplicemente Linux.

## Per cominciare

```sh
git clone https://github.com/Francy2009/Ratchet-USB.git && cd Ratchet-USB
./setup.sh
```

Installa quello che serve (chiede prima), compila, esegue i test, mette il
binario in `~/.local/bin`. Niente sudo, niente da aggiungere al PATH — c'è
già sulla maggior parte delle distro. Se i test falliscono si ferma prima di
installare niente.

Infili una chiavetta, poi:

```sh
ratchet-usb init
```

```
Found a removable drive to set up:
  /run/media/you/KINGSTON
Use it? [Y/n]
```

Tutto qui. Ogni comando dopo trova la stessa chiavetta da solo:

```sh
ratchet-usb contacts
```

`--prefix /usr/local` installa a livello di sistema (quello sì serve sudo),
`--no-deps` salta l'installazione dei pacchetti. A mano: compilatore C++20,
CMake 3.16+, libsodium (meglio 1.0.19+, vedi la nota su HKDF più avanti).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Il binario finisce in `build/ratchet-usb`.

## Usarlo

```sh
# Alice prepara il suo vault
ratchet-usb init

# Alice stampa la sua "contact card" e la manda a Bob in qualche altro modo
ratchet-usb card

# Bob fa lo stesso setup, poi importa la card di Alice
ratchet-usb add alice --card alice_card.txt
ratchet-usb trust alice        # dopo aver verificato la fingerprint

# Bob scrive ad Alice -- il primo messaggio in assoluto imposta anche le chiavi
ratchet-usb send alice "ciao" > msg.txt
# msg.txt si copia e incolla su WhatsApp/email/quel che è, Alice lo ricopia fuori

# Alice lo legge
ratchet-usb recv "$(cat msg.txt)"
```

## Quale chiavetta usa

Di solito non ci devi pensare. L'ordine è:

1. `--usb-path <dir>`, se lo passi
2. `RATCHET_USB_PATH`
3. un disco removibile montato che ha già un vault sopra
4. te lo chiede e basta

`RATCHET_USB_PATH` torna comodo per tutta una sessione di terminale:

```sh
export RATCHET_USB_PATH=/media/usb
ratchet-usb card
```

Il rilevamento resta stretto apposta — solo dischi che il kernel segna come
removibili o che stanno su USB, mai `/`, e chiede sempre prima di scrivere.
`init` ti crea una directory, ma solo dentro un disco già montato, così un
percorso digitato male non può mettere un vault sul tuo disco vero senza che
tu te ne accorga. Da script o pipe, tutto questo salta — serve
`--usb-path`, perché non c'è nessuno a rispondere alla domanda.

È Linux-only e best-effort, perché vuol dire guardare dentro `/proc/mounts`
e `/sys`. Non trova niente, si torna all'opzione 1 o 2, nessun danno.

Stessa cosa per un alias o un messaggio lasciati fuori dalla riga di
comando — `send` senza messaggio te ne chiede uno, o lo legge da una pipe.

## Comandi

`init` crea una nuova identità, mostra le 12 parole una volta, prepara il
vault. `unlock` lo apre e stampa la fingerprint — e intanto ruota una signed
prekey se ha più di 30 giorni e rimpingua le one-time prekey se ne restano
meno di 5, niente flag per nessuna delle due. `card` stampa la card da
condividere, o solo la fingerprint con `--fingerprint`; `--rotate-spk` e
`--replenish-otpk <n>` fanno la stessa manutenzione su richiesta. `add`
importa la card di qualcuno (un file con `--card`, o stdin) sotto l'alias
che gli dai, controllando la firma. `contacts` elenca chi conosci:
fingerprint, fidato o no, sessione o no. `trust <alias>` segna qualcuno come
verificato — vuol dire che hai controllato la sua fingerprint in un altro
modo. `send <alias> [messaggio]` cifra per qualcuno, impostando prima la
sessione se non c'è ancora. `recv [messaggio]` fa lo stesso dal lato di chi
riceve.

Quelle 12 parole di `init` si vedono una volta e non si salvano da nessuna
parte — sono il backup, e chi le ha può ricostruire la tua identità. Non
tutto, però: contatti e cronologia non ci sono, vedi sotto perché. Hai già
una frase da qualche parte — un vault vecchio, una generata per te da
qualcuno? `init --from-mnemonic` prende le 12 parole invece di generarne di
nuove. In entrambi i casi parti comunque con un vault vuoto.

`--argon2-time` e `--argon2-mem-kb` su `init` regolano quanto costa il
controllo della passphrase. Quello che scegli si salva nel vault stesso,
così si riapre allo stesso modo anche su una macchina più lenta.

## La crittografia

128 bit casuali da `randombytes_buf`, trasformati in 12 parole BIP-39. Il
master seed viene dal far passare quell'entropia per HKDF-SHA256 invece del
solito PBKDF2 di BIP-39 — quindi le 12 parole ricostruiscono l'identità da
sole (la passphrase del vault protegge solo il file, non entra nel seme per
niente), ma sono anche inutili in un wallet Bitcoin, e le parole di un
wallet sono inutili qui. Stessa lista, matematica diversa sotto.

Una sola coppia Ed25519 fa da identità, convertita al volo in X25519 per il
Diffie-Hellman. X3DH ha bisogno della chiave d'identità sia per firmare sia
per fare DH, e X25519 da sola non firma, che di solito è il motivo per cui
la gente finisce con due chiavi d'identità invece di una. Qui ce n'è una
sola — una fingerprint da leggere e controllare, non due.

Le prekey, signed e one-time, sono coppie X25519 casuali e non derivate dal
seme — se una one-time prekey si potesse rigenerare dal seme, ripristinare
dalle 12 parole farebbe risorgere una chiave già bruciata, il che vanifica
del tutto il senso di "usa una volta sola". Il prezzo: prekey, contatti,
chat in corso vivono solo in `vault.bin`. Perdi la chiavetta senza una copia
e le parole ti riprendono l'identità ma non i contatti.

X3DH fa lo scambio di chiavi, stesso handshake di Signal, meno il server di
Signal che distribuisce i bundle — qui il bundle è la card che qualcuno ti
ha dato a mano. `send` lo esegue da solo al primo messaggio, spendendo una
delle one-time prekey del destinatario se ne ha pubblicate (ripiegando su un
handshake a 3 vie un po' più debole quando finiscono — `unlock` e `card
--replenish-otpk` rimpinguano entrambi il gruppo). La prekey che sceglie è
casuale, non la prossima in fila: la stessa card di solito finisce in più
caselle, e sceglierne una fissa vuol dire che chi scrive per primo la
consuma e tutti gli altri trovano una chiave già sparita. La casualità non
toglie la collisione, visto che un gruppo condiviso a mano è comunque
finito, ma smette di essere garantita. Una differenza dallo spec da
segnalare: invece di autenticare solo il messaggio d'apertura con le chiavi
d'identità, entrambe le identità finiscono dentro la primissima chiave di
cifratura, così tutto quello che il ratchet produce dopo resta legato a
entrambe, non solo a come si è aperta la conversazione.

Da lì in poi è un Double Ratchet per ogni messaggio, vicino a come fa
Signal — una catena simmetrica dentro ogni direzione della conversazione, un
passo Diffie-Hellman ogni volta che la direzione cambia, ChaCha20-Poly1305 a
cifrare per davvero. Due cose semplificate rispetto all'originale: la chiave
del messaggio va dritta in ChaCha20-Poly1305 invece di essere spezzata in
pezzi per cifratura/auth/IV (non serve, con un cifrario già autenticato), e
il nonce è casuale per messaggio invece che derivato da un contatore,
qualche byte in più per non doversi preoccupare di bug sui contatori. La
consegna fuori ordine si gestisce con una cache limitata a 1000 chiavi
saltate — un buco vero nella consegna non perde il messaggio, un buco oltre
il limite viene rifiutato subito invece di far masticare a `recv` lavoro
senza fondo per colpa di un'intestazione falsa. Quelle chiavi in cache
scadono dopo una settimana, ormai. È l'unico pezzo del ratchet che non va
avanti da solo: le catene ai due lati continuano ad avanzare, la chiave
saltata resta lì ad aspettare. Senza scadenza, un vault rubato aprirebbe
comunque messaggi vecchi di mesi, e le chiavi lasciate indietro da catene
ormai abbandonate continuerebbero a mangiarsi quel budget di 1000 finché
nessun nuovo buco sarebbe più tollerabile. `recv` spazza quelle scadute
prima di fare altro, `unlock` spazza ogni sessione, quindi anche un vault
che apri e basta resta pulito. Il prezzo: un messaggio in ritardo di più di
una settimana non si decifra più.

Niente di tutto questo dimostra che una chiave d'identità appartenga a chi
pensi — quella parte tocca a te. Importare una card controlla la firma
sulla signed prekey, e ogni messaggio che ricevi dopo è legato all'identità
del mittente attraverso l'handshake, ma `add` ti dà comunque solo una
fingerprint da andare a verificare. `trust` è te che registri di averlo
fatto — al telefono, di persona, da qualche parte che non è la stessa chat
da cui è arrivata la card. `send` e `recv` ti fanno notare un contatto non
verificato ma non ti fermano.

Le chiavi segrete vivono in `SecureBytes` / `SecureString` / `SecureBuffer`
— bloccate in memoria dove il sistema lo permette, azzerate quando non
servono più, e spostabili ma non copiabili, così una copia non può esistere
di nascosto da qualche parte che hai dimenticato. La passphrase diventa la
chiave del vault via Argon2id (256 MiB, 3 passate di default), e il file è
sigillato con ChaCha20-Poly1305.

Da sapere: la build usa `crypto_kdf_hkdf_sha256_*` nativa di libsodium
quando c'è (1.0.19+), e ripiega su una piccola implementazione propria
dell'RFC 5869 altrimenti. Entrambe sono controllate contro i vettori
dell'RFC e producono gli stessi byte, quindi i vault si spostano tra le due
senza problemi.

## Struttura del file vault

```
offset  size  campo
0       4     magic "RCHT"
4       1     versione (2)
5       16    salt Argon2id
21      4     costo tempo Argon2id     (uint32, little-endian)
25      4     memoria Argon2id in KiB  (uint32, little-endian)
29      12    nonce ChaCha20-Poly1305
41      N     dati cifrati: seme, prekey, contatti, sessioni
41+N    16    tag di autenticazione Poly1305
```

Scritta campo per campo invece che riversata come struct, così le
decisioni di padding del tuo compilatore non finiscono nel formato del
file. L'intestazione è dato autenticato sulla cifratura, non testo in
chiaro lì accanto, quindi toccare salt, nonce o valori di costo rompe la
decifratura invece di derivare in silenzio una chiave diversa — e una
passphrase sbagliata dà esattamente lo stesso errore di un file manomesso,
di proposito. I valori di costo vengono controllati prima di arrivare ad
Argon2 (tempo 1–64, memoria 8 KiB–4 GiB), visto che si rileggono da un file
che in teoria potrebbe essere stato toccato. C'era un formato più vecchio,
solo un blocco fisso da 64 byte con seme e chiave — non l'ha mai usato
niente di pubblicato, quindi non c'è nessuna migrazione a cui pensare.

Card e messaggi arrivano entrambi avvolti in
`-----BEGIN RATCHET <ETICHETTA>-----`, base64, 64 caratteri a riga, spazi in
più ignorati quando li rileggi — così un'app di chat che reimpagina il tuo
paragrafo non rompe il blocco. Un messaggio porta un hash breve
dell'identità del mittente (così `recv` sa a quale conversazione appartiene
senza che glielo si dica), l'intestazione del ratchet, e, solo nel
messaggio che apre una conversazione, i dati dell'handshake X3DH.

## Struttura del progetto

`include/ratchet/` per gli header pubblici, `src/` per l'implementazione e
la lista di parole BIP-39, `test/` per i test unitari — nessun framework,
solo controlli scritti a mano.

## Come viene verificata la crittografia

Un test di andata e ritorno qui non dimostra granché. Cifrare e decifrare
con lo stesso codice dimostra solo che il codice è d'accordo con sé stesso,
e codice sbagliato in modo coerente è d'accordo con sé stesso alla
perfezione. Scambia le due costanti HMAC nel passo della chain key, o dai a
HKDF l'output DH come salt invece che come input, e i messaggi continuano a
fare andata e ritorno senza problemi. Il risultato sarebbe un ratchet che
funziona e non è quello descritto dallo spec.

Per questo lo schema delle chiavi viene controllato anche contro vettori
che vengono da tutt'altra parte. `test/vectors/reference.py` sono le
stesse derivazioni scritte una seconda volta, in Python, partendo dalle
specifiche e non da `src/ratchet.cpp`, con nient'altro che la libreria
standard. Le sue primitive sono ancorate prima a vettori pubblicati (RFC
7748 per X25519, RFC 5869 per HKDF-SHA256), e il suo output è congelato in
`test/vectors/vectors.hpp`, che il lato C++ deve riprodurre byte per byte.
La CI rigenera quell'header a ogni push e fallisce su qualunque differenza,
così i due non possono scivolare in un accordo silenzioso — un bug
dovrebbe presentarsi due volte, in modo indipendente, nella stessa
direzione.

Questo è conformità, non interoperabilità — questo strumento non parla il
formato di libsignal e non c'è modo di testarlo contro quello vero (le
divergenze citate sopra ci pensano: chiave del messaggio diretta come
chiave AEAD, nonce casuale nell'envelope, una info string della root key
che è tutta di questo progetto).

`test/smoke.sh` a parte, porta il binario vero attraverso una conversazione
intera — due vault, uno scambio di card, handshake, risposta, messaggi
fuori ordine, uno manomesso, una passphrase sbagliata — perché nessuno dei
test unitari tocca il parsing degli argomenti, l'I/O sui file, o la
codifica del blocco da copiare e incollare.

La CI esegue tutto a ogni push: GCC e Clang, Debug e Release, warning come
errori, ASan, UBSan, Valgrind, clang-tidy. Un job compila una libsodium più
recente da sorgente, perché Ubuntu distribuisce la 1.0.18 e l'HKDF di
riserva altrimenti non verrebbe mai davvero compilato, figurarsi eseguito,
in CI. Controlla anche che l'HKDF della libsodium nuova sia stato scelto
davvero, perché un bug nel rilevamento ripiegherebbe in silenzio e il badge
resterebbe verde lo stesso.

## Da cosa protegge, e da cosa no

Da chi prende la tua chiavetta ma non la passphrase. Da chiunque osservi il
canale su cui incolli i messaggi. Una chiave di sessione trapelata non
espone né i messaggi passati né quelli futuri, grazie a forward secrecy e
post-compromise security nel ratchet.

Da cosa non aiuta: un computer compromesso — un keylogger vede la
passphrase e tutto il resto, cifratura o no. Qualcuno che legge le tue 12
parole o prende `vault.bin` direttamente. Fidarsi di un contatto senza
averne davvero controllato la fingerprint. E il canale su cui incolli vede
comunque passare il testo cifrato, più i tempi — solo non può leggerne il
contenuto.

## Cosa manca ancora

Chat di gruppo, una identità su più dispositivi, key transparency. Tutto
lavoro vero, niente da fare a metà, quindi aspetta.

## Licenza

MIT, vedi [LICENSE](LICENSE). La lista di parole BIP-39 e libsodium sono di
terze parti e citate in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
