# Ratchet-USB

[English](README.md) · **Italiano**

[![CI](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml/badge.svg)](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml)

Un piccolo strumento a riga di comando per mandarsi messaggi cifrati senza
bisogno di un server. Cifri il messaggio sul tuo computer, copi il testo che
ne esce e lo incolli dove ti pare: WhatsApp, email, un forum, quello che
vuoi. L'altra persona lo ricopia dentro lo strumento per leggerlo. L'app che
trasporta il testo nel mezzo vede solo caratteri a caso, mai il messaggio
vero.

Tutto quello che conta, le tue chiavi, i tuoi contatti, la cronologia delle
chat, sta su una chiavetta USB o su un qualunque disco removibile. Lo
strumento non scrive mai niente sul computer su cui gira. La chiavetta la
trova da solo quando può, e puoi sempre indicarla esplicitamente con
`--usb-path`.

A che punto siamo: fase 2. Puoi generare un'identità, aggiungere contatti,
mandare e ricevere messaggi con una cifratura forward-secret vera. Mancano
ancora le chat di gruppo, l'uso della stessa identità da più dispositivi e
qualsiasi forma di elenco pubblico delle chiavi (ne parlo più sotto, in
"Da cosa protegge e da cosa no").

Prima di affidarci qualcosa di serio: questo progetto non ha ancora avuto una
revisione di sicurezza indipendente. È scritto con attenzione ed è testato, ma
"scritto con attenzione da una persona sola" e "controllato da crittografi
esterni" non sono la stessa garanzia. Se sei un giornalista, un attivista o
chiunque altro rischi conseguenze reali se un messaggio venisse letto, per
favore non farne la tua unica difesa. Trattalo come un livello in più, continua
a usare accanto strumenti già revisionati, e scrivimi se prima di fidartene
vuoi ragionare sulla tua situazione specifica.

## Su quali sistemi gira

**Linux**, ed è l'unico su cui sia stato davvero eseguito. `setup.sh` conosce
dnf, apt, pacman e zypper; su qualunque altra distribuzione installa a mano il
pacchetto di sviluppo di libsodium, CMake e un compilatore C++20, poi passa
`--no-deps`.

**macOS** dovrebbe compilare (tutte le chiamate di sistema usate qui esistono
anche lì, e libsodium lo supporta) ma nessuno ha provato, quindi consideralo
non verificato. Due cose andrebbero peggio: il rilevamento della chiavetta
legge `/proc/mounts` e quindi non troverebbe niente, lasciandoti a passare
`--usb-path`; e su macOS `fsync` non forza una scrittura fisica senza
`F_FULLFSYNC`, il che indebolisce la garanzia che il vault sopravviva alla
chiavetta staccata a metà scrittura.

**Windows** non compila. Non per la crittografia, che è portabile, ma per
quello che ci sta intorno: spegnere l'eco del terminale per la passphrase passa
da `termios`, e il vault viene scritto in modo durevole con `fsync` sia sul
file sia sulla sua directory, e Windows non ha un equivalente né dell'uno né
degli altri. Portarlo sono qualche centinaio di righe in `src/terminal.cpp` e
`src/vault.cpp`, ed entrambi sono posti dove un errore sottile fallisce in
silenzio invece che rumorosamente: un'eco non davvero spenta ti mette la
passphrase sullo schermo, e una scrittura durevole portata male corrompe i
vault. **WSL funziona già oggi** ed è Linux a tutti gli effetti, per quanto
riguarda questo progetto.

## Per cominciare

Due comandi, una volta sola:

```sh
git clone https://github.com/Francy2009/Ratchet-USB.git && cd Ratchet-USB
./setup.sh
```

`setup.sh` installa i pacchetti che servono (chiedendo prima), compila, esegue
i test e mette il binario in `~/.local/bin`, che sulla maggior parte delle
distribuzioni attuali è già nel PATH. Niente `sudo` per l'installazione vera e
propria, e niente `export PATH` dopo: `ratchet-usb` diventa un comando
qualunque. Se i test falliscono si ferma prima di installare qualsiasi cosa.

Poi infila una chiavetta USB e:

```sh
ratchet-usb init
```

Il setup è tutto qui. `init` cerca un disco removibile montato e chiede prima
di usarlo:

```
Found a removable drive to set up:
  /run/media/you/KINGSTON
Use it? [Y/n]
```

Da quel momento ogni altro comando trova la chiavetta da solo, quindi non c'è
niente da digitare e niente da ricordare:

```sh
ratchet-usb contacts
```

`./setup.sh --prefix /usr/local` installa a livello di sistema (quello sì che
richiede sudo), e `--no-deps` salta il passaggio dei pacchetti. Per compilare a
mano invece che con lo script servono un compilatore C++20, CMake 3.16 o più
recente e libsodium (meglio 1.0.19 o successive, vedi la nota su HKDF più
avanti), che è l'unica libreria da cui questo progetto dipende:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Il binario finisce in `build/ratchet-usb`.

## Come si usa

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

## Come gli dici quale chiavetta usare

Quasi sempre non serve. Ogni comando capisce da solo dov'è il vault, in
quest'ordine:

1. `--usb-path <dir>`, se lo passi
2. la variabile d'ambiente `RATCHET_USB_PATH`
3. un disco removibile montato che contenga già un vault, che ti viene proposto
4. se non c'è nient'altro, te lo chiede e basta

Quindi `--usb-path` c'è sempre quando vuoi essere esplicito, e impostare
`RATCHET_USB_PATH` una volta per sessione funziona ancora:

```sh
export RATCHET_USB_PATH=/media/usb
ratchet-usb card
```

Il rilevamento automatico è volutamente stretto. Considera solo i dischi che il
kernel segnala come removibili, o che stanno su un bus USB; non propone mai
`/`; e chiede sempre prima di scrivere. `init` una directory te la crea, ma
solo dentro un disco removibile già montato, così un percorso digitato male non
può mettere di nascosto un vault sul disco del computer. Tutto ciò che non è
interattivo (uno script, una pipe) salta il rilevamento e le domande e pretende
`--usb-path`, perché non c'è nessuno lì a confermare.

Rilevare i dischi vuol dire leggere `/proc/mounts` e `/sys`, quindi funziona
solo su Linux ed è best-effort per natura. Quando non trova niente si torna al
caso 1 o 2, e non si è perso nulla.

Lo stesso vale per l'alias di un contatto o per un messaggio omesso dalla riga
di comando: `send` senza messaggio, per esempio, te lo chiede (oppure lo legge
da una pipe).

## Cosa fa ogni comando

`init` crea una nuova identità, ti mostra una volta sola la frase di recupero
da 12 parole e prepara il vault. `unlock` apre il vault e mostra la tua
fingerprint, ma per strada controlla anche le prekey: una signed prekey più
vecchia di 30 giorni viene ruotata, e se restano meno di 5 one-time prekey ne
genera 10 nuove, entrambe le cose in automatico, senza flag. `card` stampa la
tua contact card da condividere, oppure solo la fingerprint con
`--fingerprint`; `--rotate-spk` e `--replenish-otpk <n>` rinfrescano quelle
chiavi su richiesta, oltre alla manutenzione automatica che `unlock` fa già di
suo. `add` importa la card di qualcuno, da un file con `--card` o da stdin,
sotto l'alias che gli dai, e verifica che la firma sia valida. `contacts`
elenca chi conosci, la loro fingerprint, se li hai segnati come fidati e se hai
già una sessione aperta con loro. `trust <alias>` segna un contatto come
verificato, cioè dice che hai controllato la sua fingerprint attraverso un
altro canale. `send <alias> [messaggio]` cifra un messaggio per qualcuno,
impostando la sessione da solo se è la prima volta. `recv [messaggio]` decifra
un messaggio che ti hanno mandato, anche qui impostando la sessione da solo se
è il primo che arriva.

`init` ti mostra le 12 parole di recupero esattamente una volta e non le salva
da nessuna parte; sono il tuo backup, e chi le ha può ricostruire la tua
identità. Non fanno però il backup di tutto, vedi sotto. Se una frase di
recupero ce l'hai già, da un vault precedente o generata da qualcun altro per
te, `init --from-mnemonic` chiede le 12 parole invece di generarne di nuove e
ricostruisce l'identità da quelle; parti comunque con un vault nuovo e vuoto,
perché contatti e cronologia nelle parole non ci sono mai stati.

Puoi anche regolare quanto costa il controllo della passphrase con
`--argon2-time` e `--argon2-mem-kb` quando esegui `init`. I valori che scegli
vengono salvati dentro il vault e riusati tutte le volte dopo, così un vault
creato su un portatile veloce si apre lo stesso su una macchina più lenta, e il
costo non cambia di nascosto.

## La crittografia, in parole povere

Il seme parte da 128 bit casuali presi da `randombytes_buf`, codificati in una
frase di backup BIP-39 da 12 parole. Il master seed vero e proprio esce dal
passare quell'entropia grezza attraverso HKDF-SHA256, non attraverso il solito
PBKDF2 di BIP-39. Ne discendono due cose: le 12 parole da sole bastano a
ricostruire il seme e la tua identità a lungo termine (la passphrase del vault
protegge solo il file sulla chiavetta, non entra nel seme), e queste parole non
funzioneranno in un wallet Bitcoin, né le parole di un wallet funzioneranno
qui. Stessa lista di parole, matematica diversa sotto.

La tua identità è una sola coppia di chiavi Ed25519 derivata da quel seme,
convertita al volo in X25519 ogni volta che serve uno scambio Diffie-Hellman.
X3DH ha bisogno della chiave d'identità per due lavori diversi, firmare la
prekey e fare uno scambio Diffie-Hellman, e X25519 da sola non sa firmare,
quindi molti progetti finiscono per usare due chiavi d'identità separate.
Tenerne una sola Ed25519 significa una sola identità e una sola fingerprint da
leggere ad alta voce e confrontare con qualcuno, invece di due.

Le signed prekey e le one-time prekey sono coppie di chiavi X25519 casuali, non
derivate dal seme. È voluto: se una one-time prekey si potesse rigenerare dal
seme, ripristinare il vault dalle 12 parole farebbe tornare in vita una chiave
già usata una volta, che è esattamente il contrario di "usa e getta". Il prezzo
è che prekey, contatti e chat in corso esistono solo dentro `vault.bin`, non
nella frase di recupero. Se perdi la chiavetta senza una copia di quel file
perdi contatti e cronologia anche avendo le parole in mano; con
`init --from-mnemonic` e le stesse parole ti riprendi l'identità, ma riparti da
zero contatti.

Lo scambio di chiavi è X3DH, lo stesso handshake che usa Signal, però senza il
server di Signal che distribuisce i bundle di prekey su richiesta. Qui il
bundle di un contatto è semplicemente la sua card, condivisa una volta, a mano,
come tutto il resto in questo strumento. `send` esegue l'handshake da solo la
prima volta che scrivi a qualcuno, consumando una delle sue one-time prekey se
ne ha pubblicate, e ripiegando su un handshake a 3 vie, un po' più debole, una
volta che sono finite (`unlock` rimpingua il gruppo da solo quando scende
troppo, oppure lo fa `card --replenish-otpk` su richiesta). Quale prekey venga
usata è scelto a caso, perché la stessa card di solito finisce nelle mani di
più persone e altrimenti punterebbero tutte alla stessa: la prima che scrive la
consuma e tutte le altre restano a puntare a una chiave che non hai più.
Condividere a mano un insieme fisso di one-time prekey vuol dire che una
collisione è sempre possibile, ma così smette di essere il caso normale. Una
piccola differenza rispetto allo spec: invece di autenticare solo il primo
messaggio con le chiavi d'identità, qui entrambe le identità vengono mescolate
dentro la primissima chiave di cifratura, così ogni chiave che il ratchet
produrrà da lì in poi resta legata a entrambe le identità, non solo al
messaggio che ha aperto la conversazione.

I messaggi successivi sono cifrati con un Double Ratchet, che segue il design
di Signal abbastanza da vicino: un ratchet simmetrico per le chiavi dentro una
direzione della conversazione, più un ratchet Diffie-Hellman ogni volta che la
conversazione cambia direzione, con ChaCha20-Poly1305 a fare la cifratura vera
e propria. Due piccole semplificazioni rispetto allo spec originale: la chiave
di un messaggio viene usata direttamente come chiave ChaCha20-Poly1305 invece
di essere spezzata in pezzi separati per cifratura, autenticazione e IV (non
serve più, una volta che il cifrario è già autenticato), e ogni messaggio si
porta un nonce casuale invece che derivato da un contatore, il che costa
qualche byte in più a messaggio ma toglie di mezzo un'intera categoria di bug
sulla gestione dei contatori. Anche i messaggi che arrivano fuori ordine sono
gestiti come fa Signal: una lista limitata, fino a 1000, di chiavi saltate,
così un buco breve nella consegna non perde niente, mentre un buco più grosso
viene rifiutato subito, perché altrimenti basterebbe un'intestazione falsa per
far lavorare `recv` senza limiti. Quelle chiavi in cache scadono anche dopo una
settimana. Una chiave saltata è l'unico pezzo del ratchet che non va avanti da
solo (le catene ai suoi due lati hanno già fatto il loro passo, ma la chiave
resta lì ad aspettare un messaggio che potrebbe non arrivare mai), quindi senza
una scadenza un vault rubato mesi dopo aprirebbe comunque quei vecchi messaggi,
e le chiavi lasciate indietro da una catena che la conversazione si è ormai
lasciata alle spalle continuerebbero a mangiarsi il budget delle 1000. `recv`
spazza via quelle scadute prima di fare qualsiasi altra cosa, e `unlock` le
spazza su tutte le sessioni, così anche un vault che apri e basta le fa
scadere. Il prezzo è che un messaggio che si presenta con più di una settimana
di ritardo non si decifra più.

Niente di tutto questo dimostra che una chiave d'identità appartenga davvero
alla persona che pensi; quello può confermarlo solo un umano. Importare la card
di qualcuno verifica che la sua signed prekey sia stata firmata davvero dalla
chiave d'identità sulla card, e ogni messaggio che ricevi è legato
crittograficamente all'identità del mittente attraverso l'handshake, ma `add`
si limita comunque a stamparti una fingerprint da controllare. `trust` registra
che l'hai verificata in qualche altro modo, di persona o al telefono, non nella
stessa chat da cui è arrivata la card. `send` e `recv` ti avvisano se un
contatto non è verificato, ma non ti fermano.

Tutto ciò che contiene una chiave segreta usa un involucro (`SecureBytes`,
`SecureString`, `SecureBuffer`) che blocca la memoria quando il sistema
operativo lo consente e la azzera quando non serve più. Uno di questi non si
può copiare per sbaglio, solo spostare, quindi un segreto non può finire a
vivere in due posti senza che tu te ne accorga. La passphrase diventa la chiave
del vault attraverso Argon2id, 256 MiB e 3 passate di default, e il file del
vault è sigillato con ChaCha20-Poly1305.

Un ultimo dettaglio: la build usa le funzioni `crypto_kdf_hkdf_sha256_*` di
libsodium quando ci sono (libsodium 1.0.19+), e ripiega su una piccola
implementazione interna dell'RFC 5869 sulle versioni più vecchie. Entrambe sono
testate contro i vettori ufficiali dell'RFC e producono output identico, quindi
un vault resta portabile qualunque strada prenda la tua libsodium.

## Struttura del file vault

`vault.bin` è fatto così:

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

L'intestazione viene scritta campo per campo invece che riversata come struct
grezza, così il formato del file non dipende da come il tuo compilatore decide
di allineare le cose. L'intera intestazione viene anche data in pasto alla
cifratura come dato autenticato, quindi manomettere il salt, il nonce o i
valori di costo fa fallire la decifratura invece di far derivare in silenzio la
chiave sbagliata; di proposito, una passphrase sbagliata e un file manomesso
danno esattamente lo stesso messaggio d'errore. I valori di costo vengono
riletti da un file che in teoria potrebbe essere stato manomesso, quindi
vengono controllati (tempo da 1 a 64, memoria tra 8 KiB e 4 GiB) prima di
finire ad Argon2. Una prima versione del formato salvava solo un blocco fisso
da 64 byte con seme e chiave; quella attuale salva l'intero vault e non è
compatibile con la precedente, anche se non c'era comunque nessun vault
pubblicato da migrare.

Una contact card e un messaggio sono entrambi avvolti in un blocco
`-----BEGIN RATCHET <ETICHETTA>-----` di testo base64, 64 caratteri per riga,
con qualsiasi spazio in più ignorato in lettura, così un'app di chat che
reimpagina il testo non rompe niente. Un messaggio contiene un hash breve
dell'identità del mittente, così `recv` sa a quale conversazione appartiene
senza che glielo si dica, l'intestazione del Double Ratchet e, solo nel
messaggio che apre una conversazione nuova, i dati dell'handshake X3DH.

## Com'è organizzato il progetto

`include/ratchet/` contiene gli header pubblici, `src/` l'implementazione vera
e propria più la lista di parole BIP-39, e `test/` i test unitari (nessun
framework esterno, solo controlli scritti a mano).

## Come viene verificata la crittografia

Un test di andata e ritorno qui vale meno di quel che sembra. Cifrare e
decifrare con lo stesso codice dimostra che l'implementazione è d'accordo con
sé stessa, e un'implementazione sbagliata in modo coerente è d'accordo con sé
stessa alla perfezione. Scambia le due costanti HMAC nella derivazione della
chain key, oppure dai a HKDF l'output Diffie-Hellman come salt e la root key
come materiale di input, e tutti i messaggi continuano a fare andata e ritorno.
Il risultato è un ratchet che funziona benissimo e non è quello descritto dalla
specifica.

Per questo lo schema delle chiavi viene confrontato anche con vettori a
risposta nota che vengono da un'altra parte. `test/vectors/reference.py`
implementa le stesse derivazioni una seconda volta, in Python, partendo dalle
specifiche e non da `src/ratchet.cpp`, usando solo la libreria standard. Le sue
primitive sono a loro volta ancorate a vettori pubblicati (RFC 7748 per X25519,
RFC 5869 per HKDF-SHA256) e il suo output è congelato in
`test/vectors/vectors.hpp`, che la suite C++ deve riprodurre byte per byte. La
CI rigenera quell'header a ogni push e fallisce se differisce dalla copia
committata, così le due implementazioni non possono scivolare in silenzio verso
l'accordo. Perché un bug sopravviva, andrebbe fatto due volte, in modo
indipendente, nella stessa direzione.

Questo è un controllo di conformità, non una promessa di interoperabilità:
questo strumento non parla il formato di libsignal e non può essere testato
contro di esso (vedi le divergenze volute dette sopra: la chiave del messaggio
usata direttamente come chiave ChaCha20-Poly1305, il nonce casuale portato
nell'envelope, e la info string della root key che è di questo progetto).

Accanto a tutto ciò, `test/smoke.sh` porta il binario davvero compilato
attraverso una conversazione intera (due vault, uno scambio di card, un
handshake, una risposta, consegna fuori ordine, un messaggio manomesso, una
passphrase sbagliata) perché nessuno dei test unitari tocca il parsing degli
argomenti, l'I/O sui file o la codifica del blocco da copiare e incollare.

La CI esegue tutto a ogni push: GCC e Clang, Debug e Release, warning trattati
come errori, AddressSanitizer, UndefinedBehaviorSanitizer, Valgrind e
clang-tidy. Un job compila da sorgente una libsodium più recente, perché Ubuntu
distribuisce la 1.0.18 e questo progetto si porta dietro il proprio HKDF RFC
5869 per le versioni precedenti alla 1.0.19: senza quel job, metà del codice
HKDF nell'albero non verrebbe mai nemmeno compilata, figurarsi eseguita.
Verifica anche che l'HKDF della libsodium nuova sia stato davvero selezionato,
visto che un fallimento del rilevamento ripiegherebbe in silenzio lasciando il
badge verde.

## Da cosa protegge e da cosa no

Protegge da chi mette le mani sulla tua chiavetta USB ma non conosce la
passphrase, e da chiunque osservi o registri il canale su cui incolli i
messaggi. Se le chiavi di una sessione dovessero trapelare, questo non espone
né i messaggi passati né quelli futuri, grazie alla forward secrecy e alla
post-compromise security che stanno nel design del Double Ratchet.

Non ti protegge da un computer compromesso: un keylogger vede la tua passphrase
e tutto quello che digiti, cifratura o no. Non ti protegge se qualcuno legge le
tue 12 parole di recupero o ruba direttamente `vault.bin`, o se ti fidi
dell'identità di un contatto senza averne controllato davvero la fingerprint.
E il canale su cui incolli i messaggi vede comunque passare il testo cifrato,
insieme al momento in cui l'hai mandato, anche se non può leggere cosa c'è
dentro.

## Cosa non fa (ancora)

Chat di gruppo, uso di una stessa identità su più dispositivi, e qualunque cosa
somigli alla key transparency. Ognuna di queste è un bel pezzo di lavoro per
conto suo, quindi sono lasciate a dopo invece che fatte a metà adesso.

## Licenza

MIT, vedi [LICENSE](LICENSE). Il codice e i dati di terze parti usati da questo
progetto, la lista di parole BIP-39 e libsodium, sono citati in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
