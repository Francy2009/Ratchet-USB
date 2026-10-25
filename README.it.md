# Ratchet-USB

Lingue: **Italiano** · [English](README.md)

Ratchet-USB permette a due persone di scambiarsi messaggi cifrati senza un
server dedicato. Scrivi un messaggio, copi il blocco cifrato che il programma
stampa e lo invii attraverso il canale che preferisci; chi lo riceve lo incolla
nel programma per leggerlo. Il trasporto vede il blocco e quando è stato
inviato, ma non il messaggio.

C'è un'interfaccia a schermo intero nel terminale e un'app desktop opzionale.
Entrambe usano gli stessi comandi sotto, quindi non importa quale scegli.

Identità, contatti e sessioni sono conservati in un vault cifrato su una chiavetta
USB o in una cartella scelta dall'utente. La chiavetta non è una chiave
crittografica: la protezione del file dipende dalla passphrase del vault, una
frase di parole casuali che il programma genera e mostra una sola volta alla
creazione. Se qualcuno copia il file, può tentare di indovinare la passphrase
senza avere la chiavetta, quindi conserva le parole al sicuro e separatamente
dalla chiavetta.

Il progetto è ancora in sviluppo (`0.5.0-dev`). La migrazione post quantum è
implementata in questa versione, ma non è stata sottoposta a una revisione
indipendente. Per il dettaglio delle verifiche fatte e di quelle ancora da fare,
vedi [lo stato della migrazione](docs/PQ-MIGRATION-STATUS.md) e il
[modello di minaccia](docs/THREAT-MODEL.md).

## Come si usa

Avviando `ratchet-usb` senza argomenti si apre l'interfaccia nel terminale.
Puoi creare il vault, aggiungere un contatto, verificare la sua impronta,
scrivere e leggere messaggi con i tasti indicati sullo schermo. La lingua segue
la locale del sistema; puoi scegliere esplicitamente `--lang it` o `--lang en`.
L'interfaccia si blocca dopo tre minuti di inattività. L'intervallo si cambia
con `--idle-lock <secondi>`.

Se preferisci una finestra, avvia `ratchet-gui`. Mette le stesse operazioni
dietro Qt6 — scegli la cartella del vault, la sblocchi, poi usi le schede
Contatti e Messaggi — e lancia `ratchet-usb` in background invece di
reimplementare qualcosa. Viene compilata quando Qt6 è installata ed è inclusa
nell'AppImage; vedi [README-GUI.md](README-GUI.md).

Gli stessi passaggi sono disponibili come comandi. Questo è uno scambio tipico:

```sh
ratchet-usb init
ratchet-usb card > mia-carta.txt
ratchet-usb add alice --card carta-alice.txt
ratchet-usb trust alice
ratchet-usb send alice
ratchet-usb recv
```

Dopo `init`, il programma mostra due cose diverse, una volta ciascuna. La prima
è una frase di recupero di 12 parole; conservala separatamente dalla chiavetta.
La frase permette di ricostruire l'identità, ma non ripristina contatti, prekey
o conversazioni. La seconda è la passphrase del vault, una frase casuale di sei
parole (66 bit di entropia) con cui si deriva la chiave Argon2id. Scrivila e
riscrivila una parola per riga quando il vault la chiede; non è la frase di
recupero e non ripristina nulla. `passphrase` ne genera una nuova e ricifra lo
stesso vault, conservando identità, contatti e sessioni; la vecchia passphrase
smette subito di funzionare. Un vault scritto da una versione precedente è
marcato come protetto da password e mantiene il suo prompt a una riga finché non
esegui `passphrase`, che lo porta al formato a parole. `add` importa la carta
ricevuta. Prima di usare `trust`, confronta l'impronta con Alice al telefono,
di persona o tramite un altro canale affidabile. Il programma richiede che il
contatto sia verificato prima di inviare o ricevere messaggi.

`send` senza testo lo chiede in modo interattivo o lo legge da standard input.
Questo evita di lasciare il messaggio nella cronologia della shell. `recv`
accetta il blocco cifrato da incollare. `contacts` mostra i contatti e lo stato
delle sessioni. `card` genera la carta da condividere. `unlock` apre il vault
e rinnova le prekey quando serve. `anchor` può registrare sul computer un
riferimento per rilevare il ripristino di una vecchia copia del vault; questa
protezione richiede un'attivazione esplicita. `migrate` prepara una migrazione
di formato e `migrate --commit` la conferma dopo le verifiche.

Oltre al testo, `send` può portare con sé un file. `ratchet-usb send alice
--file documento.odt` cifra il file con lo stesso ratchet e stampa un blocco
dello stesso tipo; nell'interfaccia, premi Ctrl-P mentre scrivi per indicarne il
percorso. Va bene qualsiasi formato — una foto, un documento, un foglio di
calcolo — e il file non viene mai modificato né copiato altrove. Dall'altra
parte `recv` riconosce il blocco e propone di mostrare il file in una cartella
temporanea; la cartella si apre nel gestore di file e viene rimossa alla
chiusura di ratchet-usb. Un file la cui estensione indica qualcosa che il
desktop potrebbe eseguire, come `.desktop` o `.sh`, viene rifiutato. Il file
viaggia interamente dentro il blocco, quindi il blocco cresce con il file
(circa un terzo in più con l'armatura) e un singolo file non può superare i
4 MiB.

L'interfaccia usa anche gli appunti di sistema: premi `y` su una carta o su un
blocco di messaggio per copiarlo, e `Ctrl-V` per incollare gli appunti in un
campo di testo. Così non devono passare dalla selezione del terminale.

Il programma prova a individuare un'unità rimovibile. Se la rilevazione non è
adatta al tuo caso, passa `--usb-path <cartella>` ai comandi o imposta
`RATCHET_USB_PATH`.

## Installazione

### AppImage

Ogni tag di release (`v*`) pubblica un `Ratchet-USB-x86_64.AppImage` autonomo
nella pagina [Releases](https://github.com/Francy2009/Ratchet-USB/releases).
Contiene la CLI, la GUI Qt opzionale e tutte le librerie che servono, quindi non
c'è niente da installare:

```sh
chmod +x Ratchet-USB-x86_64.AppImage
./Ratchet-USB-x86_64.AppImage          # apre la GUI
./Ratchet-USB-x86_64.AppImage card     # esegue un sottocomando della CLI
```

Questi tag sono pre-release: build di sviluppo, non release approvate per la
produzione. La GUI è documentata in [README-GUI.md](README-GUI.md).

### Dai sorgenti

Il sistema supportato è Linux. Servono un compilatore C++20, CMake 3.16 o più
recente, libsodium, OpenSSL 3.5 o più recente, Rust 1.88 o più recente e Cargo.
`setup.sh` propone i pacchetti per dnf, apt, pacman o zypper prima di
installarli.

Tieni aggiornate le librerie crittografiche del sistema. I controlli automatici
usano OpenSSL 3.5.9 e libsodium 1.0.22; una build locale può collegarsi ad altre
versioni installate.

```sh
./setup.sh
```

Lo script compila il programma, esegue i test e installa l'eseguibile in
`~/.local/bin`. Per compilare senza installare:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Per usare dipendenze già installate, `./setup.sh --no-deps` salta il passaggio
dei pacchetti. macOS e Windows non sono supportati. L'applicazione usa funzioni
di terminale e filesystem proprie di Linux.

## Cosa succede a un messaggio

Ogni identità ha una chiave Ed25519 e una ML-DSA-65. La carta del contatto
contiene le chiavi pubbliche, le prekey X25519 e ML-KEM-768 e le firme che
proteggono la carta. La prima comunicazione usa un handshake ibrido con
X25519 e ML-KEM-768. I due partecipanti ricavano da quel segreto uno stato
per il Double Ratchet classico e uno per lo Sparse Post Quantum Ratchet di
Signal, chiamato SPQR.

Per ogni nuovo messaggio i due ratchet producono una chiave. Il programma le
combina e usa il risultato per cifrare il testo. Il messaggio SPQR, l'intestazione
classica e i dati dell'handshake sono autenticati insieme al testo cifrato. Lo
stato avanza solo dopo che il messaggio è stato verificato. La sessione e lo
stato SPQR vengono salvati nel vault cifrato.

Le carte ibride precedenti che dichiarano solo la suite 2 continuano a usare
il loro formato di messaggio. Una sessione già avviata non cambia protocollo
mentre è in corso. Le nuove carte dichiarano la suite 4: Triple Ratchet con
il combinatore di handshake X-Wing. Le carte di suite 3 continuano a usare il
combinatore precedente.
Questa implementazione non usa il formato dei messaggi di Signal e non può
scambiare messaggi con l'app Signal. I dettagli dei formati sono in
[docs/WIRE-V3.md](docs/WIRE-V3.md).

## Limiti di sicurezza

Verificare l'impronta del contatto è indispensabile: una carta firmata prova
che le sue parti appartengono alla stessa identità, non che quell'identità
appartenga alla persona che intendi contattare. Un computer compromesso può
leggere passphrase e messaggi mentre il programma è aperto. Il canale di
trasporto vede quando e con chi comunichi. Il ponte Rust verso SPQR azzera e
blocca quando possibile i buffer segreti che restituisce al C++, ma la libreria
inclusa continua a lavorare in allocazioni normali mentre gira, quindi non è
garantito che ogni copia venga cancellata subito dopo l'uso. Anche le vecchie
copie del vault possono restare sulla memoria fisica della chiavetta dopo un
salvataggio.

I test locali coprono scambi completi, messaggi fuori ordine, replay, dati
alterati e compatibilità con la suite precedente. Restano necessari una
revisione crittografica indipendente e test di fuzzing più lunghi. Non usare
questa versione come unica protezione per comunicazioni ad alto rischio.

Aprire un file ricevuto ne scrive i byte decifrati in una cartella privata sul
computer e la rimuove alla chiusura del programma, ma fino ad allora il file è
in chiaro sul computer.

Per segnalare una vulnerabilità e leggere i limiti nel dettaglio, vedi
[SECURITY.md](SECURITY.md).

## Evoluzione del progetto

Questi tag sono pubblicati come pre-release su GitHub. Segnano passaggi di
sviluppo, non versioni approvate per l'uso in produzione.

| Tag | Passaggio |
| --- | --- |
| `milestone/pq-hybrid` | Handshake e carte ibride, prima dell'integrazione SPQR. |
| `milestone/spqr-license` | Sorgenti SPQR integrati e licenza combinata AGPL. |
| `milestone/spqr-bridge` | Collegamento tra C++ e la libreria Rust, con test. |
| `milestone/triple-ratchet` | Messaggi, sessioni e persistenza Triple Ratchet. |
| `milestone/pq-migration-docs` | Build Rust fissata e documentazione della migrazione. |
| `milestone/local-verification` | Correzione del parser e verifiche locali della migrazione. |
| `v0.5.0-dev` | Istantanea di sviluppo della prima pubblicazione delle pre-release. Resta su quel commit. |
| `milestone/linux-only` | macOS rimosso dal programma, dalla CI e dalla documentazione. |
| `milestone/suite-4-xwing` | Handshake X-Wing di suite 4 per le carte nuove, HMAC sulle ancore di rollback nuove e modello di sessione ProVerif. |
| `milestone/file-sharing` | Invio di file cifrati, appunti di sistema e file ricevuti aperti in una cartella temporanea rimossa all'uscita. |

Puoi esaminare una tappa con `git show milestone/triple-ratchet` o confrontare
due con `git diff milestone/pq-hybrid milestone/triple-ratchet`. I tag sono
nella [pagina delle release](https://github.com/Francy2009/Ratchet-USB/releases),
e ogni nuovo tag `v*` ha anche un AppImage allegato.

## Licenza e componenti

La distribuzione che include Signal SPQR è sotto
[AGPL-3.0-only](LICENSE). Il codice originale di Ratchet-USB era pubblicato
sotto MIT; il relativo testo è conservato in [LICENSE-MIT](LICENSE-MIT).
Provenienza e licenze dei componenti sono raccolte in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Il software è fornito senza
garanzia.
