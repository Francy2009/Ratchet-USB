# Ratchet-USB

Ratchet-USB è un programma da terminale per scambiarsi messaggi cifrati senza un
server dedicato. Scrivi un messaggio sul tuo computer, copi il blocco cifrato che
compare e lo invii attraverso il canale che preferisci. La persona che lo riceve
incolla il blocco nel programma per leggerlo. Il canale usato per il trasporto
vede il blocco e l'ora dello scambio, ma non il testo del messaggio.

Identità, contatti e sessioni sono conservati in un vault cifrato su una chiavetta
USB o in una cartella scelta dall'utente. La chiavetta non è una chiave
crittografica: la protezione del file dipende dalla passphrase del vault. Se
qualcuno copia il file, può tentare di indovinare la passphrase senza avere la
chiavetta.

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

Gli stessi passaggi sono disponibili come comandi. Questo è uno scambio tipico:

```sh
ratchet-usb init
ratchet-usb card > mia-carta.txt
ratchet-usb add alice --card carta-alice.txt
ratchet-usb trust alice
ratchet-usb send alice
ratchet-usb recv
```

Dopo `init`, il programma mostra una frase di recupero di 12 parole una sola
volta. Conservala separatamente dalla chiavetta. La frase permette di
ricostruire l'identità, ma non ripristina contatti, prekey o conversazioni.
`add` importa la carta ricevuta. Prima di usare `trust`, confronta l'impronta
con Alice al telefono, di persona o tramite un altro canale affidabile. Il
programma richiede che il contatto sia verificato prima di inviare o ricevere
messaggi.

`send` senza testo lo chiede in modo interattivo o lo legge da standard input.
Questo evita di lasciare il messaggio nella cronologia della shell. `recv`
accetta il blocco cifrato da incollare. `contacts` mostra i contatti e lo stato
delle sessioni. `card` genera la carta da condividere. `unlock` apre il vault
e rinnova le prekey quando serve. `anchor` può registrare sul computer un
riferimento per rilevare il ripristino di una vecchia copia del vault; questa
protezione richiede un'attivazione esplicita. `migrate` prepara una migrazione
di formato e `migrate --commit` la conferma dopo le verifiche.

Il programma prova a individuare un'unità rimovibile. Se la rilevazione non è
adatta al tuo caso, passa `--usb-path <cartella>` ai comandi o imposta
`RATCHET_USB_PATH`.

## Installazione

Sono supportati Linux e macOS. Servono un compilatore C++20, CMake 3.16 o più
recente, libsodium, OpenSSL 3.5 o più recente, Rust 1.88 o più recente e Cargo.
Su macOS puoi installare le dipendenze principali con
`brew install libsodium openssl@3.5 cmake rust`. Su Linux `setup.sh` propone i
pacchetti per dnf, apt, pacman o zypper prima di installarli.

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
dei pacchetti. Windows non è ancora supportato nativamente; l'applicazione usa
funzioni di terminale e filesystem proprie di Linux e macOS.

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
mentre è in corso. Le nuove carte dichiarano la suite 3 con Triple Ratchet.
Questa implementazione non usa il formato dei messaggi di Signal e non può
scambiare messaggi con l'app Signal. I dettagli dei formati sono in
[docs/WIRE-V3.md](docs/WIRE-V3.md).

## Limiti di sicurezza

Verificare l'impronta del contatto è indispensabile: una carta firmata prova
che le sue parti appartengono alla stessa identità, non che quell'identità
appartenga alla persona che intendi contattare. Un computer compromesso può
leggere passphrase e messaggi mentre il programma è aperto. Il canale di
trasporto vede quando e con chi comunichi. La memoria interna di SPQR in Rust
non è sempre bloccata contro lo swap e non è garantito che ogni sua copia venga
cancellata subito dopo l'uso. Anche le vecchie copie del vault possono restare
sulla memoria fisica della chiavetta dopo un salvataggio.

I test locali coprono scambi completi, messaggi fuori ordine, replay, dati
alterati e compatibilità con la suite precedente. Restano necessari una
revisione crittografica indipendente, test di fuzzing più lunghi e la verifica
della nuova build nei sistemi CI Linux e macOS. Non usare questa versione come
unica protezione per comunicazioni ad alto rischio.

## Evoluzione del progetto

I tag `milestone/*` segnano passaggi di sviluppo nel repository locale. Sono
riferimenti alla cronologia del codice, non versioni pubblicate o approvate
per l'uso in produzione. I tag di questa migrazione sono:

| Tag | Passaggio |
| --- | --- |
| `milestone/pq-hybrid` | Handshake e carte ibride, prima dell'integrazione SPQR. |
| `milestone/spqr-license` | Sorgenti SPQR integrati e licenza combinata AGPL. |
| `milestone/spqr-bridge` | Collegamento tra C++ e la libreria Rust, con test. |
| `milestone/triple-ratchet` | Messaggi, sessioni e persistenza Triple Ratchet. |
| `milestone/pq-migration-docs` | Build Rust fissata e documentazione della migrazione. |

Puoi esaminare una tappa con `git show milestone/triple-ratchet` o confrontare
due tappe con `git diff milestone/pq-hybrid milestone/triple-ratchet`. I tag
restano locali finché non vengono pubblicati esplicitamente.

## Licenza e componenti

La distribuzione che include Signal SPQR è sotto
[AGPL-3.0-only](LICENSE). Il codice originale di Ratchet-USB era pubblicato
sotto MIT; il relativo testo è conservato in [LICENSE-MIT](LICENSE-MIT).
Provenienza e licenze dei componenti sono raccolte in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Il software è fornito senza
garanzia.
