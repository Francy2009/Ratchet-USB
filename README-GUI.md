# Ratchet-USB GUI

GUI desktop minimale (Qt6 Widgets) che sostituisce l'interazione da terminale
senza toccare il core crittografico. La GUI **non** reimplementa nulla: lancia il
binario CLI `ratchet-usb` già compilato come processo figlio e ne mostra
l'output. `src/` (core), `rust/spqr_bridge` e il formato del vault restano
identici, e la CLI continua a funzionare e a passare i suoi test.

## Download (AppImage)

Ogni tag di questo repository pubblica un `Ratchet-USB-x86_64.AppImage` autonomo
nella pagina [Releases](https://github.com/Francy2009/Ratchet-USB/releases).
Contiene sia la CLI sia la GUI con tutte le librerie che servono, quindi non
c'è niente da installare:

```sh
chmod +x Ratchet-USB-x86_64.AppImage
./Ratchet-USB-x86_64.AppImage            # apre la GUI
./Ratchet-USB-x86_64.AppImage card       # esegue un sottocomando della CLI
./Ratchet-USB-x86_64.AppImage --help     # aiuto della CLI
```

È `ci/AppRun` a decidere cosa avviare: un sottocomando noto (`init`, `unlock`,
`passphrase`, `anchor`, `migrate`, `card`, `add`, `contacts`, `trust`,
`reset-session`, `remove`, `send`, `recv`, `ui`) o un flag di aiuto/versione va
alla CLI;
qualsiasi altra cosa, compreso nessun argomento, apre la GUI.

I tag di questa linea (`v0.5.0-appimage-test.*`) sono **pre-release**: build di
sviluppo, non release approvate per la produzione.

## Requisiti

- Tutte le dipendenze del progetto (Rust, OpenSSL, libsodium, CMake).
- Qt6 base development package, che fornisce `Qt6Widgets`, `moc`, `uic`, `rcc`
  e i file `Qt6*Config.cmake`. Su Fedora:

  ```sh
  sudo dnf install qt6-qtbase-devel
  ```

Se Qt6 Widgets non è presente, la configurazione emette un warning e **non**
compila `ratchet-gui`: la build della CLI e i test restano intatti.

## Compilazione

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
```

Il target della GUI è `ratchet-gui` (si può compilare da solo):

```sh
cmake --build build --target ratchet-gui -j2
```

Per escluderla del tutto:

```sh
cmake -S . -B build -DRATCHET_BUILD_GUI=OFF
```

## Avvio

```sh
build/gui/ratchet-gui
# oppure, dopo l'install:
~/.local/bin/ratchet-gui
```

### Individuazione del binario CLI

La GUI cerca `ratchet-usb` (poi `ratchet`) in questo ordine:

1. la variabile d'ambiente `RATCHET_BIN`, se punta a un eseguibile;
2. accanto all'eseguibile della GUI (e una cartella sopra, dove il build tree
   mette `ratchet-usb` rispetto a `build/gui/`);
3. nel `PATH`.

Override esplicito:

```sh
RATCHET_BIN=/percorso/ratchet-usb build/gui/ratchet-gui
```

## Uso

La finestra segue il flusso del core: prima si apre il vault, poi si usano le
funzioni che richiedono un vault aperto.

1. **Accesso al vault** (pannello in alto): scegli la **cartella del vault**
   (quella che contiene `vault.bin`, di solito sul drive USB). Il pulsante
   *Rileva chiavetta* cerca i drive rimovibili montati (come fa la CLI quando
   `--usb-path` è omesso) e compila il percorso; *Sfoglia...* apre il selettore
   con i drive rilevati nella barra laterale. Digita la **passphrase** (nascosta;
   il pulsante a forma di occhio la mostra e la rinasconde) e premi **Accedi**.
   Se il vault non esiste ancora, usa *Crea un nuovo vault...*: si apre una
   finestrella con le opzioni (`--force`, `--otpk-count`, `--passphrase-words`,
   ricostruzione `--from-mnemonic`); al termine passphrase e frase di recupero
   vengono mostrate una sola volta in un popup (annottale, non sono
   recuperabili), poi premi Accedi.
2. Solo dopo uno sblocco riuscito le schede si attivano:
   - **Vault**: `anchor` (rollback anchor), `passphrase` (cambia passphrase).
   - **Contatti**: `card` (genera la card identità), `contacts` (lista identità e
     stato), `add` (incolla la card o scegli un file), `trust`, `reset-session`,
     `remove` (seleziona l'alias e conferma nel popup: elimina contatto e
     sessione, chiavi comprese).
     Dopo lo sblocco l'elenco contatti viene letto automaticamente e i menu a
     tendina (destinatario di `send`, alias di `trust`/`reset-session`/`remove`)
     si popolano da soli; il pulsante *Aggiorna elenco contatti* li ricarica.
   - **Messaggi**: `send` (testo o `--file`) e `group-send` e `recv` (incolla
     il blocco). Il destinatario si sceglie dalla tendina e si aggiunge con
     *Aggiungi*: ogni destinatario diventa un riquadro con una × per
     toglierlo. Con un destinatario l'invio usa `send`, con due o più
     `group-send --to ...` (solo testo: per i file, un destinatario alla
     volta). La tendina *Scadenza* (`1 ora`, `24 ore`, `7 giorni`) e la casella
     *Distruggi dopo lettura* segnano il messaggio come effimero (anche di
     gruppo): la scelta viaggia dentro al testo cifrato e vale per un solo
     invio, poi il selettore torna su *Nessuna scadenza*. In ricezione un
     messaggio effimero mostra da quanto scade e, allo scadere, la finestra
     si chiude da sola cancellando ciò che mostrava (per i file, rimuovendo
     anche la cartella temporanea). Resta un aiuto, non una revoca: non
     impedisce screenshot, copie o un client modificato. A invio riuscito
     destinatari, messaggio e file vengono svuotati; dopo una `recv` riuscita
     il blocco incollato viene svuotato e dopo un `add` riuscito alias e card.
     In caso di errore resta tutto, per riprovare. Se il blocco contiene un
     file, compare un popup "File ricevuto" con *Apri cartella* (apre nel
     file manager la cartella temporanea privata dove `ratchet-usb` ha
     preparato il file, la stessa logica di `recv` da terminale) e *Chiudi*.
3. **Blocca** disabilita di nuovo le schede e cancella la passphrase dal campo.

Non c'è un pannello di testo stile terminale: ogni comando apre un **popup** che
dice se è andato a buon fine o male. Se il risultato è lungo (card, blocco
cifrato, lista contatti, impronta) viene mostrato in un'area **scorrevole** con i
pulsanti **Copia** (negli appunti) e **Chiudi** in basso, così la finestra non si
allarga. Sotto il campo della cartella la finestra mostra il percorso esatto del
file (`.../vault.bin`) su cui sta per operare.

Ogni comando che richiede il vault riceve la passphrase su stdin: la frase si
digita su una riga sola, con le parole separate da spazio (è il formato che il
core accetta).

## Note

- La GUI non mette mai il testo in chiaro negli argomenti (`/proc/<pid>/cmdline`
  è leggibile a tutti i processi dello stesso utente): messaggi e blocchi
  viaggiano su stdin con `--stdin-payload`, prima della passphrase
  (`MainWindow::launchWithPayload`). I flag vanno **prima** di un `--`
  letterale e i valori posizionali **dopo**: la CLI emette
  `send --usb-path <dir> --file <f> -- <alias>`. Senza quel separatore un
  alias che inizia con `-` (per esempio `-h`) verrebbe letto come un'opzione:
  la CLI stamperebbe l'help e uscirebbe con 0, cioè la GUI mostrerebbe
  "operazione completata" senza aver cifrato nulla. Il separatore è emesso in
  un unico punto (`MainWindow::launch`), che tiene separati `flags` e
  `positionals`.
- `add` legge la card da stdin fino a EOF: per questo una card incollata viene
  scritta in un file temporaneo privato e passata con `--card`, lasciando stdin
  alla sola passphrase.
- Un file ricevuto viene preparato dalla CLI con `recv --stage-file`, che lo
  mette nella cartella temporanea privata di `ratchet-usb` e ne stampa il
  percorso; la GUI apre quella cartella. La cartella è transitoria (la rimuove
  l'helper di `ratchet-usb`, con una finestra di alcuni minuti), quindi *Apri
  cartella* va usato subito dopo la ricezione.
- `passphrase` viene confermata automaticamente (un newline in più su stdin); la
  nuova passphrase compare nel popup di risultato.
- Il rilevamento della chiavetta legge `/proc/mounts` in un colpo solo: `atEnd()`
  di `QFile` si fida della dimensione, che per i file di `/proc` è zero.
- È un wrapper di processo (fase 1): la crittografia, il vault e la CLI non sono
  stati modificati.
