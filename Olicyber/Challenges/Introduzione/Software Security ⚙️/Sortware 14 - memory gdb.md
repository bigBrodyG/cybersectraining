## REQUEST

<div style="background-color:rgb(10, 10, 10); padding: 10px; border-radius: 5px; color: white; font-style: italic; box-shadow: 0px 8px 8px rgba(255, 255, 255, 0.3);">

Con `gdb` è possibile ispezionare il contenuto della memoria.

La sintassi del comando per ispezionare la memoria è `x/nfu addr`, dove:

- `x` → Examine (esamina)
- `n` → Numero intero che specifica quanti elementi stampare (opzionale, di default 1)
- `f` → Formato con il quale stampare la memoria (opzionale, di default `x`):
  - `s` per le stringhe
  - `i` per il disassembly
  - `x` per l'esadecimale
  - `f` per i float
  - `d` per i numeri interi con segno
  - ...
- `u` → La dimensione di ogni elemento da stampare (opzionale, di default `w`):
  - `b` Bytes
  - `h` Halfwords (2 bytes)
  - `w` Words (4 bytes)
  - `g` Giant words (8 bytes)

`addr` può essere sia un indirizzo di memoria, come `0x5000000`, sia un registro che contiene un indirizzo, come `$rax`. Insieme ad `addr` si possono specificare delle operazioni aritmetiche, ad esempio `$rax+8`.

Questo programma salva la flag in una variabile `unsigned int` (4 byte) sullo stack e poi esegue `int 3`.

Apri il programma con `gdb` e, al breakpoint, leggi la variabile utilizzando il comando `x`. La variabile sullo stack si troverà a `$rbp-4`.

Per ottenere la flag, stampa la variabile come un `float` e inserisci **SOLO** la parte intera dentro a `flag{}`.
</div>

## TERMINAL OUTPUT

```sh
❯ gdb ./sw-14
(gdb) run
Starting program: /home/user/Downloads/sw-14 

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Enable debuginfod for this session? (y or [n]) y
Debuginfod has been enabled.
To make this setting permanent, add 'set debuginfod enabled on' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000555555555131 in main ()
(gdb) x/fw $rbp-4
0x7fffffffe22c:	31337.1328
(gdb) 
```
## FLAG:

**flag{31337}**