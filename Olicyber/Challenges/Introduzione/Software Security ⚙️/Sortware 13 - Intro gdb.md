## REQUEST

<div style="background-color:rgb(10, 10, 10); padding: 10px; border-radius: 5px; color: white; font-style: italic; box-shadow: 0px 8px 8px rgba(255, 255, 255, 0.3);">

Con `gdb` è possibile stampare il risultato di espressioni. Questo si può fare utilizzando il comando print, abbreviabile con p.

La sua sintassi è:
- `print/f expr` 
- `print expr`
    f è il formato con il quale stampare il risultato dell'espressione:
        `x` per l'esadecimale
        `f` per i numeri in virgola mobile (float)
        `d` per i numeri interi con segno
        `u` per i numeri interi unsigned
        `x` per l'esadecimale
        `f` per i float
        `d` per i numeri interi con segno
        `u` per i numeri interi unsigned
        ... (For a complete list of format specifiers, refer to the [GDB documentation](https://sourceware.org/gdb/current/onlinedocs/gdb/Output-Formats.html).)

expr può essere un registro, come ad esempio `$rax`. Può anche essere un'espressione aritmetica come `$rax+0x100`.

Questo programma salva la flag all'interno del registro `$rax` e poi esegue `int 3`.

Apri il programma con gdb e al breakpoint leggi `$rax` utilizzando il comando p.

Per ottenere la flag stampa il registro come numero intero `SIGNED` e inserisci il risultato dentro a flag{} (senza il segno +/-).
</div>

## TERMINAL OUTPUT

```sh
❯ gdb ./sw-13
(gdb) run
Starting program: /home/user/Downloads/sw-13 

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Enable debuginfod for this session? (y or [n]) y
Debuginfod has been enabled.
To make this setting permanent, add 'set debuginfod enabled on' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000555555555134 in main ()
(gdb) print $rax
$1 = -415710747049308268
(gdb)
```
## FLAG:

**flag{415710747049308268}**