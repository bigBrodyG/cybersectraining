## REQUEST

<div style="background-color:rgb(10, 10, 10); padding: 10px; border-radius: 5px; color: white; font-style: italic; box-shadow: 0px 8px 8px rgba(255, 255, 255, 0.3);">

Nelle challenge precedenti è stata inserita volutamente un'istruzione int 3 in modo che il debugger si fermasse da solo.

Ora dovrai inserire manualmente un breakpoint, come si è soliti fare durante l'utilizzo di un debugger.
Con `gdb` è possibile inserire breakpoint utilizzando l'istruzione `break`, abbreviata `b`.

I due casi più frequenti sono `break *address` e `break function`.

- Il primo crea un breakpoint che viene azionato quando il programma esegue l'istruzione che si trova all'indirizzo `address`.
- Il secondo permette di mettere un breakpoint direttamente su una funzione.

È possibile specificare `address` come offset rispetto a una funzione. Ad esempio, `b *main+10` mette un breakpoint sull'istruzione che si trova 10 byte dopo l'inizio della funzione `main`.

Questa sintassi risulta utile quando combinata con l'istruzione `disassemble function_name`, che permette di disassemblare il contenuto di una funzione mostrando gli offset delle varie istruzioni rispetto all'indirizzo della funzione.

Questo programma crea una variabile `unsigned long` sullo stack e, dopo averla inizializzata, esegue diverse operazioni aritmetiche.

La flag è il valore in esadecimale della variabile sullo stack nel momento dell'invocazione della funzione `puts` che si trova nel `main`. Inserisci il valore all'interno delle parentesi di `flag{}` senza gli zeri in eccesso e senza `0x`.

Utilizzando il comando `break`, metti un breakpoint sulla chiamata alla `puts()` nella funzione `main`, e con il comando `x` stampa il contenuto della variabile in esadecimale. La variabile si trova a `$rbp-0x8`.

</div>

## TERMINAL OUTPUT

```sh
❯ gdb ./sw-15
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000001135 <+0>:	push   %rbp
   0x0000000000001136 <+1>:	mov    %rsp,%rbp
   0x0000000000001139 <+4>:	sub    $0x10,%rsp
   0x000000000000113d <+8>:	movabs $0x484773743,%rax
   0x0000000000001147 <+18>:	mov    %rax,-0x8(%rbp)
   0x000000000000114b <+22>:	mov    -0x8(%rbp),%rdx
   0x000000000000114f <+26>:	mov    %rdx,%rax
   0x0000000000001152 <+29>:	shl    $0x6,%rax
   0x0000000000001156 <+33>:	add    %rdx,%rax
   0x0000000000001159 <+36>:	shl    $0x4,%rax
   0x000000000000115d <+40>:	mov    %rax,-0x8(%rbp)
   0x0000000000001161 <+44>:	xorq   $0x4560,-0x8(%rbp)
   0x0000000000001169 <+52>:	movabs $0xf43567350,%rax
   0x0000000000001173 <+62>:	add    %rax,-0x8(%rbp)
   0x0000000000001177 <+66>:	subq   $0x5453f,-0x8(%rbp)
   0x000000000000117f <+74>:	movabs $0xaabbaaccdd,%rax
   0x0000000000001189 <+84>:	and    %rax,-0x8(%rbp)
   0x000000000000118d <+88>:	lea    0xe70(%rip),%rdi        # 0x2004
   0x0000000000001194 <+95>:	call   0x1030 <puts@plt>
   0x0000000000001199 <+100>:	mov    $0x0,%eax
   0x000000000000119e <+105>:	leave
   0x000000000000119f <+106>:	ret
End of assembler dump.
(gdb) b *main+95
Breakpoint 1 at 0x1194
(gdb) run
Starting program: /home/user/Downloads/sw-15 

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Enable debuginfod for this session? (y or [n]) y
Debuginfod has been enabled.
To make this setting permanent, add 'set debuginfod enabled on' to .gdbinit.
Download failed: No route to host.  Continuing without separate debug info for system-supplied DSO at 0x7ffff7fc4000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, 0x0000555555555194 in main ()
(gdb) x/xg $rbp-0x8
0x7fffffffe228:	0x0000002823a0c041
(gdb) 
```
## FLAG:

**flag{2823a0c041}**