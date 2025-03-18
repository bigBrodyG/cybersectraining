## REQUEST

<div style="background-color:rgb(10, 10, 10); padding: 10px; border-radius: 5px; color: white; font-style: italic; box-shadow: 0px 8px 8px rgba(255, 255, 255, 0.3);">

Questo programma esegue 3 istruzioni mov, e poi esegue una int 3.

int 3 è un'istruzione che viene utilizzata dai debugger per mettere i breakpoint e fermare l'esecuzione del programma.

Uno dei più famosi debugger, per ambienti linux, è gdb di cui puoi trovare una introduzione nel modulo di Software Security 2. Per installare gdb su Ubuntu: `apt install gdb`

Apri con gdb il binario (`gdb ./chall`).

Con il comando `run` il programma verrà eseguito dal debugger.

Ad ogni momento puoi premere `CTRL-C` per mettere in pausa l'esecuzione del programma, per poi utilizzare `continue` per riprenderne l'esecuzione.

Con il comando `info registers` puoi stampare lo stato dei registri della CPU.

Aspetta l'esecuzione della `int 3` e poi leggi il contenuto dei registri con `info registers`, concatena il valore dei primi tre registri in esadecimale e inseriscilo dentro `flag{}` (senza il `0x` prima dei valori).
</div>

## TERMINAL OUTPUT

```sh
❯ gdb ./sw-12
(gdb) run
Starting program: /home/user/Downloads/sw-12 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
✅ Writing to registers

Program received signal SIGTRAP, Trace/breakpoint trap.
0x000055555555515b in main ()
(gdb) info register
rax            0x15af56            1421142
rbx            0xf2f429            15922217
rcx            0x5e9d38            6200632
rdx            0x0                 0
rsi            0x5555555592a0      93824992252576
rdi            0x7ffff7f8e7d0      140737353672656
rbp            0x7fffffffe230      0x7fffffffe230
rsp            0x7fffffffe230      0x7fffffffe230
r8             0x0                 0
r9             0x0                 0
r10            0x0                 0
r11            0x202               514
r12            0x1                 1
r13            0x0                 0
r14            0x7ffff7ffd000      140737354125312
r15            0x0                 0
rip            0x55555555515b      0x55555555515b <main+38>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x7ffff7da1740      140737351653184
gs_base        0x0                 0
(gdb) 
```
## FLAG:

**flag{15af56f2f4295e9d38}**