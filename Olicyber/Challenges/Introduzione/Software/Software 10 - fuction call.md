# TERMINAL OUTPUT

```bash
❯ ltrace -e access ./sw-10   #filtra la chiamata a access() da parte del programma --> **-e FILTER:    modify which library calls to trace.**
sw-10->access("flag{0f32826c}", 0)                                                      = -1
+++ exited (status 0) +++
```
