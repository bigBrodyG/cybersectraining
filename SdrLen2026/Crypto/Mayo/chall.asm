
./chall:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 c9 0f 01 00 	mov    0x10fc9(%rip),%rax        # 11fd8 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 fa 0e 01 00    	push   0x10efa(%rip)        # 11f20 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 fb 0e 01 00 	bnd jmp *0x10efb(%rip)        # 11f28 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <.plt>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64
    1044:	68 01 00 00 00       	push   $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <.plt>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64
    1054:	68 02 00 00 00       	push   $0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <.plt>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64
    1064:	68 03 00 00 00       	push   $0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmp 1020 <.plt>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64
    1074:	68 04 00 00 00       	push   $0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmp 1020 <.plt>
    107f:	90                   	nop
    1080:	f3 0f 1e fa          	endbr64
    1084:	68 05 00 00 00       	push   $0x5
    1089:	f2 e9 91 ff ff ff    	bnd jmp 1020 <.plt>
    108f:	90                   	nop
    1090:	f3 0f 1e fa          	endbr64
    1094:	68 06 00 00 00       	push   $0x6
    1099:	f2 e9 81 ff ff ff    	bnd jmp 1020 <.plt>
    109f:	90                   	nop
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	68 07 00 00 00       	push   $0x7
    10a9:	f2 e9 71 ff ff ff    	bnd jmp 1020 <.plt>
    10af:	90                   	nop
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	68 08 00 00 00       	push   $0x8
    10b9:	f2 e9 61 ff ff ff    	bnd jmp 1020 <.plt>
    10bf:	90                   	nop
    10c0:	f3 0f 1e fa          	endbr64
    10c4:	68 09 00 00 00       	push   $0x9
    10c9:	f2 e9 51 ff ff ff    	bnd jmp 1020 <.plt>
    10cf:	90                   	nop
    10d0:	f3 0f 1e fa          	endbr64
    10d4:	68 0a 00 00 00       	push   $0xa
    10d9:	f2 e9 41 ff ff ff    	bnd jmp 1020 <.plt>
    10df:	90                   	nop
    10e0:	f3 0f 1e fa          	endbr64
    10e4:	68 0b 00 00 00       	push   $0xb
    10e9:	f2 e9 31 ff ff ff    	bnd jmp 1020 <.plt>
    10ef:	90                   	nop
    10f0:	f3 0f 1e fa          	endbr64
    10f4:	68 0c 00 00 00       	push   $0xc
    10f9:	f2 e9 21 ff ff ff    	bnd jmp 1020 <.plt>
    10ff:	90                   	nop
    1100:	f3 0f 1e fa          	endbr64
    1104:	68 0d 00 00 00       	push   $0xd
    1109:	f2 e9 11 ff ff ff    	bnd jmp 1020 <.plt>
    110f:	90                   	nop
    1110:	f3 0f 1e fa          	endbr64
    1114:	68 0e 00 00 00       	push   $0xe
    1119:	f2 e9 01 ff ff ff    	bnd jmp 1020 <.plt>
    111f:	90                   	nop
    1120:	f3 0f 1e fa          	endbr64
    1124:	68 0f 00 00 00       	push   $0xf
    1129:	f2 e9 f1 fe ff ff    	bnd jmp 1020 <.plt>
    112f:	90                   	nop
    1130:	f3 0f 1e fa          	endbr64
    1134:	68 10 00 00 00       	push   $0x10
    1139:	f2 e9 e1 fe ff ff    	bnd jmp 1020 <.plt>
    113f:	90                   	nop
    1140:	f3 0f 1e fa          	endbr64
    1144:	68 11 00 00 00       	push   $0x11
    1149:	f2 e9 d1 fe ff ff    	bnd jmp 1020 <.plt>
    114f:	90                   	nop
    1150:	f3 0f 1e fa          	endbr64
    1154:	68 12 00 00 00       	push   $0x12
    1159:	f2 e9 c1 fe ff ff    	bnd jmp 1020 <.plt>
    115f:	90                   	nop

Disassembly of section .plt.got:

0000000000001160 <__cxa_finalize@plt>:
    1160:	f3 0f 1e fa          	endbr64
    1164:	f2 ff 25 7d 0e 01 00 	bnd jmp *0x10e7d(%rip)        # 11fe8 <__cxa_finalize@GLIBC_2.2.5>
    116b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001170 <free@plt>:
    1170:	f3 0f 1e fa          	endbr64
    1174:	f2 ff 25 b5 0d 01 00 	bnd jmp *0x10db5(%rip)        # 11f30 <free@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001180 <putchar@plt>:
    1180:	f3 0f 1e fa          	endbr64
    1184:	f2 ff 25 ad 0d 01 00 	bnd jmp *0x10dad(%rip)        # 11f38 <putchar@GLIBC_2.2.5>
    118b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001190 <__errno_location@plt>:
    1190:	f3 0f 1e fa          	endbr64
    1194:	f2 ff 25 a5 0d 01 00 	bnd jmp *0x10da5(%rip)        # 11f40 <__errno_location@GLIBC_2.2.5>
    119b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011a0 <puts@plt>:
    11a0:	f3 0f 1e fa          	endbr64
    11a4:	f2 ff 25 9d 0d 01 00 	bnd jmp *0x10d9d(%rip)        # 11f48 <puts@GLIBC_2.2.5>
    11ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011b0 <fread@plt>:
    11b0:	f3 0f 1e fa          	endbr64
    11b4:	f2 ff 25 95 0d 01 00 	bnd jmp *0x10d95(%rip)        # 11f50 <fread@GLIBC_2.2.5>
    11bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011c0 <fclose@plt>:
    11c0:	f3 0f 1e fa          	endbr64
    11c4:	f2 ff 25 8d 0d 01 00 	bnd jmp *0x10d8d(%rip)        # 11f58 <fclose@GLIBC_2.2.5>
    11cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011d0 <__stack_chk_fail@plt>:
    11d0:	f3 0f 1e fa          	endbr64
    11d4:	f2 ff 25 85 0d 01 00 	bnd jmp *0x10d85(%rip)        # 11f60 <__stack_chk_fail@GLIBC_2.4>
    11db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011e0 <printf@plt>:
    11e0:	f3 0f 1e fa          	endbr64
    11e4:	f2 ff 25 7d 0d 01 00 	bnd jmp *0x10d7d(%rip)        # 11f68 <printf@GLIBC_2.2.5>
    11eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011f0 <__assert_fail@plt>:
    11f0:	f3 0f 1e fa          	endbr64
    11f4:	f2 ff 25 75 0d 01 00 	bnd jmp *0x10d75(%rip)        # 11f70 <__assert_fail@GLIBC_2.2.5>
    11fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001200 <memset@plt>:
    1200:	f3 0f 1e fa          	endbr64
    1204:	f2 ff 25 6d 0d 01 00 	bnd jmp *0x10d6d(%rip)        # 11f78 <memset@GLIBC_2.2.5>
    120b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001210 <memcmp@plt>:
    1210:	f3 0f 1e fa          	endbr64
    1214:	f2 ff 25 65 0d 01 00 	bnd jmp *0x10d65(%rip)        # 11f80 <memcmp@GLIBC_2.2.5>
    121b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001220 <strcmp@plt>:
    1220:	f3 0f 1e fa          	endbr64
    1224:	f2 ff 25 5d 0d 01 00 	bnd jmp *0x10d5d(%rip)        # 11f88 <strcmp@GLIBC_2.2.5>
    122b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001230 <memcpy@plt>:
    1230:	f3 0f 1e fa          	endbr64
    1234:	f2 ff 25 55 0d 01 00 	bnd jmp *0x10d55(%rip)        # 11f90 <memcpy@GLIBC_2.14>
    123b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001240 <malloc@plt>:
    1240:	f3 0f 1e fa          	endbr64
    1244:	f2 ff 25 4d 0d 01 00 	bnd jmp *0x10d4d(%rip)        # 11f98 <malloc@GLIBC_2.2.5>
    124b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001250 <memmove@plt>:
    1250:	f3 0f 1e fa          	endbr64
    1254:	f2 ff 25 45 0d 01 00 	bnd jmp *0x10d45(%rip)        # 11fa0 <memmove@GLIBC_2.2.5>
    125b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001260 <fopen@plt>:
    1260:	f3 0f 1e fa          	endbr64
    1264:	f2 ff 25 3d 0d 01 00 	bnd jmp *0x10d3d(%rip)        # 11fa8 <fopen@GLIBC_2.2.5>
    126b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001270 <exit@plt>:
    1270:	f3 0f 1e fa          	endbr64
    1274:	f2 ff 25 35 0d 01 00 	bnd jmp *0x10d35(%rip)        # 11fb0 <exit@GLIBC_2.2.5>
    127b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001280 <fwrite@plt>:
    1280:	f3 0f 1e fa          	endbr64
    1284:	f2 ff 25 2d 0d 01 00 	bnd jmp *0x10d2d(%rip)        # 11fb8 <fwrite@GLIBC_2.2.5>
    128b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001290 <getrandom@plt>:
    1290:	f3 0f 1e fa          	endbr64
    1294:	f2 ff 25 25 0d 01 00 	bnd jmp *0x10d25(%rip)        # 11fc0 <getrandom@GLIBC_2.25>
    129b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000012a0 <_start>:
    12a0:	f3 0f 1e fa          	endbr64
    12a4:	31 ed                	xor    %ebp,%ebp
    12a6:	49 89 d1             	mov    %rdx,%r9
    12a9:	5e                   	pop    %rsi
    12aa:	48 89 e2             	mov    %rsp,%rdx
    12ad:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    12b1:	50                   	push   %rax
    12b2:	54                   	push   %rsp
    12b3:	4c 8d 05 e6 cc 00 00 	lea    0xcce6(%rip),%r8        # dfa0 <__libc_csu_fini>
    12ba:	48 8d 0d 6f cc 00 00 	lea    0xcc6f(%rip),%rcx        # df30 <__libc_csu_init>
    12c1:	48 8d 3d aa 07 00 00 	lea    0x7aa(%rip),%rdi        # 1a72 <main>
    12c8:	ff 15 02 0d 01 00    	call   *0x10d02(%rip)        # 11fd0 <__libc_start_main@GLIBC_2.2.5>
    12ce:	f4                   	hlt
    12cf:	90                   	nop

00000000000012d0 <deregister_tm_clones>:
    12d0:	48 8d 3d 49 0d 01 00 	lea    0x10d49(%rip),%rdi        # 12020 <__TMC_END__>
    12d7:	48 8d 05 42 0d 01 00 	lea    0x10d42(%rip),%rax        # 12020 <__TMC_END__>
    12de:	48 39 f8             	cmp    %rdi,%rax
    12e1:	74 15                	je     12f8 <deregister_tm_clones+0x28>
    12e3:	48 8b 05 de 0c 01 00 	mov    0x10cde(%rip),%rax        # 11fc8 <_ITM_deregisterTMCloneTable>
    12ea:	48 85 c0             	test   %rax,%rax
    12ed:	74 09                	je     12f8 <deregister_tm_clones+0x28>
    12ef:	ff e0                	jmp    *%rax
    12f1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    12f8:	c3                   	ret
    12f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001300 <register_tm_clones>:
    1300:	48 8d 3d 19 0d 01 00 	lea    0x10d19(%rip),%rdi        # 12020 <__TMC_END__>
    1307:	48 8d 35 12 0d 01 00 	lea    0x10d12(%rip),%rsi        # 12020 <__TMC_END__>
    130e:	48 29 fe             	sub    %rdi,%rsi
    1311:	48 89 f0             	mov    %rsi,%rax
    1314:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1318:	48 c1 f8 03          	sar    $0x3,%rax
    131c:	48 01 c6             	add    %rax,%rsi
    131f:	48 d1 fe             	sar    $1,%rsi
    1322:	74 14                	je     1338 <register_tm_clones+0x38>
    1324:	48 8b 05 b5 0c 01 00 	mov    0x10cb5(%rip),%rax        # 11fe0 <_ITM_registerTMCloneTable>
    132b:	48 85 c0             	test   %rax,%rax
    132e:	74 08                	je     1338 <register_tm_clones+0x38>
    1330:	ff e0                	jmp    *%rax
    1332:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1338:	c3                   	ret
    1339:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001340 <__do_global_dtors_aux>:
    1340:	f3 0f 1e fa          	endbr64
    1344:	80 3d d5 0c 01 00 00 	cmpb   $0x0,0x10cd5(%rip)        # 12020 <__TMC_END__>
    134b:	75 2b                	jne    1378 <__do_global_dtors_aux+0x38>
    134d:	55                   	push   %rbp
    134e:	48 83 3d 92 0c 01 00 	cmpq   $0x0,0x10c92(%rip)        # 11fe8 <__cxa_finalize@GLIBC_2.2.5>
    1355:	00 
    1356:	48 89 e5             	mov    %rsp,%rbp
    1359:	74 0c                	je     1367 <__do_global_dtors_aux+0x27>
    135b:	48 8b 3d a6 0c 01 00 	mov    0x10ca6(%rip),%rdi        # 12008 <__dso_handle>
    1362:	e8 f9 fd ff ff       	call   1160 <__cxa_finalize@plt>
    1367:	e8 64 ff ff ff       	call   12d0 <deregister_tm_clones>
    136c:	c6 05 ad 0c 01 00 01 	movb   $0x1,0x10cad(%rip)        # 12020 <__TMC_END__>
    1373:	5d                   	pop    %rbp
    1374:	c3                   	ret
    1375:	0f 1f 00             	nopl   (%rax)
    1378:	c3                   	ret
    1379:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001380 <frame_dummy>:
    1380:	f3 0f 1e fa          	endbr64
    1384:	e9 77 ff ff ff       	jmp    1300 <register_tm_clones>

0000000000001389 <print_hex>:
    1389:	f3 0f 1e fa          	endbr64
    138d:	55                   	push   %rbp
    138e:	48 89 e5             	mov    %rsp,%rbp
    1391:	48 83 ec 20          	sub    $0x20,%rsp
    1395:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1399:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    139c:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    13a3:	eb 29                	jmp    13ce <print_hex+0x45>
    13a5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    13a8:	48 98                	cltq
    13aa:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    13ae:	48 01 d0             	add    %rdx,%rax
    13b1:	0f b6 00             	movzbl (%rax),%eax
    13b4:	0f b6 c0             	movzbl %al,%eax
    13b7:	89 c6                	mov    %eax,%esi
    13b9:	48 8d 3d 44 cc 00 00 	lea    0xcc44(%rip),%rdi        # e004 <_IO_stdin_used+0x4>
    13c0:	b8 00 00 00 00       	mov    $0x0,%eax
    13c5:	e8 16 fe ff ff       	call   11e0 <printf@plt>
    13ca:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    13ce:	8b 45 fc             	mov    -0x4(%rbp),%eax
    13d1:	3b 45 e4             	cmp    -0x1c(%rbp),%eax
    13d4:	7c cf                	jl     13a5 <print_hex+0x1c>
    13d6:	bf 0a 00 00 00       	mov    $0xa,%edi
    13db:	e8 a0 fd ff ff       	call   1180 <putchar@plt>
    13e0:	90                   	nop
    13e1:	c9                   	leave
    13e2:	c3                   	ret

00000000000013e3 <gen_key>:
    13e3:	f3 0f 1e fa          	endbr64
    13e7:	55                   	push   %rbp
    13e8:	48 89 e5             	mov    %rsp,%rbp
    13eb:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    13f2:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    13f7:	48 81 ec 60 06 00 00 	sub    $0x660,%rsp
    13fe:	48 89 bd a8 e9 ff ff 	mov    %rdi,-0x1658(%rbp)
    1405:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    140c:	00 00 
    140e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1412:	31 c0                	xor    %eax,%eax
    1414:	48 c7 85 40 ea ff ff 	movq   $0x0,-0x15c0(%rbp)
    141b:	00 00 00 00 
    141f:	48 c7 85 48 ea ff ff 	movq   $0x0,-0x15b8(%rbp)
    1426:	00 00 00 00 
    142a:	48 8d 85 50 ea ff ff 	lea    -0x15b0(%rbp),%rax
    1431:	ba a3 15 00 00       	mov    $0x15a3,%edx
    1436:	be 00 00 00 00       	mov    $0x0,%esi
    143b:	48 89 c7             	mov    %rax,%rdi
    143e:	e8 bd fd ff ff       	call   1200 <memset@plt>
    1443:	48 c7 85 e0 e9 ff ff 	movq   $0x0,-0x1620(%rbp)
    144a:	00 00 00 00 
    144e:	48 c7 85 e8 e9 ff ff 	movq   $0x0,-0x1618(%rbp)
    1455:	00 00 00 00 
    1459:	48 c7 85 f0 e9 ff ff 	movq   $0x0,-0x1610(%rbp)
    1460:	00 00 00 00 
    1464:	48 c7 85 f8 e9 ff ff 	movq   $0x0,-0x1608(%rbp)
    146b:	00 00 00 00 
    146f:	48 c7 85 00 ea ff ff 	movq   $0x0,-0x1600(%rbp)
    1476:	00 00 00 00 
    147a:	c6 85 08 ea ff ff 00 	movb   $0x0,-0x15f8(%rbp)
    1481:	48 8d 85 40 ea ff ff 	lea    -0x15c0(%rbp),%rax
    1488:	48 83 c8 01          	or     $0x1,%rax
    148c:	48 89 85 c0 e9 ff ff 	mov    %rax,-0x1640(%rbp)
    1493:	48 8d 85 e0 e9 ff ff 	lea    -0x1620(%rbp),%rax
    149a:	48 83 c8 01          	or     $0x1,%rax
    149e:	48 89 85 c8 e9 ff ff 	mov    %rax,-0x1638(%rbp)
    14a5:	48 c7 85 10 ea ff ff 	movq   $0x0,-0x15f0(%rbp)
    14ac:	00 00 00 00 
    14b0:	48 c7 85 18 ea ff ff 	movq   $0x0,-0x15e8(%rbp)
    14b7:	00 00 00 00 
    14bb:	48 c7 85 20 ea ff ff 	movq   $0x0,-0x15e0(%rbp)
    14c2:	00 00 00 00 
    14c6:	48 c7 85 28 ea ff ff 	movq   $0x0,-0x15d8(%rbp)
    14cd:	00 00 00 00 
    14d1:	48 c7 85 30 ea ff ff 	movq   $0x0,-0x15d0(%rbp)
    14d8:	00 00 00 00 
    14dc:	48 c7 85 38 ea ff ff 	movq   $0x0,-0x15c8(%rbp)
    14e3:	00 00 00 00 
    14e7:	48 8d 85 10 ea ff ff 	lea    -0x15f0(%rbp),%rax
    14ee:	ba 00 01 00 00       	mov    $0x100,%edx
    14f3:	be 00 00 00 00       	mov    $0x0,%esi
    14f8:	48 89 c7             	mov    %rax,%rdi
    14fb:	e8 d6 73 00 00       	call   88d6 <randombytes_init>
    1500:	48 8b 95 c8 e9 ff ff 	mov    -0x1638(%rbp),%rdx
    1507:	48 8b 8d c0 e9 ff ff 	mov    -0x1640(%rbp),%rcx
    150e:	48 8b 85 a8 e9 ff ff 	mov    -0x1658(%rbp),%rax
    1515:	48 89 ce             	mov    %rcx,%rsi
    1518:	48 89 c7             	mov    %rax,%rdi
    151b:	e8 13 3b 00 00       	call   5033 <mayo_keypair>
    1520:	89 85 bc e9 ff ff    	mov    %eax,-0x1644(%rbp)
    1526:	83 bd bc e9 ff ff 00 	cmpl   $0x0,-0x1644(%rbp)
    152d:	74 1b                	je     154a <gen_key+0x167>
    152f:	c7 85 bc e9 ff ff ff 	movl   $0xffffffff,-0x1644(%rbp)
    1536:	ff ff ff 
    1539:	48 8d 3d c9 ca 00 00 	lea    0xcac9(%rip),%rdi        # e009 <_IO_stdin_used+0x9>
    1540:	e8 5b fc ff ff       	call   11a0 <puts@plt>
    1545:	e9 b2 00 00 00       	jmp    15fc <gen_key+0x219>
    154a:	48 8d 35 c7 ca 00 00 	lea    0xcac7(%rip),%rsi        # e018 <_IO_stdin_used+0x18>
    1551:	48 8d 3d c2 ca 00 00 	lea    0xcac2(%rip),%rdi        # e01a <_IO_stdin_used+0x1a>
    1558:	e8 03 fd ff ff       	call   1260 <fopen@plt>
    155d:	48 89 85 d0 e9 ff ff 	mov    %rax,-0x1630(%rbp)
    1564:	48 8d 35 ad ca 00 00 	lea    0xcaad(%rip),%rsi        # e018 <_IO_stdin_used+0x18>
    156b:	48 8d 3d af ca 00 00 	lea    0xcaaf(%rip),%rdi        # e021 <_IO_stdin_used+0x21>
    1572:	e8 e9 fc ff ff       	call   1260 <fopen@plt>
    1577:	48 89 85 d8 e9 ff ff 	mov    %rax,-0x1628(%rbp)
    157e:	48 8b 85 a8 e9 ff ff 	mov    -0x1658(%rbp),%rax
    1585:	8b 40 44             	mov    0x44(%rax),%eax
    1588:	48 98                	cltq
    158a:	48 8b 95 d0 e9 ff ff 	mov    -0x1630(%rbp),%rdx
    1591:	48 8b bd c0 e9 ff ff 	mov    -0x1640(%rbp),%rdi
    1598:	48 89 d1             	mov    %rdx,%rcx
    159b:	48 89 c2             	mov    %rax,%rdx
    159e:	be 01 00 00 00       	mov    $0x1,%esi
    15a3:	e8 d8 fc ff ff       	call   1280 <fwrite@plt>
    15a8:	48 8b 85 a8 e9 ff ff 	mov    -0x1658(%rbp),%rax
    15af:	8b 40 40             	mov    0x40(%rax),%eax
    15b2:	48 98                	cltq
    15b4:	48 8b 95 d8 e9 ff ff 	mov    -0x1628(%rbp),%rdx
    15bb:	48 8b bd c8 e9 ff ff 	mov    -0x1638(%rbp),%rdi
    15c2:	48 89 d1             	mov    %rdx,%rcx
    15c5:	48 89 c2             	mov    %rax,%rdx
    15c8:	be 01 00 00 00       	mov    $0x1,%esi
    15cd:	e8 ae fc ff ff       	call   1280 <fwrite@plt>
    15d2:	48 8b 85 d0 e9 ff ff 	mov    -0x1630(%rbp),%rax
    15d9:	48 89 c7             	mov    %rax,%rdi
    15dc:	e8 df fb ff ff       	call   11c0 <fclose@plt>
    15e1:	48 8b 85 d8 e9 ff ff 	mov    -0x1628(%rbp),%rax
    15e8:	48 89 c7             	mov    %rax,%rdi
    15eb:	e8 d0 fb ff ff       	call   11c0 <fclose@plt>
    15f0:	48 8d 3d 31 ca 00 00 	lea    0xca31(%rip),%rdi        # e028 <_IO_stdin_used+0x28>
    15f7:	e8 a4 fb ff ff       	call   11a0 <puts@plt>
    15fc:	8b 85 bc e9 ff ff    	mov    -0x1644(%rbp),%eax
    1602:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    1606:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    160d:	00 00 
    160f:	74 05                	je     1616 <gen_key+0x233>
    1611:	e8 ba fb ff ff       	call   11d0 <__stack_chk_fail@plt>
    1616:	c9                   	leave
    1617:	c3                   	ret

0000000000001618 <get_signature>:
    1618:	f3 0f 1e fa          	endbr64
    161c:	55                   	push   %rbp
    161d:	48 89 e5             	mov    %rsp,%rbp
    1620:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    1627:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    162c:	48 81 ec a0 0a 00 00 	sub    $0xaa0,%rsp
    1633:	48 89 bd 68 e5 ff ff 	mov    %rdi,-0x1a98(%rbp)
    163a:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1641:	00 00 
    1643:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1647:	31 c0                	xor    %eax,%eax
    1649:	48 c7 85 40 ea ff ff 	movq   $0x0,-0x15c0(%rbp)
    1650:	00 00 00 00 
    1654:	48 c7 85 48 ea ff ff 	movq   $0x0,-0x15b8(%rbp)
    165b:	00 00 00 00 
    165f:	48 8d 85 50 ea ff ff 	lea    -0x15b0(%rbp),%rax
    1666:	ba a3 15 00 00       	mov    $0x15a3,%edx
    166b:	be 00 00 00 00       	mov    $0x0,%esi
    1670:	48 89 c7             	mov    %rax,%rdi
    1673:	e8 88 fb ff ff       	call   1200 <memset@plt>
    1678:	48 c7 85 f0 e5 ff ff 	movq   $0x0,-0x1a10(%rbp)
    167f:	00 00 00 00 
    1683:	48 c7 85 f8 e5 ff ff 	movq   $0x0,-0x1a08(%rbp)
    168a:	00 00 00 00 
    168e:	48 c7 85 00 e6 ff ff 	movq   $0x0,-0x1a00(%rbp)
    1695:	00 00 00 00 
    1699:	48 c7 85 08 e6 ff ff 	movq   $0x0,-0x19f8(%rbp)
    16a0:	00 00 00 00 
    16a4:	48 c7 85 10 e6 ff ff 	movq   $0x0,-0x19f0(%rbp)
    16ab:	00 00 00 00 
    16af:	c6 85 18 e6 ff ff 00 	movb   $0x0,-0x19e8(%rbp)
    16b6:	48 c7 85 50 e6 ff ff 	movq   $0x0,-0x19b0(%rbp)
    16bd:	00 00 00 00 
    16c1:	48 c7 85 58 e6 ff ff 	movq   $0x0,-0x19a8(%rbp)
    16c8:	00 00 00 00 
    16cc:	48 8d 85 60 e6 ff ff 	lea    -0x19a0(%rbp),%rax
    16d3:	ba d5 03 00 00       	mov    $0x3d5,%edx
    16d8:	be 00 00 00 00       	mov    $0x0,%esi
    16dd:	48 89 c7             	mov    %rax,%rdi
    16e0:	e8 1b fb ff ff       	call   1200 <memset@plt>
    16e5:	48 c7 85 c0 e5 ff ff 	movq   $0x0,-0x1a40(%rbp)
    16ec:	00 00 00 00 
    16f0:	48 c7 85 c8 e5 ff ff 	movq   $0x0,-0x1a38(%rbp)
    16f7:	00 00 00 00 
    16fb:	48 c7 85 d0 e5 ff ff 	movq   $0x0,-0x1a30(%rbp)
    1702:	00 00 00 00 
    1706:	48 c7 85 d8 e5 ff ff 	movq   $0x0,-0x1a28(%rbp)
    170d:	00 00 00 00 
    1711:	c6 85 e0 e5 ff ff 00 	movb   $0x0,-0x1a20(%rbp)
    1718:	48 8d 85 40 ea ff ff 	lea    -0x15c0(%rbp),%rax
    171f:	48 83 c8 01          	or     $0x1,%rax
    1723:	48 89 85 90 e5 ff ff 	mov    %rax,-0x1a70(%rbp)
    172a:	48 8d 85 f0 e5 ff ff 	lea    -0x1a10(%rbp),%rax
    1731:	48 83 c8 01          	or     $0x1,%rax
    1735:	48 89 85 98 e5 ff ff 	mov    %rax,-0x1a68(%rbp)
    173c:	48 8d 85 50 e6 ff ff 	lea    -0x19b0(%rbp),%rax
    1743:	48 83 c8 01          	or     $0x1,%rax
    1747:	48 89 85 a0 e5 ff ff 	mov    %rax,-0x1a60(%rbp)
    174e:	48 8d 85 c0 e5 ff ff 	lea    -0x1a40(%rbp),%rax
    1755:	48 83 c8 01          	or     $0x1,%rax
    1759:	48 89 85 a8 e5 ff ff 	mov    %rax,-0x1a58(%rbp)
    1760:	48 c7 85 20 e6 ff ff 	movq   $0x0,-0x19e0(%rbp)
    1767:	00 00 00 00 
    176b:	48 c7 85 28 e6 ff ff 	movq   $0x0,-0x19d8(%rbp)
    1772:	00 00 00 00 
    1776:	48 c7 85 30 e6 ff ff 	movq   $0x0,-0x19d0(%rbp)
    177d:	00 00 00 00 
    1781:	48 c7 85 38 e6 ff ff 	movq   $0x0,-0x19c8(%rbp)
    1788:	00 00 00 00 
    178c:	48 c7 85 40 e6 ff ff 	movq   $0x0,-0x19c0(%rbp)
    1793:	00 00 00 00 
    1797:	48 c7 85 48 e6 ff ff 	movq   $0x0,-0x19b8(%rbp)
    179e:	00 00 00 00 
    17a2:	48 8d 85 20 e6 ff ff 	lea    -0x19e0(%rbp),%rax
    17a9:	ba 00 01 00 00       	mov    $0x100,%edx
    17ae:	be 00 00 00 00       	mov    $0x0,%esi
    17b3:	48 89 c7             	mov    %rax,%rdi
    17b6:	e8 1b 71 00 00       	call   88d6 <randombytes_init>
    17bb:	48 c7 85 80 e5 ff ff 	movq   $0x20,-0x1a80(%rbp)
    17c2:	20 00 00 00 
    17c6:	48 8b 95 80 e5 ff ff 	mov    -0x1a80(%rbp),%rdx
    17cd:	48 8b 85 a8 e5 ff ff 	mov    -0x1a58(%rbp),%rax
    17d4:	48 89 d6             	mov    %rdx,%rsi
    17d7:	48 89 c7             	mov    %rax,%rdi
    17da:	e8 c8 70 00 00       	call   88a7 <randombytes>
    17df:	48 8d 35 51 c8 00 00 	lea    0xc851(%rip),%rsi        # e037 <_IO_stdin_used+0x37>
    17e6:	48 8d 3d 2d c8 00 00 	lea    0xc82d(%rip),%rdi        # e01a <_IO_stdin_used+0x1a>
    17ed:	e8 6e fa ff ff       	call   1260 <fopen@plt>
    17f2:	48 89 85 b0 e5 ff ff 	mov    %rax,-0x1a50(%rbp)
    17f9:	48 8d 35 37 c8 00 00 	lea    0xc837(%rip),%rsi        # e037 <_IO_stdin_used+0x37>
    1800:	48 8d 3d 1a c8 00 00 	lea    0xc81a(%rip),%rdi        # e021 <_IO_stdin_used+0x21>
    1807:	e8 54 fa ff ff       	call   1260 <fopen@plt>
    180c:	48 89 85 b8 e5 ff ff 	mov    %rax,-0x1a48(%rbp)
    1813:	c7 85 7c e5 ff ff 00 	movl   $0x0,-0x1a84(%rbp)
    181a:	00 00 00 
    181d:	48 83 bd b0 e5 ff ff 	cmpq   $0x0,-0x1a50(%rbp)
    1824:	00 
    1825:	74 0a                	je     1831 <get_signature+0x219>
    1827:	48 83 bd b8 e5 ff ff 	cmpq   $0x0,-0x1a48(%rbp)
    182e:	00 
    182f:	75 0f                	jne    1840 <get_signature+0x228>
    1831:	c7 85 7c e5 ff ff ff 	movl   $0xffffffff,-0x1a84(%rbp)
    1838:	ff ff ff 
    183b:	e9 8e 00 00 00       	jmp    18ce <get_signature+0x2b6>
    1840:	48 8b 85 68 e5 ff ff 	mov    -0x1a98(%rbp),%rax
    1847:	8b 40 44             	mov    0x44(%rax),%eax
    184a:	48 98                	cltq
    184c:	48 8b 95 b0 e5 ff ff 	mov    -0x1a50(%rbp),%rdx
    1853:	48 8b bd 90 e5 ff ff 	mov    -0x1a70(%rbp),%rdi
    185a:	48 89 d1             	mov    %rdx,%rcx
    185d:	48 89 c2             	mov    %rax,%rdx
    1860:	be 01 00 00 00       	mov    $0x1,%esi
    1865:	e8 46 f9 ff ff       	call   11b0 <fread@plt>
    186a:	48 8b 95 68 e5 ff ff 	mov    -0x1a98(%rbp),%rdx
    1871:	8b 52 44             	mov    0x44(%rdx),%edx
    1874:	48 63 d2             	movslq %edx,%rdx
    1877:	48 39 d0             	cmp    %rdx,%rax
    187a:	74 0c                	je     1888 <get_signature+0x270>
    187c:	c7 85 7c e5 ff ff ff 	movl   $0xffffffff,-0x1a84(%rbp)
    1883:	ff ff ff 
    1886:	eb 46                	jmp    18ce <get_signature+0x2b6>
    1888:	48 8b 85 68 e5 ff ff 	mov    -0x1a98(%rbp),%rax
    188f:	8b 40 40             	mov    0x40(%rax),%eax
    1892:	48 98                	cltq
    1894:	48 8b 95 b8 e5 ff ff 	mov    -0x1a48(%rbp),%rdx
    189b:	48 8b bd 98 e5 ff ff 	mov    -0x1a68(%rbp),%rdi
    18a2:	48 89 d1             	mov    %rdx,%rcx
    18a5:	48 89 c2             	mov    %rax,%rdx
    18a8:	be 01 00 00 00       	mov    $0x1,%esi
    18ad:	e8 fe f8 ff ff       	call   11b0 <fread@plt>
    18b2:	48 8b 95 68 e5 ff ff 	mov    -0x1a98(%rbp),%rdx
    18b9:	8b 52 40             	mov    0x40(%rdx),%edx
    18bc:	48 63 d2             	movslq %edx,%rdx
    18bf:	48 39 d0             	cmp    %rdx,%rax
    18c2:	74 0a                	je     18ce <get_signature+0x2b6>
    18c4:	c7 85 7c e5 ff ff ff 	movl   $0xffffffff,-0x1a84(%rbp)
    18cb:	ff ff ff 
    18ce:	48 83 bd b0 e5 ff ff 	cmpq   $0x0,-0x1a50(%rbp)
    18d5:	00 
    18d6:	74 0f                	je     18e7 <get_signature+0x2cf>
    18d8:	48 8b 85 b0 e5 ff ff 	mov    -0x1a50(%rbp),%rax
    18df:	48 89 c7             	mov    %rax,%rdi
    18e2:	e8 d9 f8 ff ff       	call   11c0 <fclose@plt>
    18e7:	48 83 bd b8 e5 ff ff 	cmpq   $0x0,-0x1a48(%rbp)
    18ee:	00 
    18ef:	74 0f                	je     1900 <get_signature+0x2e8>
    18f1:	48 8b 85 b8 e5 ff ff 	mov    -0x1a48(%rbp),%rax
    18f8:	48 89 c7             	mov    %rax,%rdi
    18fb:	e8 c0 f8 ff ff       	call   11c0 <fclose@plt>
    1900:	83 bd 7c e5 ff ff 00 	cmpl   $0x0,-0x1a84(%rbp)
    1907:	74 11                	je     191a <get_signature+0x302>
    1909:	48 8d 3d 29 c7 00 00 	lea    0xc729(%rip),%rdi        # e039 <_IO_stdin_used+0x39>
    1910:	e8 8b f8 ff ff       	call   11a0 <puts@plt>
    1915:	e9 3c 01 00 00       	jmp    1a56 <get_signature+0x43e>
    191a:	48 8b 85 68 e5 ff ff 	mov    -0x1a98(%rbp),%rax
    1921:	8b 40 48             	mov    0x48(%rax),%eax
    1924:	83 c0 20             	add    $0x20,%eax
    1927:	48 98                	cltq
    1929:	48 89 85 88 e5 ff ff 	mov    %rax,-0x1a78(%rbp)
    1930:	48 8b 8d 98 e5 ff ff 	mov    -0x1a68(%rbp),%rcx
    1937:	48 8b 95 a8 e5 ff ff 	mov    -0x1a58(%rbp),%rdx
    193e:	48 8d 85 88 e5 ff ff 	lea    -0x1a78(%rbp),%rax
    1945:	48 8b b5 a0 e5 ff ff 	mov    -0x1a60(%rbp),%rsi
    194c:	48 8b bd 68 e5 ff ff 	mov    -0x1a98(%rbp),%rdi
    1953:	49 89 c9             	mov    %rcx,%r9
    1956:	41 b8 20 00 00 00    	mov    $0x20,%r8d
    195c:	48 89 d1             	mov    %rdx,%rcx
    195f:	48 89 c2             	mov    %rax,%rdx
    1962:	e8 76 4f 00 00       	call   68dd <mayo_sign>
    1967:	89 85 7c e5 ff ff    	mov    %eax,-0x1a84(%rbp)
    196d:	83 bd 7c e5 ff ff 00 	cmpl   $0x0,-0x1a84(%rbp)
    1974:	74 1b                	je     1991 <get_signature+0x379>
    1976:	c7 85 7c e5 ff ff ff 	movl   $0xffffffff,-0x1a84(%rbp)
    197d:	ff ff ff 
    1980:	48 8d 3d c6 c6 00 00 	lea    0xc6c6(%rip),%rdi        # e04d <_IO_stdin_used+0x4d>
    1987:	e8 14 f8 ff ff       	call   11a0 <puts@plt>
    198c:	e9 c5 00 00 00       	jmp    1a56 <get_signature+0x43e>
    1991:	48 8d 3d c2 c6 00 00 	lea    0xc6c2(%rip),%rdi        # e05a <_IO_stdin_used+0x5a>
    1998:	b8 00 00 00 00       	mov    $0x0,%eax
    199d:	e8 3e f8 ff ff       	call   11e0 <printf@plt>
    19a2:	48 8b 85 68 e5 ff ff 	mov    -0x1a98(%rbp),%rax
    19a9:	8b 50 44             	mov    0x44(%rax),%edx
    19ac:	48 8b 85 90 e5 ff ff 	mov    -0x1a70(%rbp),%rax
    19b3:	89 d6                	mov    %edx,%esi
    19b5:	48 89 c7             	mov    %rax,%rdi
    19b8:	e8 cc f9 ff ff       	call   1389 <print_hex>
    19bd:	48 8d 3d 9b c6 00 00 	lea    0xc69b(%rip),%rdi        # e05f <_IO_stdin_used+0x5f>
    19c4:	b8 00 00 00 00       	mov    $0x0,%eax
    19c9:	e8 12 f8 ff ff       	call   11e0 <printf@plt>
    19ce:	48 8b 85 88 e5 ff ff 	mov    -0x1a78(%rbp),%rax
    19d5:	89 c2                	mov    %eax,%edx
    19d7:	48 8b 85 a0 e5 ff ff 	mov    -0x1a60(%rbp),%rax
    19de:	89 d6                	mov    %edx,%esi
    19e0:	48 89 c7             	mov    %rax,%rdi
    19e3:	e8 a1 f9 ff ff       	call   1389 <print_hex>
    19e8:	48 8b 8d 88 e5 ff ff 	mov    -0x1a78(%rbp),%rcx
    19ef:	4c 8b 85 90 e5 ff ff 	mov    -0x1a70(%rbp),%r8
    19f6:	48 8b 95 a0 e5 ff ff 	mov    -0x1a60(%rbp),%rdx
    19fd:	48 8d 85 80 e5 ff ff 	lea    -0x1a80(%rbp),%rax
    1a04:	48 8b b5 a8 e5 ff ff 	mov    -0x1a58(%rbp),%rsi
    1a0b:	48 8b bd 68 e5 ff ff 	mov    -0x1a98(%rbp),%rdi
    1a12:	4d 89 c1             	mov    %r8,%r9
    1a15:	49 89 c8             	mov    %rcx,%r8
    1a18:	48 89 d1             	mov    %rdx,%rcx
    1a1b:	48 89 c2             	mov    %rax,%rdx
    1a1e:	e8 ae 4f 00 00       	call   69d1 <mayo_open>
    1a23:	89 85 7c e5 ff ff    	mov    %eax,-0x1a84(%rbp)
    1a29:	83 bd 7c e5 ff ff 00 	cmpl   $0x0,-0x1a84(%rbp)
    1a30:	74 18                	je     1a4a <get_signature+0x432>
    1a32:	c7 85 7c e5 ff ff ff 	movl   $0xffffffff,-0x1a84(%rbp)
    1a39:	ff ff ff 
    1a3c:	48 8d 3d 21 c6 00 00 	lea    0xc621(%rip),%rdi        # e064 <_IO_stdin_used+0x64>
    1a43:	e8 58 f7 ff ff       	call   11a0 <puts@plt>
    1a48:	eb 0c                	jmp    1a56 <get_signature+0x43e>
    1a4a:	48 8d 3d 22 c6 00 00 	lea    0xc622(%rip),%rdi        # e073 <_IO_stdin_used+0x73>
    1a51:	e8 4a f7 ff ff       	call   11a0 <puts@plt>
    1a56:	8b 85 7c e5 ff ff    	mov    -0x1a84(%rbp),%eax
    1a5c:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    1a60:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    1a67:	00 00 
    1a69:	74 05                	je     1a70 <get_signature+0x458>
    1a6b:	e8 60 f7 ff ff       	call   11d0 <__stack_chk_fail@plt>
    1a70:	c9                   	leave
    1a71:	c3                   	ret

0000000000001a72 <main>:
    1a72:	f3 0f 1e fa          	endbr64
    1a76:	55                   	push   %rbp
    1a77:	48 89 e5             	mov    %rsp,%rbp
    1a7a:	48 83 ec 20          	sub    $0x20,%rsp
    1a7e:	89 7d ec             	mov    %edi,-0x14(%rbp)
    1a81:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1a85:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1a8c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1a90:	48 83 c0 08          	add    $0x8,%rax
    1a94:	48 8b 00             	mov    (%rax),%rax
    1a97:	48 8d 35 e5 c5 00 00 	lea    0xc5e5(%rip),%rsi        # e083 <_IO_stdin_used+0x83>
    1a9e:	48 89 c7             	mov    %rax,%rdi
    1aa1:	e8 7a f7 ff ff       	call   1220 <strcmp@plt>
    1aa6:	85 c0                	test   %eax,%eax
    1aa8:	75 10                	jne    1aba <main+0x48>
    1aaa:	48 8d 05 8f 00 01 00 	lea    0x1008f(%rip),%rax        # 11b40 <MAYO_1>
    1ab1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1ab5:	e9 94 00 00 00       	jmp    1b4e <main+0xdc>
    1aba:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1abe:	48 83 c0 08          	add    $0x8,%rax
    1ac2:	48 8b 00             	mov    (%rax),%rax
    1ac5:	48 8d 35 be c5 00 00 	lea    0xc5be(%rip),%rsi        # e08a <_IO_stdin_used+0x8a>
    1acc:	48 89 c7             	mov    %rax,%rdi
    1acf:	e8 4c f7 ff ff       	call   1220 <strcmp@plt>
    1ad4:	85 c0                	test   %eax,%eax
    1ad6:	75 0d                	jne    1ae5 <main+0x73>
    1ad8:	48 8d 05 e1 00 01 00 	lea    0x100e1(%rip),%rax        # 11bc0 <MAYO_2>
    1adf:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1ae3:	eb 69                	jmp    1b4e <main+0xdc>
    1ae5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1ae9:	48 83 c0 08          	add    $0x8,%rax
    1aed:	48 8b 00             	mov    (%rax),%rax
    1af0:	48 8d 35 9a c5 00 00 	lea    0xc59a(%rip),%rsi        # e091 <_IO_stdin_used+0x91>
    1af7:	48 89 c7             	mov    %rax,%rdi
    1afa:	e8 21 f7 ff ff       	call   1220 <strcmp@plt>
    1aff:	85 c0                	test   %eax,%eax
    1b01:	75 0d                	jne    1b10 <main+0x9e>
    1b03:	48 8d 05 36 01 01 00 	lea    0x10136(%rip),%rax        # 11c40 <MAYO_3>
    1b0a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1b0e:	eb 3e                	jmp    1b4e <main+0xdc>
    1b10:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1b14:	48 83 c0 08          	add    $0x8,%rax
    1b18:	48 8b 00             	mov    (%rax),%rax
    1b1b:	48 8d 35 76 c5 00 00 	lea    0xc576(%rip),%rsi        # e098 <_IO_stdin_used+0x98>
    1b22:	48 89 c7             	mov    %rax,%rdi
    1b25:	e8 f6 f6 ff ff       	call   1220 <strcmp@plt>
    1b2a:	85 c0                	test   %eax,%eax
    1b2c:	75 0d                	jne    1b3b <main+0xc9>
    1b2e:	48 8d 05 8b 01 01 00 	lea    0x1018b(%rip),%rax        # 11cc0 <MAYO_5>
    1b35:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1b39:	eb 13                	jmp    1b4e <main+0xdc>
    1b3b:	48 8d 3d 5d c5 00 00 	lea    0xc55d(%rip),%rdi        # e09f <_IO_stdin_used+0x9f>
    1b42:	e8 59 f6 ff ff       	call   11a0 <puts@plt>
    1b47:	b8 01 00 00 00       	mov    $0x1,%eax
    1b4c:	eb 47                	jmp    1b95 <main+0x123>
    1b4e:	83 7d ec 02          	cmpl   $0x2,-0x14(%rbp)
    1b52:	7e 2f                	jle    1b83 <main+0x111>
    1b54:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1b58:	48 83 c0 10          	add    $0x10,%rax
    1b5c:	48 8b 00             	mov    (%rax),%rax
    1b5f:	48 8d 35 4f c5 00 00 	lea    0xc54f(%rip),%rsi        # e0b5 <_IO_stdin_used+0xb5>
    1b66:	48 89 c7             	mov    %rax,%rdi
    1b69:	e8 b2 f6 ff ff       	call   1220 <strcmp@plt>
    1b6e:	85 c0                	test   %eax,%eax
    1b70:	75 11                	jne    1b83 <main+0x111>
    1b72:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1b76:	48 89 c7             	mov    %rax,%rdi
    1b79:	e8 65 f8 ff ff       	call   13e3 <gen_key>
    1b7e:	89 45 f4             	mov    %eax,-0xc(%rbp)
    1b81:	eb 0f                	jmp    1b92 <main+0x120>
    1b83:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1b87:	48 89 c7             	mov    %rax,%rdi
    1b8a:	e8 89 fa ff ff       	call   1618 <get_signature>
    1b8f:	89 45 f4             	mov    %eax,-0xc(%rbp)
    1b92:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1b95:	c9                   	leave
    1b96:	c3                   	ret

0000000000001b97 <mul_f>:
    1b97:	55                   	push   %rbp
    1b98:	48 89 e5             	mov    %rsp,%rbp
    1b9b:	89 fa                	mov    %edi,%edx
    1b9d:	89 f0                	mov    %esi,%eax
    1b9f:	88 55 ec             	mov    %dl,-0x14(%rbp)
    1ba2:	88 45 e8             	mov    %al,-0x18(%rbp)
    1ba5:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    1ba9:	83 e0 01             	and    $0x1,%eax
    1bac:	89 c2                	mov    %eax,%edx
    1bae:	0f b6 45 e8          	movzbl -0x18(%rbp),%eax
    1bb2:	0f af c2             	imul   %edx,%eax
    1bb5:	88 45 fd             	mov    %al,-0x3(%rbp)
    1bb8:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    1bbc:	83 e0 02             	and    $0x2,%eax
    1bbf:	f6 65 e8             	mulb   -0x18(%rbp)
    1bc2:	89 c2                	mov    %eax,%edx
    1bc4:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    1bc8:	31 d0                	xor    %edx,%eax
    1bca:	88 45 fd             	mov    %al,-0x3(%rbp)
    1bcd:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    1bd1:	83 e0 04             	and    $0x4,%eax
    1bd4:	f6 65 e8             	mulb   -0x18(%rbp)
    1bd7:	89 c2                	mov    %eax,%edx
    1bd9:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    1bdd:	31 d0                	xor    %edx,%eax
    1bdf:	88 45 fd             	mov    %al,-0x3(%rbp)
    1be2:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    1be6:	83 e0 08             	and    $0x8,%eax
    1be9:	f6 65 e8             	mulb   -0x18(%rbp)
    1bec:	89 c2                	mov    %eax,%edx
    1bee:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    1bf2:	31 d0                	xor    %edx,%eax
    1bf4:	88 45 fd             	mov    %al,-0x3(%rbp)
    1bf7:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    1bfb:	83 e0 f0             	and    $0xfffffff0,%eax
    1bfe:	88 45 fe             	mov    %al,-0x2(%rbp)
    1c01:	0f b6 45 fe          	movzbl -0x2(%rbp),%eax
    1c05:	c0 e8 04             	shr    $0x4,%al
    1c08:	32 45 fd             	xor    -0x3(%rbp),%al
    1c0b:	89 c2                	mov    %eax,%edx
    1c0d:	0f b6 45 fe          	movzbl -0x2(%rbp),%eax
    1c11:	c0 e8 03             	shr    $0x3,%al
    1c14:	31 d0                	xor    %edx,%eax
    1c16:	83 e0 0f             	and    $0xf,%eax
    1c19:	88 45 ff             	mov    %al,-0x1(%rbp)
    1c1c:	0f b6 45 ff          	movzbl -0x1(%rbp),%eax
    1c20:	5d                   	pop    %rbp
    1c21:	c3                   	ret

0000000000001c22 <add_f>:
    1c22:	55                   	push   %rbp
    1c23:	48 89 e5             	mov    %rsp,%rbp
    1c26:	89 fa                	mov    %edi,%edx
    1c28:	89 f0                	mov    %esi,%eax
    1c2a:	88 55 fc             	mov    %dl,-0x4(%rbp)
    1c2d:	88 45 f8             	mov    %al,-0x8(%rbp)
    1c30:	0f b6 45 fc          	movzbl -0x4(%rbp),%eax
    1c34:	32 45 f8             	xor    -0x8(%rbp),%al
    1c37:	5d                   	pop    %rbp
    1c38:	c3                   	ret

0000000000001c39 <lincomb>:
    1c39:	55                   	push   %rbp
    1c3a:	48 89 e5             	mov    %rsp,%rbp
    1c3d:	53                   	push   %rbx
    1c3e:	48 83 ec 28          	sub    $0x28,%rsp
    1c42:	48 89 7d e0          	mov    %rdi,-0x20(%rbp)
    1c46:	48 89 75 d8          	mov    %rsi,-0x28(%rbp)
    1c4a:	89 55 d4             	mov    %edx,-0x2c(%rbp)
    1c4d:	89 4d d0             	mov    %ecx,-0x30(%rbp)
    1c50:	c6 45 f3 00          	movb   $0x0,-0xd(%rbp)
    1c54:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1c5b:	eb 45                	jmp    1ca2 <lincomb+0x69>
    1c5d:	0f b6 5d f3          	movzbl -0xd(%rbp),%ebx
    1c61:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1c65:	0f b6 00             	movzbl (%rax),%eax
    1c68:	0f b6 d0             	movzbl %al,%edx
    1c6b:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1c6e:	48 98                	cltq
    1c70:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1c74:	48 01 c8             	add    %rcx,%rax
    1c77:	0f b6 00             	movzbl (%rax),%eax
    1c7a:	0f b6 c0             	movzbl %al,%eax
    1c7d:	89 d6                	mov    %edx,%esi
    1c7f:	89 c7                	mov    %eax,%edi
    1c81:	e8 11 ff ff ff       	call   1b97 <mul_f>
    1c86:	0f b6 c0             	movzbl %al,%eax
    1c89:	89 de                	mov    %ebx,%esi
    1c8b:	89 c7                	mov    %eax,%edi
    1c8d:	e8 90 ff ff ff       	call   1c22 <add_f>
    1c92:	88 45 f3             	mov    %al,-0xd(%rbp)
    1c95:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1c99:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1c9c:	48 98                	cltq
    1c9e:	48 01 45 d8          	add    %rax,-0x28(%rbp)
    1ca2:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1ca5:	3b 45 d4             	cmp    -0x2c(%rbp),%eax
    1ca8:	7c b3                	jl     1c5d <lincomb+0x24>
    1caa:	0f b6 45 f3          	movzbl -0xd(%rbp),%eax
    1cae:	48 83 c4 28          	add    $0x28,%rsp
    1cb2:	5b                   	pop    %rbx
    1cb3:	5d                   	pop    %rbp
    1cb4:	c3                   	ret

0000000000001cb5 <mat_mul>:
    1cb5:	55                   	push   %rbp
    1cb6:	48 89 e5             	mov    %rsp,%rbp
    1cb9:	48 83 ec 38          	sub    $0x38,%rsp
    1cbd:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1cc1:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1cc5:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    1cc9:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
    1ccc:	44 89 45 d0          	mov    %r8d,-0x30(%rbp)
    1cd0:	44 89 4d cc          	mov    %r9d,-0x34(%rbp)
    1cd4:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    1cdb:	eb 4c                	jmp    1d29 <mat_mul+0x74>
    1cdd:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1ce4:	eb 2e                	jmp    1d14 <mat_mul+0x5f>
    1ce6:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ce9:	48 98                	cltq
    1ceb:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1cef:	48 8d 34 10          	lea    (%rax,%rdx,1),%rsi
    1cf3:	8b 4d cc             	mov    -0x34(%rbp),%ecx
    1cf6:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1cf9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1cfd:	48 89 c7             	mov    %rax,%rdi
    1d00:	e8 34 ff ff ff       	call   1c39 <lincomb>
    1d05:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    1d09:	88 02                	mov    %al,(%rdx)
    1d0b:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1d0f:	48 83 45 d8 01       	addq   $0x1,-0x28(%rbp)
    1d14:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1d17:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    1d1a:	7c ca                	jl     1ce6 <mat_mul+0x31>
    1d1c:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    1d20:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1d23:	48 98                	cltq
    1d25:	48 01 45 e8          	add    %rax,-0x18(%rbp)
    1d29:	8b 45 f8             	mov    -0x8(%rbp),%eax
    1d2c:	3b 45 d0             	cmp    -0x30(%rbp),%eax
    1d2f:	7c ac                	jl     1cdd <mat_mul+0x28>
    1d31:	90                   	nop
    1d32:	90                   	nop
    1d33:	c9                   	leave
    1d34:	c3                   	ret

0000000000001d35 <gf16v_mul_u64>:
    1d35:	55                   	push   %rbp
    1d36:	48 89 e5             	mov    %rsp,%rbp
    1d39:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    1d3d:	89 f0                	mov    %esi,%eax
    1d3f:	88 45 c4             	mov    %al,-0x3c(%rbp)
    1d42:	48 b8 88 88 88 88 88 	movabs $0x8888888888888888,%rax
    1d49:	88 88 88 
    1d4c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    1d50:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1d54:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    1d58:	0f b6 45 c4          	movzbl -0x3c(%rbp),%eax
    1d5c:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    1d60:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1d64:	83 e0 01             	and    $0x1,%eax
    1d67:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1d6b:	48 0f af c2          	imul   %rdx,%rax
    1d6f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1d73:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1d77:	48 23 45 d8          	and    -0x28(%rbp),%rax
    1d7b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1d7f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1d83:	48 31 45 e0          	xor    %rax,-0x20(%rbp)
    1d87:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1d8b:	48 8d 0c 00          	lea    (%rax,%rax,1),%rcx
    1d8f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1d93:	48 c1 e8 03          	shr    $0x3,%rax
    1d97:	48 89 c2             	mov    %rax,%rdx
    1d9a:	48 89 d0             	mov    %rdx,%rax
    1d9d:	48 01 c0             	add    %rax,%rax
    1da0:	48 01 d0             	add    %rdx,%rax
    1da3:	48 31 c8             	xor    %rcx,%rax
    1da6:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    1daa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1dae:	48 d1 e8             	shr    $1,%rax
    1db1:	83 e0 01             	and    $0x1,%eax
    1db4:	48 0f af 45 e0       	imul   -0x20(%rbp),%rax
    1db9:	48 31 45 f0          	xor    %rax,-0x10(%rbp)
    1dbd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1dc1:	48 23 45 d8          	and    -0x28(%rbp),%rax
    1dc5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1dc9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1dcd:	48 31 45 e0          	xor    %rax,-0x20(%rbp)
    1dd1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1dd5:	48 8d 0c 00          	lea    (%rax,%rax,1),%rcx
    1dd9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1ddd:	48 c1 e8 03          	shr    $0x3,%rax
    1de1:	48 89 c2             	mov    %rax,%rdx
    1de4:	48 89 d0             	mov    %rdx,%rax
    1de7:	48 01 c0             	add    %rax,%rax
    1dea:	48 01 d0             	add    %rdx,%rax
    1ded:	48 31 c8             	xor    %rcx,%rax
    1df0:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    1df4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1df8:	48 c1 e8 02          	shr    $0x2,%rax
    1dfc:	83 e0 01             	and    $0x1,%eax
    1dff:	48 0f af 45 e0       	imul   -0x20(%rbp),%rax
    1e04:	48 31 45 f0          	xor    %rax,-0x10(%rbp)
    1e08:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1e0c:	48 23 45 d8          	and    -0x28(%rbp),%rax
    1e10:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1e14:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1e18:	48 31 45 e0          	xor    %rax,-0x20(%rbp)
    1e1c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1e20:	48 8d 0c 00          	lea    (%rax,%rax,1),%rcx
    1e24:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1e28:	48 c1 e8 03          	shr    $0x3,%rax
    1e2c:	48 89 c2             	mov    %rax,%rdx
    1e2f:	48 89 d0             	mov    %rdx,%rax
    1e32:	48 01 c0             	add    %rax,%rax
    1e35:	48 01 d0             	add    %rdx,%rax
    1e38:	48 31 c8             	xor    %rcx,%rax
    1e3b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    1e3f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e43:	48 c1 e8 03          	shr    $0x3,%rax
    1e47:	83 e0 01             	and    $0x1,%eax
    1e4a:	48 0f af 45 e0       	imul   -0x20(%rbp),%rax
    1e4f:	48 31 45 f0          	xor    %rax,-0x10(%rbp)
    1e53:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1e57:	5d                   	pop    %rbp
    1e58:	c3                   	ret

0000000000001e59 <m_vec_copy>:
    1e59:	55                   	push   %rbp
    1e5a:	48 89 e5             	mov    %rsp,%rbp
    1e5d:	89 7d ec             	mov    %edi,-0x14(%rbp)
    1e60:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1e64:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    1e68:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1e6f:	eb 32                	jmp    1ea3 <m_vec_copy+0x4a>
    1e71:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1e74:	48 98                	cltq
    1e76:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1e7d:	00 
    1e7e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1e82:	48 01 c2             	add    %rax,%rdx
    1e85:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1e88:	48 98                	cltq
    1e8a:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    1e91:	00 
    1e92:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1e96:	48 01 c8             	add    %rcx,%rax
    1e99:	48 8b 12             	mov    (%rdx),%rdx
    1e9c:	48 89 10             	mov    %rdx,(%rax)
    1e9f:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1ea3:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ea6:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    1ea9:	7c c6                	jl     1e71 <m_vec_copy+0x18>
    1eab:	90                   	nop
    1eac:	90                   	nop
    1ead:	5d                   	pop    %rbp
    1eae:	c3                   	ret

0000000000001eaf <m_vec_add>:
    1eaf:	55                   	push   %rbp
    1eb0:	48 89 e5             	mov    %rsp,%rbp
    1eb3:	89 7d ec             	mov    %edi,-0x14(%rbp)
    1eb6:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1eba:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    1ebe:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1ec5:	eb 4c                	jmp    1f13 <m_vec_add+0x64>
    1ec7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1eca:	48 98                	cltq
    1ecc:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1ed3:	00 
    1ed4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ed8:	48 01 d0             	add    %rdx,%rax
    1edb:	48 8b 08             	mov    (%rax),%rcx
    1ede:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ee1:	48 98                	cltq
    1ee3:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1eea:	00 
    1eeb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1eef:	48 01 d0             	add    %rdx,%rax
    1ef2:	48 8b 10             	mov    (%rax),%rdx
    1ef5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ef8:	48 98                	cltq
    1efa:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    1f01:	00 
    1f02:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f06:	48 01 f0             	add    %rsi,%rax
    1f09:	48 31 ca             	xor    %rcx,%rdx
    1f0c:	48 89 10             	mov    %rdx,(%rax)
    1f0f:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1f13:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1f16:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    1f19:	7c ac                	jl     1ec7 <m_vec_add+0x18>
    1f1b:	90                   	nop
    1f1c:	90                   	nop
    1f1d:	5d                   	pop    %rbp
    1f1e:	c3                   	ret

0000000000001f1f <m_vec_mul_add>:
    1f1f:	55                   	push   %rbp
    1f20:	48 89 e5             	mov    %rsp,%rbp
    1f23:	48 83 ec 28          	sub    $0x28,%rsp
    1f27:	89 7d ec             	mov    %edi,-0x14(%rbp)
    1f2a:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1f2e:	89 d0                	mov    %edx,%eax
    1f30:	48 89 4d d8          	mov    %rcx,-0x28(%rbp)
    1f34:	88 45 e8             	mov    %al,-0x18(%rbp)
    1f37:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1f3e:	eb 5d                	jmp    1f9d <m_vec_mul_add+0x7e>
    1f40:	0f b6 45 e8          	movzbl -0x18(%rbp),%eax
    1f44:	8b 55 fc             	mov    -0x4(%rbp),%edx
    1f47:	48 63 d2             	movslq %edx,%rdx
    1f4a:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    1f51:	00 
    1f52:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1f56:	48 01 ca             	add    %rcx,%rdx
    1f59:	48 8b 12             	mov    (%rdx),%rdx
    1f5c:	89 c6                	mov    %eax,%esi
    1f5e:	48 89 d7             	mov    %rdx,%rdi
    1f61:	e8 cf fd ff ff       	call   1d35 <gf16v_mul_u64>
    1f66:	8b 55 fc             	mov    -0x4(%rbp),%edx
    1f69:	48 63 d2             	movslq %edx,%rdx
    1f6c:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    1f73:	00 
    1f74:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    1f78:	48 01 ca             	add    %rcx,%rdx
    1f7b:	48 8b 0a             	mov    (%rdx),%rcx
    1f7e:	8b 55 fc             	mov    -0x4(%rbp),%edx
    1f81:	48 63 d2             	movslq %edx,%rdx
    1f84:	48 8d 34 d5 00 00 00 	lea    0x0(,%rdx,8),%rsi
    1f8b:	00 
    1f8c:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    1f90:	48 01 f2             	add    %rsi,%rdx
    1f93:	48 31 c8             	xor    %rcx,%rax
    1f96:	48 89 02             	mov    %rax,(%rdx)
    1f99:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1f9d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1fa0:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    1fa3:	7c 9b                	jl     1f40 <m_vec_mul_add+0x21>
    1fa5:	90                   	nop
    1fa6:	90                   	nop
    1fa7:	c9                   	leave
    1fa8:	c3                   	ret

0000000000001fa9 <m_vec_mul_add_x>:
    1fa9:	55                   	push   %rbp
    1faa:	48 89 e5             	mov    %rsp,%rbp
    1fad:	89 7d dc             	mov    %edi,-0x24(%rbp)
    1fb0:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1fb4:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    1fb8:	48 b8 88 88 88 88 88 	movabs $0x8888888888888888,%rax
    1fbf:	88 88 88 
    1fc2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1fc6:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    1fcd:	e9 8d 00 00 00       	jmp    205f <m_vec_mul_add_x+0xb6>
    1fd2:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1fd5:	48 98                	cltq
    1fd7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1fde:	00 
    1fdf:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1fe3:	48 01 d0             	add    %rdx,%rax
    1fe6:	48 8b 00             	mov    (%rax),%rax
    1fe9:	48 23 45 f0          	and    -0x10(%rbp),%rax
    1fed:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1ff1:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1ff4:	48 98                	cltq
    1ff6:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1ffd:	00 
    1ffe:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    2002:	48 01 d0             	add    %rdx,%rax
    2005:	48 8b 08             	mov    (%rax),%rcx
    2008:	8b 45 ec             	mov    -0x14(%rbp),%eax
    200b:	48 98                	cltq
    200d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2014:	00 
    2015:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2019:	48 01 d0             	add    %rdx,%rax
    201c:	48 8b 00             	mov    (%rax),%rax
    201f:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    2023:	48 8d 34 00          	lea    (%rax,%rax,1),%rsi
    2027:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    202b:	48 c1 e8 03          	shr    $0x3,%rax
    202f:	48 89 c2             	mov    %rax,%rdx
    2032:	48 89 d0             	mov    %rdx,%rax
    2035:	48 01 c0             	add    %rax,%rax
    2038:	48 01 d0             	add    %rdx,%rax
    203b:	48 31 c6             	xor    %rax,%rsi
    203e:	48 89 f2             	mov    %rsi,%rdx
    2041:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2044:	48 98                	cltq
    2046:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    204d:	00 
    204e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    2052:	48 01 f0             	add    %rsi,%rax
    2055:	48 31 ca             	xor    %rcx,%rdx
    2058:	48 89 10             	mov    %rdx,(%rax)
    205b:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    205f:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2062:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    2065:	0f 8c 67 ff ff ff    	jl     1fd2 <m_vec_mul_add_x+0x29>
    206b:	90                   	nop
    206c:	90                   	nop
    206d:	5d                   	pop    %rbp
    206e:	c3                   	ret

000000000000206f <m_vec_mul_add_x_inv>:
    206f:	55                   	push   %rbp
    2070:	48 89 e5             	mov    %rsp,%rbp
    2073:	89 7d dc             	mov    %edi,-0x24(%rbp)
    2076:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    207a:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    207e:	48 b8 11 11 11 11 11 	movabs $0x1111111111111111,%rax
    2085:	11 11 11 
    2088:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    208c:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    2093:	e9 89 00 00 00       	jmp    2121 <m_vec_mul_add_x_inv+0xb2>
    2098:	8b 45 ec             	mov    -0x14(%rbp),%eax
    209b:	48 98                	cltq
    209d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    20a4:	00 
    20a5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    20a9:	48 01 d0             	add    %rdx,%rax
    20ac:	48 8b 00             	mov    (%rax),%rax
    20af:	48 23 45 f0          	and    -0x10(%rbp),%rax
    20b3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    20b7:	8b 45 ec             	mov    -0x14(%rbp),%eax
    20ba:	48 98                	cltq
    20bc:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    20c3:	00 
    20c4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    20c8:	48 01 d0             	add    %rdx,%rax
    20cb:	48 8b 08             	mov    (%rax),%rcx
    20ce:	8b 45 ec             	mov    -0x14(%rbp),%eax
    20d1:	48 98                	cltq
    20d3:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    20da:	00 
    20db:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    20df:	48 01 d0             	add    %rdx,%rax
    20e2:	48 8b 00             	mov    (%rax),%rax
    20e5:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    20e9:	48 d1 e8             	shr    $1,%rax
    20ec:	48 89 c6             	mov    %rax,%rsi
    20ef:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    20f3:	48 89 d0             	mov    %rdx,%rax
    20f6:	48 c1 e0 03          	shl    $0x3,%rax
    20fa:	48 01 d0             	add    %rdx,%rax
    20fd:	48 31 c6             	xor    %rax,%rsi
    2100:	48 89 f2             	mov    %rsi,%rdx
    2103:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2106:	48 98                	cltq
    2108:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    210f:	00 
    2110:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    2114:	48 01 f0             	add    %rsi,%rax
    2117:	48 31 ca             	xor    %rcx,%rdx
    211a:	48 89 10             	mov    %rdx,(%rax)
    211d:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    2121:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2124:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    2127:	0f 8c 6b ff ff ff    	jl     2098 <m_vec_mul_add_x_inv+0x29>
    212d:	90                   	nop
    212e:	90                   	nop
    212f:	5d                   	pop    %rbp
    2130:	c3                   	ret

0000000000002131 <m_vec_multiply_bins>:
    2131:	55                   	push   %rbp
    2132:	48 89 e5             	mov    %rsp,%rbp
    2135:	48 83 ec 18          	sub    $0x18,%rsp
    2139:	89 7d fc             	mov    %edi,-0x4(%rbp)
    213c:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    2140:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    2144:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2147:	89 d0                	mov    %edx,%eax
    2149:	c1 e0 02             	shl    $0x2,%eax
    214c:	01 d0                	add    %edx,%eax
    214e:	01 c0                	add    %eax,%eax
    2150:	48 98                	cltq
    2152:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2159:	00 
    215a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    215e:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    2162:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2165:	89 d0                	mov    %edx,%eax
    2167:	c1 e0 02             	shl    $0x2,%eax
    216a:	01 d0                	add    %edx,%eax
    216c:	48 98                	cltq
    216e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2175:	00 
    2176:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    217a:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    217e:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2181:	48 89 f2             	mov    %rsi,%rdx
    2184:	48 89 ce             	mov    %rcx,%rsi
    2187:	89 c7                	mov    %eax,%edi
    2189:	e8 e1 fe ff ff       	call   206f <m_vec_mul_add_x_inv>
    218e:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2191:	89 d0                	mov    %edx,%eax
    2193:	01 c0                	add    %eax,%eax
    2195:	01 d0                	add    %edx,%eax
    2197:	c1 e0 02             	shl    $0x2,%eax
    219a:	48 98                	cltq
    219c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    21a3:	00 
    21a4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    21a8:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    21ac:	8b 55 fc             	mov    -0x4(%rbp),%edx
    21af:	89 d0                	mov    %edx,%eax
    21b1:	c1 e0 02             	shl    $0x2,%eax
    21b4:	01 d0                	add    %edx,%eax
    21b6:	01 c0                	add    %eax,%eax
    21b8:	01 d0                	add    %edx,%eax
    21ba:	48 98                	cltq
    21bc:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    21c3:	00 
    21c4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    21c8:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    21cc:	8b 45 fc             	mov    -0x4(%rbp),%eax
    21cf:	48 89 f2             	mov    %rsi,%rdx
    21d2:	48 89 ce             	mov    %rcx,%rsi
    21d5:	89 c7                	mov    %eax,%edi
    21d7:	e8 cd fd ff ff       	call   1fa9 <m_vec_mul_add_x>
    21dc:	8b 55 fc             	mov    -0x4(%rbp),%edx
    21df:	89 d0                	mov    %edx,%eax
    21e1:	c1 e0 03             	shl    $0x3,%eax
    21e4:	29 d0                	sub    %edx,%eax
    21e6:	48 98                	cltq
    21e8:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    21ef:	00 
    21f0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    21f4:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    21f8:	8b 55 fc             	mov    -0x4(%rbp),%edx
    21fb:	89 d0                	mov    %edx,%eax
    21fd:	c1 e0 02             	shl    $0x2,%eax
    2200:	01 d0                	add    %edx,%eax
    2202:	01 c0                	add    %eax,%eax
    2204:	48 98                	cltq
    2206:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    220d:	00 
    220e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2212:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    2216:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2219:	48 89 f2             	mov    %rsi,%rdx
    221c:	48 89 ce             	mov    %rcx,%rsi
    221f:	89 c7                	mov    %eax,%edi
    2221:	e8 49 fe ff ff       	call   206f <m_vec_mul_add_x_inv>
    2226:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2229:	89 d0                	mov    %edx,%eax
    222b:	01 c0                	add    %eax,%eax
    222d:	01 d0                	add    %edx,%eax
    222f:	01 c0                	add    %eax,%eax
    2231:	48 98                	cltq
    2233:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    223a:	00 
    223b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    223f:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    2243:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2246:	89 d0                	mov    %edx,%eax
    2248:	01 c0                	add    %eax,%eax
    224a:	01 d0                	add    %edx,%eax
    224c:	c1 e0 02             	shl    $0x2,%eax
    224f:	48 98                	cltq
    2251:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2258:	00 
    2259:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    225d:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    2261:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2264:	48 89 f2             	mov    %rsi,%rdx
    2267:	48 89 ce             	mov    %rcx,%rsi
    226a:	89 c7                	mov    %eax,%edi
    226c:	e8 38 fd ff ff       	call   1fa9 <m_vec_mul_add_x>
    2271:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2274:	6b c0 0e             	imul   $0xe,%eax,%eax
    2277:	48 98                	cltq
    2279:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2280:	00 
    2281:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2285:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    2289:	8b 55 fc             	mov    -0x4(%rbp),%edx
    228c:	89 d0                	mov    %edx,%eax
    228e:	c1 e0 03             	shl    $0x3,%eax
    2291:	29 d0                	sub    %edx,%eax
    2293:	48 98                	cltq
    2295:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    229c:	00 
    229d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    22a1:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    22a5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    22a8:	48 89 f2             	mov    %rsi,%rdx
    22ab:	48 89 ce             	mov    %rcx,%rsi
    22ae:	89 c7                	mov    %eax,%edi
    22b0:	e8 ba fd ff ff       	call   206f <m_vec_mul_add_x_inv>
    22b5:	8b 55 fc             	mov    -0x4(%rbp),%edx
    22b8:	89 d0                	mov    %edx,%eax
    22ba:	01 c0                	add    %eax,%eax
    22bc:	01 d0                	add    %edx,%eax
    22be:	48 98                	cltq
    22c0:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    22c7:	00 
    22c8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    22cc:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    22d0:	8b 55 fc             	mov    -0x4(%rbp),%edx
    22d3:	89 d0                	mov    %edx,%eax
    22d5:	01 c0                	add    %eax,%eax
    22d7:	01 d0                	add    %edx,%eax
    22d9:	01 c0                	add    %eax,%eax
    22db:	48 98                	cltq
    22dd:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    22e4:	00 
    22e5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    22e9:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    22ed:	8b 45 fc             	mov    -0x4(%rbp),%eax
    22f0:	48 89 f2             	mov    %rsi,%rdx
    22f3:	48 89 ce             	mov    %rcx,%rsi
    22f6:	89 c7                	mov    %eax,%edi
    22f8:	e8 ac fc ff ff       	call   1fa9 <m_vec_mul_add_x>
    22fd:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2300:	89 d0                	mov    %edx,%eax
    2302:	c1 e0 04             	shl    $0x4,%eax
    2305:	29 d0                	sub    %edx,%eax
    2307:	48 98                	cltq
    2309:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2310:	00 
    2311:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2315:	48 01 c2             	add    %rax,%rdx
    2318:	8b 45 fc             	mov    -0x4(%rbp),%eax
    231b:	6b c0 0e             	imul   $0xe,%eax,%eax
    231e:	48 98                	cltq
    2320:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2327:	00 
    2328:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    232c:	48 01 c1             	add    %rax,%rcx
    232f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2332:	48 89 ce             	mov    %rcx,%rsi
    2335:	89 c7                	mov    %eax,%edi
    2337:	e8 33 fd ff ff       	call   206f <m_vec_mul_add_x_inv>
    233c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    233f:	c1 e0 03             	shl    $0x3,%eax
    2342:	48 98                	cltq
    2344:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    234b:	00 
    234c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2350:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    2354:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2357:	89 d0                	mov    %edx,%eax
    2359:	01 c0                	add    %eax,%eax
    235b:	01 d0                	add    %edx,%eax
    235d:	48 98                	cltq
    235f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2366:	00 
    2367:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    236b:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    236f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2372:	48 89 f2             	mov    %rsi,%rdx
    2375:	48 89 ce             	mov    %rcx,%rsi
    2378:	89 c7                	mov    %eax,%edi
    237a:	e8 2a fc ff ff       	call   1fa9 <m_vec_mul_add_x>
    237f:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2382:	89 d0                	mov    %edx,%eax
    2384:	01 c0                	add    %eax,%eax
    2386:	01 d0                	add    %edx,%eax
    2388:	c1 e0 02             	shl    $0x2,%eax
    238b:	01 d0                	add    %edx,%eax
    238d:	48 98                	cltq
    238f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2396:	00 
    2397:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    239b:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    239f:	8b 55 fc             	mov    -0x4(%rbp),%edx
    23a2:	89 d0                	mov    %edx,%eax
    23a4:	c1 e0 04             	shl    $0x4,%eax
    23a7:	29 d0                	sub    %edx,%eax
    23a9:	48 98                	cltq
    23ab:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    23b2:	00 
    23b3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    23b7:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    23bb:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23be:	48 89 f2             	mov    %rsi,%rdx
    23c1:	48 89 ce             	mov    %rcx,%rsi
    23c4:	89 c7                	mov    %eax,%edi
    23c6:	e8 a4 fc ff ff       	call   206f <m_vec_mul_add_x_inv>
    23cb:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23ce:	c1 e0 02             	shl    $0x2,%eax
    23d1:	48 98                	cltq
    23d3:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    23da:	00 
    23db:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    23df:	48 01 c2             	add    %rax,%rdx
    23e2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23e5:	c1 e0 03             	shl    $0x3,%eax
    23e8:	48 98                	cltq
    23ea:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    23f1:	00 
    23f2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    23f6:	48 01 c1             	add    %rax,%rcx
    23f9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23fc:	48 89 ce             	mov    %rcx,%rsi
    23ff:	89 c7                	mov    %eax,%edi
    2401:	e8 a3 fb ff ff       	call   1fa9 <m_vec_mul_add_x>
    2406:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2409:	89 d0                	mov    %edx,%eax
    240b:	c1 e0 03             	shl    $0x3,%eax
    240e:	01 d0                	add    %edx,%eax
    2410:	48 98                	cltq
    2412:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2419:	00 
    241a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    241e:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    2422:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2425:	89 d0                	mov    %edx,%eax
    2427:	01 c0                	add    %eax,%eax
    2429:	01 d0                	add    %edx,%eax
    242b:	c1 e0 02             	shl    $0x2,%eax
    242e:	01 d0                	add    %edx,%eax
    2430:	48 98                	cltq
    2432:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2439:	00 
    243a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    243e:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    2442:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2445:	48 89 f2             	mov    %rsi,%rdx
    2448:	48 89 ce             	mov    %rcx,%rsi
    244b:	89 c7                	mov    %eax,%edi
    244d:	e8 1d fc ff ff       	call   206f <m_vec_mul_add_x_inv>
    2452:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2455:	01 c0                	add    %eax,%eax
    2457:	48 98                	cltq
    2459:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2460:	00 
    2461:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2465:	48 01 c2             	add    %rax,%rdx
    2468:	8b 45 fc             	mov    -0x4(%rbp),%eax
    246b:	c1 e0 02             	shl    $0x2,%eax
    246e:	48 98                	cltq
    2470:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2477:	00 
    2478:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    247c:	48 01 c1             	add    %rax,%rcx
    247f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2482:	48 89 ce             	mov    %rcx,%rsi
    2485:	89 c7                	mov    %eax,%edi
    2487:	e8 1d fb ff ff       	call   1fa9 <m_vec_mul_add_x>
    248c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    248f:	48 98                	cltq
    2491:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2498:	00 
    2499:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    249d:	48 8d 34 02          	lea    (%rdx,%rax,1),%rsi
    24a1:	8b 55 fc             	mov    -0x4(%rbp),%edx
    24a4:	89 d0                	mov    %edx,%eax
    24a6:	c1 e0 03             	shl    $0x3,%eax
    24a9:	01 d0                	add    %edx,%eax
    24ab:	48 98                	cltq
    24ad:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    24b4:	00 
    24b5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24b9:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    24bd:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24c0:	48 89 f2             	mov    %rsi,%rdx
    24c3:	48 89 ce             	mov    %rcx,%rsi
    24c6:	89 c7                	mov    %eax,%edi
    24c8:	e8 a2 fb ff ff       	call   206f <m_vec_mul_add_x_inv>
    24cd:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24d0:	48 98                	cltq
    24d2:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    24d9:	00 
    24da:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24de:	48 01 c2             	add    %rax,%rdx
    24e1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24e4:	01 c0                	add    %eax,%eax
    24e6:	48 98                	cltq
    24e8:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    24ef:	00 
    24f0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24f4:	48 01 c1             	add    %rax,%rcx
    24f7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24fa:	48 89 ce             	mov    %rcx,%rsi
    24fd:	89 c7                	mov    %eax,%edi
    24ff:	e8 a5 fa ff ff       	call   1fa9 <m_vec_mul_add_x>
    2504:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2507:	48 98                	cltq
    2509:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2510:	00 
    2511:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2515:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    2519:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    251d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2520:	48 89 ce             	mov    %rcx,%rsi
    2523:	89 c7                	mov    %eax,%edi
    2525:	e8 2f f9 ff ff       	call   1e59 <m_vec_copy>
    252a:	90                   	nop
    252b:	c9                   	leave
    252c:	c3                   	ret

000000000000252d <mul_add_m_upper_triangular_mat_x_mat>:
    252d:	55                   	push   %rbp
    252e:	48 89 e5             	mov    %rsp,%rbp
    2531:	48 83 ec 38          	sub    $0x38,%rsp
    2535:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2538:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    253c:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    2540:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    2544:	44 89 45 e8          	mov    %r8d,-0x18(%rbp)
    2548:	44 89 4d cc          	mov    %r9d,-0x34(%rbp)
    254c:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    2553:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    255a:	e9 9b 00 00 00       	jmp    25fa <mul_add_m_upper_triangular_mat_x_mat+0xcd>
    255f:	8b 45 18             	mov    0x18(%rbp),%eax
    2562:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    2566:	89 45 f8             	mov    %eax,-0x8(%rbp)
    2569:	eb 7f                	jmp    25ea <mul_add_m_upper_triangular_mat_x_mat+0xbd>
    256b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2572:	eb 66                	jmp    25da <mul_add_m_upper_triangular_mat_x_mat+0xad>
    2574:	8b 45 f4             	mov    -0xc(%rbp),%eax
    2577:	0f af 45 10          	imul   0x10(%rbp),%eax
    257b:	8b 55 fc             	mov    -0x4(%rbp),%edx
    257e:	01 d0                	add    %edx,%eax
    2580:	0f af 45 ec          	imul   -0x14(%rbp),%eax
    2584:	48 98                	cltq
    2586:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    258d:	00 
    258e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2592:	48 01 c2             	add    %rax,%rdx
    2595:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2598:	0f af 45 10          	imul   0x10(%rbp),%eax
    259c:	8b 4d fc             	mov    -0x4(%rbp),%ecx
    259f:	01 c8                	add    %ecx,%eax
    25a1:	48 98                	cltq
    25a3:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    25a7:	48 01 c8             	add    %rcx,%rax
    25aa:	0f b6 00             	movzbl (%rax),%eax
    25ad:	0f b6 c0             	movzbl %al,%eax
    25b0:	8b 4d ec             	mov    -0x14(%rbp),%ecx
    25b3:	0f af 4d f0          	imul   -0x10(%rbp),%ecx
    25b7:	48 63 c9             	movslq %ecx,%rcx
    25ba:	48 8d 34 cd 00 00 00 	lea    0x0(,%rcx,8),%rsi
    25c1:	00 
    25c2:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    25c6:	48 01 ce             	add    %rcx,%rsi
    25c9:	8b 7d ec             	mov    -0x14(%rbp),%edi
    25cc:	48 89 d1             	mov    %rdx,%rcx
    25cf:	89 c2                	mov    %eax,%edx
    25d1:	e8 49 f9 ff ff       	call   1f1f <m_vec_mul_add>
    25d6:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    25da:	8b 45 fc             	mov    -0x4(%rbp),%eax
    25dd:	3b 45 10             	cmp    0x10(%rbp),%eax
    25e0:	7c 92                	jl     2574 <mul_add_m_upper_triangular_mat_x_mat+0x47>
    25e2:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    25e6:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    25ea:	8b 45 f8             	mov    -0x8(%rbp),%eax
    25ed:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    25f0:	0f 8c 75 ff ff ff    	jl     256b <mul_add_m_upper_triangular_mat_x_mat+0x3e>
    25f6:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    25fa:	8b 45 f4             	mov    -0xc(%rbp),%eax
    25fd:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    2600:	0f 8c 59 ff ff ff    	jl     255f <mul_add_m_upper_triangular_mat_x_mat+0x32>
    2606:	90                   	nop
    2607:	90                   	nop
    2608:	c9                   	leave
    2609:	c3                   	ret

000000000000260a <mul_add_m_upper_triangular_mat_x_mat_trans>:
    260a:	55                   	push   %rbp
    260b:	48 89 e5             	mov    %rsp,%rbp
    260e:	48 83 ec 38          	sub    $0x38,%rsp
    2612:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2615:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    2619:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    261d:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    2621:	44 89 45 e8          	mov    %r8d,-0x18(%rbp)
    2625:	44 89 4d cc          	mov    %r9d,-0x34(%rbp)
    2629:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    2630:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    2637:	e9 9b 00 00 00       	jmp    26d7 <mul_add_m_upper_triangular_mat_x_mat_trans+0xcd>
    263c:	8b 45 18             	mov    0x18(%rbp),%eax
    263f:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    2643:	89 45 f8             	mov    %eax,-0x8(%rbp)
    2646:	eb 7f                	jmp    26c7 <mul_add_m_upper_triangular_mat_x_mat_trans+0xbd>
    2648:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    264f:	eb 66                	jmp    26b7 <mul_add_m_upper_triangular_mat_x_mat_trans+0xad>
    2651:	8b 45 f4             	mov    -0xc(%rbp),%eax
    2654:	0f af 45 10          	imul   0x10(%rbp),%eax
    2658:	8b 55 fc             	mov    -0x4(%rbp),%edx
    265b:	01 d0                	add    %edx,%eax
    265d:	0f af 45 ec          	imul   -0x14(%rbp),%eax
    2661:	48 98                	cltq
    2663:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    266a:	00 
    266b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    266f:	48 01 c2             	add    %rax,%rdx
    2672:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2675:	0f af 45 cc          	imul   -0x34(%rbp),%eax
    2679:	8b 4d f8             	mov    -0x8(%rbp),%ecx
    267c:	01 c8                	add    %ecx,%eax
    267e:	48 98                	cltq
    2680:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    2684:	48 01 c8             	add    %rcx,%rax
    2687:	0f b6 00             	movzbl (%rax),%eax
    268a:	0f b6 c0             	movzbl %al,%eax
    268d:	8b 4d ec             	mov    -0x14(%rbp),%ecx
    2690:	0f af 4d f0          	imul   -0x10(%rbp),%ecx
    2694:	48 63 c9             	movslq %ecx,%rcx
    2697:	48 8d 34 cd 00 00 00 	lea    0x0(,%rcx,8),%rsi
    269e:	00 
    269f:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    26a3:	48 01 ce             	add    %rcx,%rsi
    26a6:	8b 7d ec             	mov    -0x14(%rbp),%edi
    26a9:	48 89 d1             	mov    %rdx,%rcx
    26ac:	89 c2                	mov    %eax,%edx
    26ae:	e8 6c f8 ff ff       	call   1f1f <m_vec_mul_add>
    26b3:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    26b7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26ba:	3b 45 10             	cmp    0x10(%rbp),%eax
    26bd:	7c 92                	jl     2651 <mul_add_m_upper_triangular_mat_x_mat_trans+0x47>
    26bf:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    26c3:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    26c7:	8b 45 f8             	mov    -0x8(%rbp),%eax
    26ca:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    26cd:	0f 8c 75 ff ff ff    	jl     2648 <mul_add_m_upper_triangular_mat_x_mat_trans+0x3e>
    26d3:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    26d7:	8b 45 f4             	mov    -0xc(%rbp),%eax
    26da:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    26dd:	0f 8c 59 ff ff ff    	jl     263c <mul_add_m_upper_triangular_mat_x_mat_trans+0x32>
    26e3:	90                   	nop
    26e4:	90                   	nop
    26e5:	c9                   	leave
    26e6:	c3                   	ret

00000000000026e7 <mul_add_mat_trans_x_m_mat>:
    26e7:	55                   	push   %rbp
    26e8:	48 89 e5             	mov    %rsp,%rbp
    26eb:	48 83 ec 38          	sub    $0x38,%rsp
    26ef:	89 7d ec             	mov    %edi,-0x14(%rbp)
    26f2:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    26f6:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    26fa:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    26fe:	44 89 45 e8          	mov    %r8d,-0x18(%rbp)
    2702:	44 89 4d cc          	mov    %r9d,-0x34(%rbp)
    2706:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    270d:	e9 a0 00 00 00       	jmp    27b2 <mul_add_mat_trans_x_m_mat+0xcb>
    2712:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    2719:	e9 84 00 00 00       	jmp    27a2 <mul_add_mat_trans_x_m_mat+0xbb>
    271e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2725:	eb 6f                	jmp    2796 <mul_add_mat_trans_x_m_mat+0xaf>
    2727:	8b 45 f4             	mov    -0xc(%rbp),%eax
    272a:	0f af 45 10          	imul   0x10(%rbp),%eax
    272e:	8b 55 fc             	mov    -0x4(%rbp),%edx
    2731:	01 d0                	add    %edx,%eax
    2733:	0f af 45 ec          	imul   -0x14(%rbp),%eax
    2737:	48 98                	cltq
    2739:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2740:	00 
    2741:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2745:	48 01 c2             	add    %rax,%rdx
    2748:	8b 45 f8             	mov    -0x8(%rbp),%eax
    274b:	0f af 45 cc          	imul   -0x34(%rbp),%eax
    274f:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    2752:	01 c8                	add    %ecx,%eax
    2754:	48 98                	cltq
    2756:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    275a:	48 01 c8             	add    %rcx,%rax
    275d:	0f b6 00             	movzbl (%rax),%eax
    2760:	0f b6 c0             	movzbl %al,%eax
    2763:	8b 4d f8             	mov    -0x8(%rbp),%ecx
    2766:	0f af 4d 10          	imul   0x10(%rbp),%ecx
    276a:	8b 75 fc             	mov    -0x4(%rbp),%esi
    276d:	01 f1                	add    %esi,%ecx
    276f:	0f af 4d ec          	imul   -0x14(%rbp),%ecx
    2773:	48 63 c9             	movslq %ecx,%rcx
    2776:	48 8d 34 cd 00 00 00 	lea    0x0(,%rcx,8),%rsi
    277d:	00 
    277e:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    2782:	48 01 ce             	add    %rcx,%rsi
    2785:	8b 7d ec             	mov    -0x14(%rbp),%edi
    2788:	48 89 d1             	mov    %rdx,%rcx
    278b:	89 c2                	mov    %eax,%edx
    278d:	e8 8d f7 ff ff       	call   1f1f <m_vec_mul_add>
    2792:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2796:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2799:	3b 45 10             	cmp    0x10(%rbp),%eax
    279c:	7c 89                	jl     2727 <mul_add_mat_trans_x_m_mat+0x40>
    279e:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    27a2:	8b 45 f8             	mov    -0x8(%rbp),%eax
    27a5:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    27a8:	0f 8c 70 ff ff ff    	jl     271e <mul_add_mat_trans_x_m_mat+0x37>
    27ae:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    27b2:	8b 45 f4             	mov    -0xc(%rbp),%eax
    27b5:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    27b8:	0f 8c 54 ff ff ff    	jl     2712 <mul_add_mat_trans_x_m_mat+0x2b>
    27be:	90                   	nop
    27bf:	90                   	nop
    27c0:	c9                   	leave
    27c1:	c3                   	ret

00000000000027c2 <mul_add_mat_x_m_mat>:
    27c2:	55                   	push   %rbp
    27c3:	48 89 e5             	mov    %rsp,%rbp
    27c6:	48 83 ec 38          	sub    $0x38,%rsp
    27ca:	89 7d ec             	mov    %edi,-0x14(%rbp)
    27cd:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    27d1:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    27d5:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    27d9:	44 89 45 e8          	mov    %r8d,-0x18(%rbp)
    27dd:	44 89 4d cc          	mov    %r9d,-0x34(%rbp)
    27e1:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    27e8:	e9 a0 00 00 00       	jmp    288d <mul_add_mat_x_m_mat+0xcb>
    27ed:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    27f4:	e9 84 00 00 00       	jmp    287d <mul_add_mat_x_m_mat+0xbb>
    27f9:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2800:	eb 6f                	jmp    2871 <mul_add_mat_x_m_mat+0xaf>
    2802:	8b 45 f4             	mov    -0xc(%rbp),%eax
    2805:	0f af 45 10          	imul   0x10(%rbp),%eax
    2809:	8b 55 fc             	mov    -0x4(%rbp),%edx
    280c:	01 d0                	add    %edx,%eax
    280e:	0f af 45 ec          	imul   -0x14(%rbp),%eax
    2812:	48 98                	cltq
    2814:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    281b:	00 
    281c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2820:	48 01 c2             	add    %rax,%rdx
    2823:	8b 45 f4             	mov    -0xc(%rbp),%eax
    2826:	0f af 45 cc          	imul   -0x34(%rbp),%eax
    282a:	8b 4d f8             	mov    -0x8(%rbp),%ecx
    282d:	01 c8                	add    %ecx,%eax
    282f:	48 98                	cltq
    2831:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    2835:	48 01 c8             	add    %rcx,%rax
    2838:	0f b6 00             	movzbl (%rax),%eax
    283b:	0f b6 c0             	movzbl %al,%eax
    283e:	8b 4d f8             	mov    -0x8(%rbp),%ecx
    2841:	0f af 4d 10          	imul   0x10(%rbp),%ecx
    2845:	8b 75 fc             	mov    -0x4(%rbp),%esi
    2848:	01 f1                	add    %esi,%ecx
    284a:	0f af 4d ec          	imul   -0x14(%rbp),%ecx
    284e:	48 63 c9             	movslq %ecx,%rcx
    2851:	48 8d 34 cd 00 00 00 	lea    0x0(,%rcx,8),%rsi
    2858:	00 
    2859:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    285d:	48 01 ce             	add    %rcx,%rsi
    2860:	8b 7d ec             	mov    -0x14(%rbp),%edi
    2863:	48 89 d1             	mov    %rdx,%rcx
    2866:	89 c2                	mov    %eax,%edx
    2868:	e8 b2 f6 ff ff       	call   1f1f <m_vec_mul_add>
    286d:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2871:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2874:	3b 45 10             	cmp    0x10(%rbp),%eax
    2877:	7c 89                	jl     2802 <mul_add_mat_x_m_mat+0x40>
    2879:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    287d:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2880:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    2883:	0f 8c 70 ff ff ff    	jl     27f9 <mul_add_mat_x_m_mat+0x37>
    2889:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    288d:	8b 45 f4             	mov    -0xc(%rbp),%eax
    2890:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    2893:	0f 8c 54 ff ff ff    	jl     27ed <mul_add_mat_x_m_mat+0x2b>
    2899:	90                   	nop
    289a:	90                   	nop
    289b:	c9                   	leave
    289c:	c3                   	ret

000000000000289d <P1_times_O>:
    289d:	55                   	push   %rbp
    289e:	48 89 e5             	mov    %rsp,%rbp
    28a1:	48 83 ec 20          	sub    $0x20,%rsp
    28a5:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    28a9:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    28ad:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    28b1:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    28b5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    28b9:	8b 78 08             	mov    0x8(%rax),%edi
    28bc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    28c0:	8b 50 04             	mov    0x4(%rax),%edx
    28c3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    28c7:	8b 40 08             	mov    0x8(%rax),%eax
    28ca:	29 c2                	sub    %eax,%edx
    28cc:	41 89 d1             	mov    %edx,%r9d
    28cf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    28d3:	8b 50 04             	mov    0x4(%rax),%edx
    28d6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    28da:	8b 40 08             	mov    0x8(%rax),%eax
    28dd:	29 c2                	sub    %eax,%edx
    28df:	41 89 d0             	mov    %edx,%r8d
    28e2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    28e6:	8b 40 5c             	mov    0x5c(%rax),%eax
    28e9:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    28ed:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    28f1:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    28f5:	6a 01                	push   $0x1
    28f7:	57                   	push   %rdi
    28f8:	89 c7                	mov    %eax,%edi
    28fa:	e8 2e fc ff ff       	call   252d <mul_add_m_upper_triangular_mat_x_mat>
    28ff:	48 83 c4 10          	add    $0x10,%rsp
    2903:	90                   	nop
    2904:	c9                   	leave
    2905:	c3                   	ret

0000000000002906 <P1_times_Vt>:
    2906:	55                   	push   %rbp
    2907:	48 89 e5             	mov    %rsp,%rbp
    290a:	48 83 ec 20          	sub    $0x20,%rsp
    290e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2912:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    2916:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    291a:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    291e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2922:	8b 78 0c             	mov    0xc(%rax),%edi
    2925:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2929:	8b 50 04             	mov    0x4(%rax),%edx
    292c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2930:	8b 40 08             	mov    0x8(%rax),%eax
    2933:	29 c2                	sub    %eax,%edx
    2935:	41 89 d1             	mov    %edx,%r9d
    2938:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    293c:	8b 50 04             	mov    0x4(%rax),%edx
    293f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2943:	8b 40 08             	mov    0x8(%rax),%eax
    2946:	29 c2                	sub    %eax,%edx
    2948:	41 89 d0             	mov    %edx,%r8d
    294b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    294f:	8b 40 5c             	mov    0x5c(%rax),%eax
    2952:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    2956:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    295a:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    295e:	6a 01                	push   $0x1
    2960:	57                   	push   %rdi
    2961:	89 c7                	mov    %eax,%edi
    2963:	e8 a2 fc ff ff       	call   260a <mul_add_m_upper_triangular_mat_x_mat_trans>
    2968:	48 83 c4 10          	add    $0x10,%rsp
    296c:	90                   	nop
    296d:	c9                   	leave
    296e:	c3                   	ret

000000000000296f <mayo_generic_m_calculate_PS>:
    296f:	55                   	push   %rbp
    2970:	48 89 e5             	mov    %rsp,%rbp
    2973:	4c 8d 9c 24 00 90 df 	lea    -0x207000(%rsp),%r11
    297a:	ff 
    297b:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    2982:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    2987:	4c 39 dc             	cmp    %r11,%rsp
    298a:	75 ef                	jne    297b <mayo_generic_m_calculate_PS+0xc>
    298c:	48 81 ec 80 0c 00 00 	sub    $0xc80,%rsp
    2993:	48 89 bd a8 83 df ff 	mov    %rdi,-0x207c58(%rbp)
    299a:	48 89 b5 a0 83 df ff 	mov    %rsi,-0x207c60(%rbp)
    29a1:	48 89 95 98 83 df ff 	mov    %rdx,-0x207c68(%rbp)
    29a8:	48 89 8d 90 83 df ff 	mov    %rcx,-0x207c70(%rbp)
    29af:	44 89 85 8c 83 df ff 	mov    %r8d,-0x207c74(%rbp)
    29b6:	44 89 8d 88 83 df ff 	mov    %r9d,-0x207c78(%rbp)
    29bd:	48 8b 45 20          	mov    0x20(%rbp),%rax
    29c1:	48 89 85 80 83 df ff 	mov    %rax,-0x207c80(%rbp)
    29c8:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    29cf:	00 00 
    29d1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    29d5:	31 c0                	xor    %eax,%eax
    29d7:	8b 55 10             	mov    0x10(%rbp),%edx
    29da:	8b 85 88 83 df ff    	mov    -0x207c78(%rbp),%eax
    29e0:	01 d0                	add    %edx,%eax
    29e2:	89 85 e8 83 df ff    	mov    %eax,-0x207c18(%rbp)
    29e8:	8b 85 8c 83 df ff    	mov    -0x207c74(%rbp),%eax
    29ee:	83 c0 0f             	add    $0xf,%eax
    29f1:	8d 50 0f             	lea    0xf(%rax),%edx
    29f4:	85 c0                	test   %eax,%eax
    29f6:	0f 48 c2             	cmovs  %edx,%eax
    29f9:	c1 f8 04             	sar    $0x4,%eax
    29fc:	89 85 ec 83 df ff    	mov    %eax,-0x207c14(%rbp)
    2a02:	48 8d 85 f0 83 df ff 	lea    -0x207c10(%rbp),%rax
    2a09:	ba 00 7c 20 00       	mov    $0x207c00,%edx
    2a0e:	be 00 00 00 00       	mov    $0x0,%esi
    2a13:	48 89 c7             	mov    %rax,%rdi
    2a16:	e8 e5 e7 ff ff       	call   1200 <memset@plt>
    2a1b:	c7 85 bc 83 df ff 00 	movl   $0x0,-0x207c44(%rbp)
    2a22:	00 00 00 
    2a25:	c7 85 c0 83 df ff 00 	movl   $0x0,-0x207c40(%rbp)
    2a2c:	00 00 00 
    2a2f:	e9 d3 01 00 00       	jmp    2c07 <mayo_generic_m_calculate_PS+0x298>
    2a34:	8b 85 c0 83 df ff    	mov    -0x207c40(%rbp),%eax
    2a3a:	89 85 c4 83 df ff    	mov    %eax,-0x207c3c(%rbp)
    2a40:	e9 bf 00 00 00       	jmp    2b04 <mayo_generic_m_calculate_PS+0x195>
    2a45:	c7 85 c8 83 df ff 00 	movl   $0x0,-0x207c38(%rbp)
    2a4c:	00 00 00 
    2a4f:	e9 93 00 00 00       	jmp    2ae7 <mayo_generic_m_calculate_PS+0x178>
    2a54:	8b 85 c0 83 df ff    	mov    -0x207c40(%rbp),%eax
    2a5a:	0f af 45 18          	imul   0x18(%rbp),%eax
    2a5e:	8b 95 c8 83 df ff    	mov    -0x207c38(%rbp),%edx
    2a64:	01 d0                	add    %edx,%eax
    2a66:	c1 e0 04             	shl    $0x4,%eax
    2a69:	89 c2                	mov    %eax,%edx
    2a6b:	8b 85 c8 83 df ff    	mov    -0x207c38(%rbp),%eax
    2a71:	0f af 85 e8 83 df ff 	imul   -0x207c18(%rbp),%eax
    2a78:	8b 8d c4 83 df ff    	mov    -0x207c3c(%rbp),%ecx
    2a7e:	01 c8                	add    %ecx,%eax
    2a80:	48 98                	cltq
    2a82:	48 8b 8d 90 83 df ff 	mov    -0x207c70(%rbp),%rcx
    2a89:	48 01 c8             	add    %rcx,%rax
    2a8c:	0f b6 00             	movzbl (%rax),%eax
    2a8f:	0f b6 c0             	movzbl %al,%eax
    2a92:	01 d0                	add    %edx,%eax
    2a94:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2a9b:	48 98                	cltq
    2a9d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2aa4:	00 
    2aa5:	48 8d 85 f0 83 df ff 	lea    -0x207c10(%rbp),%rax
    2aac:	48 01 c2             	add    %rax,%rdx
    2aaf:	8b 85 bc 83 df ff    	mov    -0x207c44(%rbp),%eax
    2ab5:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2abc:	48 98                	cltq
    2abe:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2ac5:	00 
    2ac6:	48 8b 85 a8 83 df ff 	mov    -0x207c58(%rbp),%rax
    2acd:	48 01 c1             	add    %rax,%rcx
    2ad0:	8b 85 ec 83 df ff    	mov    -0x207c14(%rbp),%eax
    2ad6:	48 89 ce             	mov    %rcx,%rsi
    2ad9:	89 c7                	mov    %eax,%edi
    2adb:	e8 cf f3 ff ff       	call   1eaf <m_vec_add>
    2ae0:	83 85 c8 83 df ff 01 	addl   $0x1,-0x207c38(%rbp)
    2ae7:	8b 85 c8 83 df ff    	mov    -0x207c38(%rbp),%eax
    2aed:	3b 45 18             	cmp    0x18(%rbp),%eax
    2af0:	0f 8c 5e ff ff ff    	jl     2a54 <mayo_generic_m_calculate_PS+0xe5>
    2af6:	83 85 bc 83 df ff 01 	addl   $0x1,-0x207c44(%rbp)
    2afd:	83 85 c4 83 df ff 01 	addl   $0x1,-0x207c3c(%rbp)
    2b04:	8b 85 c4 83 df ff    	mov    -0x207c3c(%rbp),%eax
    2b0a:	3b 85 88 83 df ff    	cmp    -0x207c78(%rbp),%eax
    2b10:	0f 8c 2f ff ff ff    	jl     2a45 <mayo_generic_m_calculate_PS+0xd6>
    2b16:	c7 85 cc 83 df ff 00 	movl   $0x0,-0x207c34(%rbp)
    2b1d:	00 00 00 
    2b20:	e9 cc 00 00 00       	jmp    2bf1 <mayo_generic_m_calculate_PS+0x282>
    2b25:	c7 85 d0 83 df ff 00 	movl   $0x0,-0x207c30(%rbp)
    2b2c:	00 00 00 
    2b2f:	e9 a7 00 00 00       	jmp    2bdb <mayo_generic_m_calculate_PS+0x26c>
    2b34:	8b 85 c0 83 df ff    	mov    -0x207c40(%rbp),%eax
    2b3a:	0f af 45 18          	imul   0x18(%rbp),%eax
    2b3e:	8b 95 d0 83 df ff    	mov    -0x207c30(%rbp),%edx
    2b44:	01 d0                	add    %edx,%eax
    2b46:	c1 e0 04             	shl    $0x4,%eax
    2b49:	89 c2                	mov    %eax,%edx
    2b4b:	8b 85 d0 83 df ff    	mov    -0x207c30(%rbp),%eax
    2b51:	0f af 85 e8 83 df ff 	imul   -0x207c18(%rbp),%eax
    2b58:	8b 8d cc 83 df ff    	mov    -0x207c34(%rbp),%ecx
    2b5e:	01 c1                	add    %eax,%ecx
    2b60:	8b 85 88 83 df ff    	mov    -0x207c78(%rbp),%eax
    2b66:	01 c8                	add    %ecx,%eax
    2b68:	48 98                	cltq
    2b6a:	48 8b 8d 90 83 df ff 	mov    -0x207c70(%rbp),%rcx
    2b71:	48 01 c8             	add    %rcx,%rax
    2b74:	0f b6 00             	movzbl (%rax),%eax
    2b77:	0f b6 c0             	movzbl %al,%eax
    2b7a:	01 d0                	add    %edx,%eax
    2b7c:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2b83:	48 98                	cltq
    2b85:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2b8c:	00 
    2b8d:	48 8d 85 f0 83 df ff 	lea    -0x207c10(%rbp),%rax
    2b94:	48 01 c2             	add    %rax,%rdx
    2b97:	8b 85 c0 83 df ff    	mov    -0x207c40(%rbp),%eax
    2b9d:	0f af 45 10          	imul   0x10(%rbp),%eax
    2ba1:	8b 8d cc 83 df ff    	mov    -0x207c34(%rbp),%ecx
    2ba7:	01 c8                	add    %ecx,%eax
    2ba9:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2bb0:	48 98                	cltq
    2bb2:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2bb9:	00 
    2bba:	48 8b 85 a0 83 df ff 	mov    -0x207c60(%rbp),%rax
    2bc1:	48 01 c1             	add    %rax,%rcx
    2bc4:	8b 85 ec 83 df ff    	mov    -0x207c14(%rbp),%eax
    2bca:	48 89 ce             	mov    %rcx,%rsi
    2bcd:	89 c7                	mov    %eax,%edi
    2bcf:	e8 db f2 ff ff       	call   1eaf <m_vec_add>
    2bd4:	83 85 d0 83 df ff 01 	addl   $0x1,-0x207c30(%rbp)
    2bdb:	8b 85 d0 83 df ff    	mov    -0x207c30(%rbp),%eax
    2be1:	3b 45 18             	cmp    0x18(%rbp),%eax
    2be4:	0f 8c 4a ff ff ff    	jl     2b34 <mayo_generic_m_calculate_PS+0x1c5>
    2bea:	83 85 cc 83 df ff 01 	addl   $0x1,-0x207c34(%rbp)
    2bf1:	8b 85 cc 83 df ff    	mov    -0x207c34(%rbp),%eax
    2bf7:	3b 45 10             	cmp    0x10(%rbp),%eax
    2bfa:	0f 8c 25 ff ff ff    	jl     2b25 <mayo_generic_m_calculate_PS+0x1b6>
    2c00:	83 85 c0 83 df ff 01 	addl   $0x1,-0x207c40(%rbp)
    2c07:	8b 85 c0 83 df ff    	mov    -0x207c40(%rbp),%eax
    2c0d:	3b 85 88 83 df ff    	cmp    -0x207c78(%rbp),%eax
    2c13:	0f 8c 1b fe ff ff    	jl     2a34 <mayo_generic_m_calculate_PS+0xc5>
    2c19:	c7 85 d4 83 df ff 00 	movl   $0x0,-0x207c2c(%rbp)
    2c20:	00 00 00 
    2c23:	8b 85 88 83 df ff    	mov    -0x207c78(%rbp),%eax
    2c29:	89 85 d8 83 df ff    	mov    %eax,-0x207c28(%rbp)
    2c2f:	e9 e9 00 00 00       	jmp    2d1d <mayo_generic_m_calculate_PS+0x3ae>
    2c34:	8b 85 d8 83 df ff    	mov    -0x207c28(%rbp),%eax
    2c3a:	89 85 dc 83 df ff    	mov    %eax,-0x207c24(%rbp)
    2c40:	e9 bf 00 00 00       	jmp    2d04 <mayo_generic_m_calculate_PS+0x395>
    2c45:	c7 85 e0 83 df ff 00 	movl   $0x0,-0x207c20(%rbp)
    2c4c:	00 00 00 
    2c4f:	e9 93 00 00 00       	jmp    2ce7 <mayo_generic_m_calculate_PS+0x378>
    2c54:	8b 85 d8 83 df ff    	mov    -0x207c28(%rbp),%eax
    2c5a:	0f af 45 18          	imul   0x18(%rbp),%eax
    2c5e:	8b 95 e0 83 df ff    	mov    -0x207c20(%rbp),%edx
    2c64:	01 d0                	add    %edx,%eax
    2c66:	c1 e0 04             	shl    $0x4,%eax
    2c69:	89 c2                	mov    %eax,%edx
    2c6b:	8b 85 e0 83 df ff    	mov    -0x207c20(%rbp),%eax
    2c71:	0f af 85 e8 83 df ff 	imul   -0x207c18(%rbp),%eax
    2c78:	8b 8d dc 83 df ff    	mov    -0x207c24(%rbp),%ecx
    2c7e:	01 c8                	add    %ecx,%eax
    2c80:	48 98                	cltq
    2c82:	48 8b 8d 90 83 df ff 	mov    -0x207c70(%rbp),%rcx
    2c89:	48 01 c8             	add    %rcx,%rax
    2c8c:	0f b6 00             	movzbl (%rax),%eax
    2c8f:	0f b6 c0             	movzbl %al,%eax
    2c92:	01 d0                	add    %edx,%eax
    2c94:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2c9b:	48 98                	cltq
    2c9d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2ca4:	00 
    2ca5:	48 8d 85 f0 83 df ff 	lea    -0x207c10(%rbp),%rax
    2cac:	48 01 c2             	add    %rax,%rdx
    2caf:	8b 85 d4 83 df ff    	mov    -0x207c2c(%rbp),%eax
    2cb5:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2cbc:	48 98                	cltq
    2cbe:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2cc5:	00 
    2cc6:	48 8b 85 98 83 df ff 	mov    -0x207c68(%rbp),%rax
    2ccd:	48 01 c1             	add    %rax,%rcx
    2cd0:	8b 85 ec 83 df ff    	mov    -0x207c14(%rbp),%eax
    2cd6:	48 89 ce             	mov    %rcx,%rsi
    2cd9:	89 c7                	mov    %eax,%edi
    2cdb:	e8 cf f1 ff ff       	call   1eaf <m_vec_add>
    2ce0:	83 85 e0 83 df ff 01 	addl   $0x1,-0x207c20(%rbp)
    2ce7:	8b 85 e0 83 df ff    	mov    -0x207c20(%rbp),%eax
    2ced:	3b 45 18             	cmp    0x18(%rbp),%eax
    2cf0:	0f 8c 5e ff ff ff    	jl     2c54 <mayo_generic_m_calculate_PS+0x2e5>
    2cf6:	83 85 d4 83 df ff 01 	addl   $0x1,-0x207c2c(%rbp)
    2cfd:	83 85 dc 83 df ff 01 	addl   $0x1,-0x207c24(%rbp)
    2d04:	8b 85 dc 83 df ff    	mov    -0x207c24(%rbp),%eax
    2d0a:	3b 85 e8 83 df ff    	cmp    -0x207c18(%rbp),%eax
    2d10:	0f 8c 2f ff ff ff    	jl     2c45 <mayo_generic_m_calculate_PS+0x2d6>
    2d16:	83 85 d8 83 df ff 01 	addl   $0x1,-0x207c28(%rbp)
    2d1d:	8b 85 d8 83 df ff    	mov    -0x207c28(%rbp),%eax
    2d23:	3b 85 e8 83 df ff    	cmp    -0x207c18(%rbp),%eax
    2d29:	0f 8c 05 ff ff ff    	jl     2c34 <mayo_generic_m_calculate_PS+0x2c5>
    2d2f:	c7 85 e4 83 df ff 00 	movl   $0x0,-0x207c1c(%rbp)
    2d36:	00 00 00 
    2d39:	eb 5c                	jmp    2d97 <mayo_generic_m_calculate_PS+0x428>
    2d3b:	8b 85 e4 83 df ff    	mov    -0x207c1c(%rbp),%eax
    2d41:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2d48:	48 98                	cltq
    2d4a:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2d51:	00 
    2d52:	48 8b 85 80 83 df ff 	mov    -0x207c80(%rbp),%rax
    2d59:	48 01 c2             	add    %rax,%rdx
    2d5c:	8b 85 e4 83 df ff    	mov    -0x207c1c(%rbp),%eax
    2d62:	0f af 85 ec 83 df ff 	imul   -0x207c14(%rbp),%eax
    2d69:	c1 e0 04             	shl    $0x4,%eax
    2d6c:	48 98                	cltq
    2d6e:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2d75:	00 
    2d76:	48 8d 85 f0 83 df ff 	lea    -0x207c10(%rbp),%rax
    2d7d:	48 01 c1             	add    %rax,%rcx
    2d80:	8b 85 ec 83 df ff    	mov    -0x207c14(%rbp),%eax
    2d86:	48 89 ce             	mov    %rcx,%rsi
    2d89:	89 c7                	mov    %eax,%edi
    2d8b:	e8 a1 f3 ff ff       	call   2131 <m_vec_multiply_bins>
    2d90:	83 85 e4 83 df ff 01 	addl   $0x1,-0x207c1c(%rbp)
    2d97:	8b 85 e8 83 df ff    	mov    -0x207c18(%rbp),%eax
    2d9d:	0f af 45 18          	imul   0x18(%rbp),%eax
    2da1:	39 85 e4 83 df ff    	cmp    %eax,-0x207c1c(%rbp)
    2da7:	7c 92                	jl     2d3b <mayo_generic_m_calculate_PS+0x3cc>
    2da9:	90                   	nop
    2daa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2dae:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    2db5:	00 00 
    2db7:	74 05                	je     2dbe <mayo_generic_m_calculate_PS+0x44f>
    2db9:	e8 12 e4 ff ff       	call   11d0 <__stack_chk_fail@plt>
    2dbe:	c9                   	leave
    2dbf:	c3                   	ret

0000000000002dc0 <mayo_generic_m_calculate_SPS>:
    2dc0:	55                   	push   %rbp
    2dc1:	48 89 e5             	mov    %rsp,%rbp
    2dc4:	4c 8d 9c 24 00 80 fd 	lea    -0x28000(%rsp),%r11
    2dcb:	ff 
    2dcc:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    2dd3:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    2dd8:	4c 39 dc             	cmp    %r11,%rsp
    2ddb:	75 ef                	jne    2dcc <mayo_generic_m_calculate_SPS+0xc>
    2ddd:	48 81 ec 60 08 00 00 	sub    $0x860,%rsp
    2de4:	48 89 bd c8 77 fd ff 	mov    %rdi,-0x28838(%rbp)
    2deb:	48 89 b5 c0 77 fd ff 	mov    %rsi,-0x28840(%rbp)
    2df2:	89 95 bc 77 fd ff    	mov    %edx,-0x28844(%rbp)
    2df8:	89 8d b8 77 fd ff    	mov    %ecx,-0x28848(%rbp)
    2dfe:	44 89 85 b4 77 fd ff 	mov    %r8d,-0x2884c(%rbp)
    2e05:	4c 89 8d a8 77 fd ff 	mov    %r9,-0x28858(%rbp)
    2e0c:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2e13:	00 00 
    2e15:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2e19:	31 c0                	xor    %eax,%eax
    2e1b:	48 8d 85 f0 77 fd ff 	lea    -0x28810(%rbp),%rax
    2e22:	ba 00 88 02 00       	mov    $0x28800,%edx
    2e27:	be 00 00 00 00       	mov    $0x0,%esi
    2e2c:	48 89 c7             	mov    %rax,%rdi
    2e2f:	e8 cc e3 ff ff       	call   1200 <memset@plt>
    2e34:	8b 85 bc 77 fd ff    	mov    -0x28844(%rbp),%eax
    2e3a:	83 c0 0f             	add    $0xf,%eax
    2e3d:	8d 50 0f             	lea    0xf(%rax),%edx
    2e40:	85 c0                	test   %eax,%eax
    2e42:	0f 48 c2             	cmovs  %edx,%eax
    2e45:	c1 f8 04             	sar    $0x4,%eax
    2e48:	89 85 ec 77 fd ff    	mov    %eax,-0x28814(%rbp)
    2e4e:	c7 85 dc 77 fd ff 00 	movl   $0x0,-0x28824(%rbp)
    2e55:	00 00 00 
    2e58:	e9 f5 00 00 00       	jmp    2f52 <mayo_generic_m_calculate_SPS+0x192>
    2e5d:	c7 85 e0 77 fd ff 00 	movl   $0x0,-0x28820(%rbp)
    2e64:	00 00 00 
    2e67:	e9 cd 00 00 00       	jmp    2f39 <mayo_generic_m_calculate_SPS+0x179>
    2e6c:	c7 85 e4 77 fd ff 00 	movl   $0x0,-0x2881c(%rbp)
    2e73:	00 00 00 
    2e76:	e9 a5 00 00 00       	jmp    2f20 <mayo_generic_m_calculate_SPS+0x160>
    2e7b:	8b 85 dc 77 fd ff    	mov    -0x28824(%rbp),%eax
    2e81:	0f af 85 b8 77 fd ff 	imul   -0x28848(%rbp),%eax
    2e88:	8b 95 e4 77 fd ff    	mov    -0x2881c(%rbp),%edx
    2e8e:	01 d0                	add    %edx,%eax
    2e90:	c1 e0 04             	shl    $0x4,%eax
    2e93:	89 c2                	mov    %eax,%edx
    2e95:	8b 85 dc 77 fd ff    	mov    -0x28824(%rbp),%eax
    2e9b:	0f af 85 b4 77 fd ff 	imul   -0x2884c(%rbp),%eax
    2ea2:	8b 8d e0 77 fd ff    	mov    -0x28820(%rbp),%ecx
    2ea8:	01 c8                	add    %ecx,%eax
    2eaa:	48 98                	cltq
    2eac:	48 8b 8d c0 77 fd ff 	mov    -0x28840(%rbp),%rcx
    2eb3:	48 01 c8             	add    %rcx,%rax
    2eb6:	0f b6 00             	movzbl (%rax),%eax
    2eb9:	0f b6 c0             	movzbl %al,%eax
    2ebc:	01 d0                	add    %edx,%eax
    2ebe:	0f af 85 ec 77 fd ff 	imul   -0x28814(%rbp),%eax
    2ec5:	48 98                	cltq
    2ec7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2ece:	00 
    2ecf:	48 8d 85 f0 77 fd ff 	lea    -0x28810(%rbp),%rax
    2ed6:	48 01 c2             	add    %rax,%rdx
    2ed9:	8b 85 e0 77 fd ff    	mov    -0x28820(%rbp),%eax
    2edf:	0f af 85 b8 77 fd ff 	imul   -0x28848(%rbp),%eax
    2ee6:	8b 8d e4 77 fd ff    	mov    -0x2881c(%rbp),%ecx
    2eec:	01 c8                	add    %ecx,%eax
    2eee:	0f af 85 ec 77 fd ff 	imul   -0x28814(%rbp),%eax
    2ef5:	48 98                	cltq
    2ef7:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2efe:	00 
    2eff:	48 8b 85 c8 77 fd ff 	mov    -0x28838(%rbp),%rax
    2f06:	48 01 c1             	add    %rax,%rcx
    2f09:	8b 85 ec 77 fd ff    	mov    -0x28814(%rbp),%eax
    2f0f:	48 89 ce             	mov    %rcx,%rsi
    2f12:	89 c7                	mov    %eax,%edi
    2f14:	e8 96 ef ff ff       	call   1eaf <m_vec_add>
    2f19:	83 85 e4 77 fd ff 01 	addl   $0x1,-0x2881c(%rbp)
    2f20:	8b 85 e4 77 fd ff    	mov    -0x2881c(%rbp),%eax
    2f26:	3b 85 b8 77 fd ff    	cmp    -0x28848(%rbp),%eax
    2f2c:	0f 8c 49 ff ff ff    	jl     2e7b <mayo_generic_m_calculate_SPS+0xbb>
    2f32:	83 85 e0 77 fd ff 01 	addl   $0x1,-0x28820(%rbp)
    2f39:	8b 85 e0 77 fd ff    	mov    -0x28820(%rbp),%eax
    2f3f:	3b 85 b4 77 fd ff    	cmp    -0x2884c(%rbp),%eax
    2f45:	0f 8c 21 ff ff ff    	jl     2e6c <mayo_generic_m_calculate_SPS+0xac>
    2f4b:	83 85 dc 77 fd ff 01 	addl   $0x1,-0x28824(%rbp)
    2f52:	8b 85 dc 77 fd ff    	mov    -0x28824(%rbp),%eax
    2f58:	3b 85 b8 77 fd ff    	cmp    -0x28848(%rbp),%eax
    2f5e:	0f 8c f9 fe ff ff    	jl     2e5d <mayo_generic_m_calculate_SPS+0x9d>
    2f64:	c7 85 e8 77 fd ff 00 	movl   $0x0,-0x28818(%rbp)
    2f6b:	00 00 00 
    2f6e:	eb 5c                	jmp    2fcc <mayo_generic_m_calculate_SPS+0x20c>
    2f70:	8b 85 e8 77 fd ff    	mov    -0x28818(%rbp),%eax
    2f76:	0f af 85 ec 77 fd ff 	imul   -0x28814(%rbp),%eax
    2f7d:	48 98                	cltq
    2f7f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    2f86:	00 
    2f87:	48 8b 85 a8 77 fd ff 	mov    -0x28858(%rbp),%rax
    2f8e:	48 01 c2             	add    %rax,%rdx
    2f91:	8b 85 e8 77 fd ff    	mov    -0x28818(%rbp),%eax
    2f97:	0f af 85 ec 77 fd ff 	imul   -0x28814(%rbp),%eax
    2f9e:	c1 e0 04             	shl    $0x4,%eax
    2fa1:	48 98                	cltq
    2fa3:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    2faa:	00 
    2fab:	48 8d 85 f0 77 fd ff 	lea    -0x28810(%rbp),%rax
    2fb2:	48 01 c1             	add    %rax,%rcx
    2fb5:	8b 85 ec 77 fd ff    	mov    -0x28814(%rbp),%eax
    2fbb:	48 89 ce             	mov    %rcx,%rsi
    2fbe:	89 c7                	mov    %eax,%edi
    2fc0:	e8 6c f1 ff ff       	call   2131 <m_vec_multiply_bins>
    2fc5:	83 85 e8 77 fd ff 01 	addl   $0x1,-0x28818(%rbp)
    2fcc:	8b 85 b8 77 fd ff    	mov    -0x28848(%rbp),%eax
    2fd2:	0f af c0             	imul   %eax,%eax
    2fd5:	39 85 e8 77 fd ff    	cmp    %eax,-0x28818(%rbp)
    2fdb:	7c 93                	jl     2f70 <mayo_generic_m_calculate_SPS+0x1b0>
    2fdd:	90                   	nop
    2fde:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2fe2:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    2fe9:	00 00 
    2feb:	74 05                	je     2ff2 <mayo_generic_m_calculate_SPS+0x232>
    2fed:	e8 de e1 ff ff       	call   11d0 <__stack_chk_fail@plt>
    2ff2:	c9                   	leave
    2ff3:	c3                   	ret

0000000000002ff4 <P1P1t_times_O>:
    2ff4:	55                   	push   %rbp
    2ff5:	48 89 e5             	mov    %rsp,%rbp
    2ff8:	48 83 ec 40          	sub    $0x40,%rsp
    2ffc:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3000:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    3004:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    3008:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    300c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3010:	8b 40 08             	mov    0x8(%rax),%eax
    3013:	89 45 f4             	mov    %eax,-0xc(%rbp)
    3016:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    301a:	8b 50 04             	mov    0x4(%rax),%edx
    301d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3021:	8b 40 08             	mov    0x8(%rax),%eax
    3024:	29 c2                	sub    %eax,%edx
    3026:	89 d0                	mov    %edx,%eax
    3028:	89 45 f8             	mov    %eax,-0x8(%rbp)
    302b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    302f:	8b 40 5c             	mov    0x5c(%rax),%eax
    3032:	89 45 fc             	mov    %eax,-0x4(%rbp)
    3035:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
    303c:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    3043:	e9 14 01 00 00       	jmp    315c <P1P1t_times_O+0x168>
    3048:	8b 45 e8             	mov    -0x18(%rbp),%eax
    304b:	89 45 ec             	mov    %eax,-0x14(%rbp)
    304e:	e9 f9 00 00 00       	jmp    314c <P1P1t_times_O+0x158>
    3053:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3056:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    3059:	75 09                	jne    3064 <P1P1t_times_O+0x70>
    305b:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
    305f:	e9 e4 00 00 00       	jmp    3148 <P1P1t_times_O+0x154>
    3064:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    306b:	e9 c8 00 00 00       	jmp    3138 <P1P1t_times_O+0x144>
    3070:	8b 45 e8             	mov    -0x18(%rbp),%eax
    3073:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    3077:	8b 55 f0             	mov    -0x10(%rbp),%edx
    307a:	01 d0                	add    %edx,%eax
    307c:	0f af 45 fc          	imul   -0x4(%rbp),%eax
    3080:	48 98                	cltq
    3082:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3089:	00 
    308a:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    308e:	48 01 c2             	add    %rax,%rdx
    3091:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3094:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    3098:	8b 4d f0             	mov    -0x10(%rbp),%ecx
    309b:	01 c8                	add    %ecx,%eax
    309d:	48 98                	cltq
    309f:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    30a3:	48 01 c8             	add    %rcx,%rax
    30a6:	0f b6 00             	movzbl (%rax),%eax
    30a9:	0f b6 c0             	movzbl %al,%eax
    30ac:	8b 4d fc             	mov    -0x4(%rbp),%ecx
    30af:	0f af 4d e4          	imul   -0x1c(%rbp),%ecx
    30b3:	48 63 c9             	movslq %ecx,%rcx
    30b6:	48 8d 34 cd 00 00 00 	lea    0x0(,%rcx,8),%rsi
    30bd:	00 
    30be:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    30c2:	48 01 ce             	add    %rcx,%rsi
    30c5:	8b 7d fc             	mov    -0x4(%rbp),%edi
    30c8:	48 89 d1             	mov    %rdx,%rcx
    30cb:	89 c2                	mov    %eax,%edx
    30cd:	e8 4d ee ff ff       	call   1f1f <m_vec_mul_add>
    30d2:	8b 45 ec             	mov    -0x14(%rbp),%eax
    30d5:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    30d9:	8b 55 f0             	mov    -0x10(%rbp),%edx
    30dc:	01 d0                	add    %edx,%eax
    30de:	0f af 45 fc          	imul   -0x4(%rbp),%eax
    30e2:	48 98                	cltq
    30e4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    30eb:	00 
    30ec:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    30f0:	48 01 c2             	add    %rax,%rdx
    30f3:	8b 45 e8             	mov    -0x18(%rbp),%eax
    30f6:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    30fa:	8b 4d f0             	mov    -0x10(%rbp),%ecx
    30fd:	01 c8                	add    %ecx,%eax
    30ff:	48 98                	cltq
    3101:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    3105:	48 01 c8             	add    %rcx,%rax
    3108:	0f b6 00             	movzbl (%rax),%eax
    310b:	0f b6 c0             	movzbl %al,%eax
    310e:	8b 4d fc             	mov    -0x4(%rbp),%ecx
    3111:	0f af 4d e4          	imul   -0x1c(%rbp),%ecx
    3115:	48 63 c9             	movslq %ecx,%rcx
    3118:	48 8d 34 cd 00 00 00 	lea    0x0(,%rcx,8),%rsi
    311f:	00 
    3120:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    3124:	48 01 ce             	add    %rcx,%rsi
    3127:	8b 7d fc             	mov    -0x4(%rbp),%edi
    312a:	48 89 d1             	mov    %rdx,%rcx
    312d:	89 c2                	mov    %eax,%edx
    312f:	e8 eb ed ff ff       	call   1f1f <m_vec_mul_add>
    3134:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    3138:	8b 45 f0             	mov    -0x10(%rbp),%eax
    313b:	3b 45 f4             	cmp    -0xc(%rbp),%eax
    313e:	0f 8c 2c ff ff ff    	jl     3070 <P1P1t_times_O+0x7c>
    3144:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
    3148:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    314c:	8b 45 ec             	mov    -0x14(%rbp),%eax
    314f:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    3152:	0f 8c fb fe ff ff    	jl     3053 <P1P1t_times_O+0x5f>
    3158:	83 45 e8 01          	addl   $0x1,-0x18(%rbp)
    315c:	8b 45 e8             	mov    -0x18(%rbp),%eax
    315f:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    3162:	0f 8c e0 fe ff ff    	jl     3048 <P1P1t_times_O+0x54>
    3168:	90                   	nop
    3169:	90                   	nop
    316a:	c9                   	leave
    316b:	c3                   	ret

000000000000316c <compute_M_and_VPV>:
    316c:	55                   	push   %rbp
    316d:	48 89 e5             	mov    %rsp,%rbp
    3170:	4c 8d 9c 24 00 30 fe 	lea    -0x1d000(%rsp),%r11
    3177:	ff 
    3178:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    317f:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    3184:	4c 39 dc             	cmp    %r11,%rsp
    3187:	75 ef                	jne    3178 <compute_M_and_VPV+0xc>
    3189:	48 81 ec 90 0f 00 00 	sub    $0xf90,%rsp
    3190:	48 89 bd 98 20 fe ff 	mov    %rdi,-0x1df68(%rbp)
    3197:	48 89 b5 90 20 fe ff 	mov    %rsi,-0x1df70(%rbp)
    319e:	48 89 95 88 20 fe ff 	mov    %rdx,-0x1df78(%rbp)
    31a5:	48 89 8d 80 20 fe ff 	mov    %rcx,-0x1df80(%rbp)
    31ac:	4c 89 85 78 20 fe ff 	mov    %r8,-0x1df88(%rbp)
    31b3:	4c 89 8d 70 20 fe ff 	mov    %r9,-0x1df90(%rbp)
    31ba:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    31c1:	00 00 
    31c3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    31c7:	31 c0                	xor    %eax,%eax
    31c9:	48 8b 85 98 20 fe ff 	mov    -0x1df68(%rbp),%rax
    31d0:	8b 40 0c             	mov    0xc(%rax),%eax
    31d3:	89 85 a4 20 fe ff    	mov    %eax,-0x1df5c(%rbp)
    31d9:	48 8b 85 98 20 fe ff 	mov    -0x1df68(%rbp),%rax
    31e0:	8b 50 04             	mov    0x4(%rax),%edx
    31e3:	48 8b 85 98 20 fe ff 	mov    -0x1df68(%rbp),%rax
    31ea:	8b 40 08             	mov    0x8(%rax),%eax
    31ed:	29 c2                	sub    %eax,%edx
    31ef:	89 d0                	mov    %edx,%eax
    31f1:	89 85 a8 20 fe ff    	mov    %eax,-0x1df58(%rbp)
    31f7:	48 8b 85 98 20 fe ff 	mov    -0x1df68(%rbp),%rax
    31fe:	8b 40 08             	mov    0x8(%rax),%eax
    3201:	89 85 ac 20 fe ff    	mov    %eax,-0x1df54(%rbp)
    3207:	48 8b 85 98 20 fe ff 	mov    -0x1df68(%rbp),%rax
    320e:	8b 40 5c             	mov    0x5c(%rax),%eax
    3211:	44 8b 8d a8 20 fe ff 	mov    -0x1df58(%rbp),%r9d
    3218:	44 8b 85 a4 20 fe ff 	mov    -0x1df5c(%rbp),%r8d
    321f:	48 8b 8d 78 20 fe ff 	mov    -0x1df88(%rbp),%rcx
    3226:	48 8b 95 88 20 fe ff 	mov    -0x1df78(%rbp),%rdx
    322d:	48 8b b5 90 20 fe ff 	mov    -0x1df70(%rbp),%rsi
    3234:	8b bd ac 20 fe ff    	mov    -0x1df54(%rbp),%edi
    323a:	57                   	push   %rdi
    323b:	89 c7                	mov    %eax,%edi
    323d:	e8 80 f5 ff ff       	call   27c2 <mul_add_mat_x_m_mat>
    3242:	48 83 c4 08          	add    $0x8,%rsp
    3246:	48 8d 85 b0 20 fe ff 	lea    -0x1df50(%rbp),%rax
    324d:	ba 40 df 01 00       	mov    $0x1df40,%edx
    3252:	be 00 00 00 00       	mov    $0x0,%esi
    3257:	48 89 c7             	mov    %rax,%rdi
    325a:	e8 a1 df ff ff       	call   1200 <memset@plt>
    325f:	48 8d 85 b0 20 fe ff 	lea    -0x1df50(%rbp),%rax
    3266:	48 8b 95 90 20 fe ff 	mov    -0x1df70(%rbp),%rdx
    326d:	48 8b b5 80 20 fe ff 	mov    -0x1df80(%rbp),%rsi
    3274:	48 8b bd 98 20 fe ff 	mov    -0x1df68(%rbp),%rdi
    327b:	48 89 c1             	mov    %rax,%rcx
    327e:	e8 83 f6 ff ff       	call   2906 <P1_times_Vt>
    3283:	48 8b 85 98 20 fe ff 	mov    -0x1df68(%rbp),%rax
    328a:	8b 78 5c             	mov    0x5c(%rax),%edi
    328d:	44 8b 8d a8 20 fe ff 	mov    -0x1df58(%rbp),%r9d
    3294:	44 8b 85 a4 20 fe ff 	mov    -0x1df5c(%rbp),%r8d
    329b:	48 8b 95 70 20 fe ff 	mov    -0x1df90(%rbp),%rdx
    32a2:	48 8d 85 b0 20 fe ff 	lea    -0x1df50(%rbp),%rax
    32a9:	48 8b b5 90 20 fe ff 	mov    -0x1df70(%rbp),%rsi
    32b0:	48 83 ec 08          	sub    $0x8,%rsp
    32b4:	8b 8d a4 20 fe ff    	mov    -0x1df5c(%rbp),%ecx
    32ba:	51                   	push   %rcx
    32bb:	48 89 d1             	mov    %rdx,%rcx
    32be:	48 89 c2             	mov    %rax,%rdx
    32c1:	e8 fc f4 ff ff       	call   27c2 <mul_add_mat_x_m_mat>
    32c6:	48 83 c4 10          	add    $0x10,%rsp
    32ca:	90                   	nop
    32cb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    32cf:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    32d6:	00 00 
    32d8:	74 05                	je     32df <compute_M_and_VPV+0x173>
    32da:	e8 f1 de ff ff       	call   11d0 <__stack_chk_fail@plt>
    32df:	c9                   	leave
    32e0:	c3                   	ret

00000000000032e1 <compute_P3>:
    32e1:	55                   	push   %rbp
    32e2:	48 89 e5             	mov    %rsp,%rbp
    32e5:	48 83 ec 38          	sub    $0x38,%rsp
    32e9:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    32ed:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    32f1:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    32f5:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    32f9:	4c 89 45 c8          	mov    %r8,-0x38(%rbp)
    32fd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3301:	8b 40 5c             	mov    0x5c(%rax),%eax
    3304:	89 45 f4             	mov    %eax,-0xc(%rbp)
    3307:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    330b:	8b 50 04             	mov    0x4(%rax),%edx
    330e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3312:	8b 40 08             	mov    0x8(%rax),%eax
    3315:	29 c2                	sub    %eax,%edx
    3317:	89 d0                	mov    %edx,%eax
    3319:	89 45 f8             	mov    %eax,-0x8(%rbp)
    331c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3320:	8b 40 08             	mov    0x8(%rax),%eax
    3323:	89 45 fc             	mov    %eax,-0x4(%rbp)
    3326:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    332a:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    332e:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    3332:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3336:	48 89 c7             	mov    %rax,%rdi
    3339:	e8 5f f5 ff ff       	call   289d <P1_times_O>
    333e:	44 8b 4d fc          	mov    -0x4(%rbp),%r9d
    3342:	44 8b 45 f8          	mov    -0x8(%rbp),%r8d
    3346:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    334a:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    334e:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    3352:	8b 45 f4             	mov    -0xc(%rbp),%eax
    3355:	8b 7d fc             	mov    -0x4(%rbp),%edi
    3358:	57                   	push   %rdi
    3359:	89 c7                	mov    %eax,%edi
    335b:	e8 87 f3 ff ff       	call   26e7 <mul_add_mat_trans_x_m_mat>
    3360:	48 83 c4 08          	add    $0x8,%rsp
    3364:	90                   	nop
    3365:	c9                   	leave
    3366:	c3                   	ret

0000000000003367 <m_calculate_PS_SPS>:
    3367:	55                   	push   %rbp
    3368:	48 89 e5             	mov    %rsp,%rbp
    336b:	4c 8d 9c 24 00 00 fe 	lea    -0x20000(%rsp),%r11
    3372:	ff 
    3373:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    337a:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    337f:	4c 39 dc             	cmp    %r11,%rsp
    3382:	75 ef                	jne    3373 <m_calculate_PS_SPS+0xc>
    3384:	48 81 ec 00 08 00 00 	sub    $0x800,%rsp
    338b:	48 89 bd 28 f8 fd ff 	mov    %rdi,-0x207d8(%rbp)
    3392:	48 89 b5 20 f8 fd ff 	mov    %rsi,-0x207e0(%rbp)
    3399:	48 89 95 18 f8 fd ff 	mov    %rdx,-0x207e8(%rbp)
    33a0:	48 89 8d 10 f8 fd ff 	mov    %rcx,-0x207f0(%rbp)
    33a7:	4c 89 85 08 f8 fd ff 	mov    %r8,-0x207f8(%rbp)
    33ae:	4c 89 8d 00 f8 fd ff 	mov    %r9,-0x20800(%rbp)
    33b5:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    33bc:	00 00 
    33be:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    33c2:	31 c0                	xor    %eax,%eax
    33c4:	48 8d 85 30 f8 fd ff 	lea    -0x207d0(%rbp),%rax
    33cb:	ba c0 07 02 00       	mov    $0x207c0,%edx
    33d0:	be 00 00 00 00       	mov    $0x0,%esi
    33d5:	48 89 c7             	mov    %rax,%rdi
    33d8:	e8 23 de ff ff       	call   1200 <memset@plt>
    33dd:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    33e4:	44 8b 48 0c          	mov    0xc(%rax),%r9d
    33e8:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    33ef:	44 8b 40 08          	mov    0x8(%rax),%r8d
    33f3:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    33fa:	8b 50 04             	mov    0x4(%rax),%edx
    33fd:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    3404:	8b 40 08             	mov    0x8(%rax),%eax
    3407:	29 c2                	sub    %eax,%edx
    3409:	41 89 d3             	mov    %edx,%r11d
    340c:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    3413:	44 8b 10             	mov    (%rax),%r10d
    3416:	48 8b 8d 08 f8 fd ff 	mov    -0x207f8(%rbp),%rcx
    341d:	48 8b 95 10 f8 fd ff 	mov    -0x207f0(%rbp),%rdx
    3424:	48 8b b5 18 f8 fd ff 	mov    -0x207e8(%rbp),%rsi
    342b:	48 8b 85 20 f8 fd ff 	mov    -0x207e0(%rbp),%rax
    3432:	48 83 ec 08          	sub    $0x8,%rsp
    3436:	48 8d bd 30 f8 fd ff 	lea    -0x207d0(%rbp),%rdi
    343d:	57                   	push   %rdi
    343e:	41 51                	push   %r9
    3440:	41 50                	push   %r8
    3442:	45 89 d9             	mov    %r11d,%r9d
    3445:	45 89 d0             	mov    %r10d,%r8d
    3448:	48 89 c7             	mov    %rax,%rdi
    344b:	e8 1f f5 ff ff       	call   296f <mayo_generic_m_calculate_PS>
    3450:	48 83 c4 20          	add    $0x20,%rsp
    3454:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    345b:	8b 78 04             	mov    0x4(%rax),%edi
    345e:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    3465:	8b 48 0c             	mov    0xc(%rax),%ecx
    3468:	48 8b 85 28 f8 fd ff 	mov    -0x207d8(%rbp),%rax
    346f:	8b 10                	mov    (%rax),%edx
    3471:	4c 8b 85 00 f8 fd ff 	mov    -0x20800(%rbp),%r8
    3478:	48 8b b5 08 f8 fd ff 	mov    -0x207f8(%rbp),%rsi
    347f:	48 8d 85 30 f8 fd ff 	lea    -0x207d0(%rbp),%rax
    3486:	4d 89 c1             	mov    %r8,%r9
    3489:	41 89 f8             	mov    %edi,%r8d
    348c:	48 89 c7             	mov    %rax,%rdi
    348f:	e8 2c f9 ff ff       	call   2dc0 <mayo_generic_m_calculate_SPS>
    3494:	90                   	nop
    3495:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3499:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    34a0:	00 00 
    34a2:	74 05                	je     34a9 <m_calculate_PS_SPS+0x142>
    34a4:	e8 27 dd ff ff       	call   11d0 <__stack_chk_fail@plt>
    34a9:	c9                   	leave
    34aa:	c3                   	ret

00000000000034ab <decode>:
    34ab:	f3 0f 1e fa          	endbr64
    34af:	55                   	push   %rbp
    34b0:	48 89 e5             	mov    %rsp,%rbp
    34b3:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    34b7:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    34bb:	89 55 dc             	mov    %edx,-0x24(%rbp)
    34be:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    34c5:	eb 44                	jmp    350b <decode+0x60>
    34c7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    34ca:	48 98                	cltq
    34cc:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    34d0:	48 01 d0             	add    %rdx,%rax
    34d3:	0f b6 10             	movzbl (%rax),%edx
    34d6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    34da:	48 8d 48 01          	lea    0x1(%rax),%rcx
    34de:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    34e2:	83 e2 0f             	and    $0xf,%edx
    34e5:	88 10                	mov    %dl,(%rax)
    34e7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    34ea:	48 98                	cltq
    34ec:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    34f0:	48 01 d0             	add    %rdx,%rax
    34f3:	0f b6 10             	movzbl (%rax),%edx
    34f6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    34fa:	48 8d 48 01          	lea    0x1(%rax),%rcx
    34fe:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    3502:	c0 ea 04             	shr    $0x4,%dl
    3505:	88 10                	mov    %dl,(%rax)
    3507:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    350b:	8b 45 dc             	mov    -0x24(%rbp),%eax
    350e:	89 c2                	mov    %eax,%edx
    3510:	c1 ea 1f             	shr    $0x1f,%edx
    3513:	01 d0                	add    %edx,%eax
    3515:	d1 f8                	sar    $1,%eax
    3517:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    351a:	7c ab                	jl     34c7 <decode+0x1c>
    351c:	8b 55 dc             	mov    -0x24(%rbp),%edx
    351f:	89 d0                	mov    %edx,%eax
    3521:	c1 f8 1f             	sar    $0x1f,%eax
    3524:	c1 e8 1f             	shr    $0x1f,%eax
    3527:	01 c2                	add    %eax,%edx
    3529:	83 e2 01             	and    $0x1,%edx
    352c:	29 c2                	sub    %eax,%edx
    352e:	89 d0                	mov    %edx,%eax
    3530:	83 f8 01             	cmp    $0x1,%eax
    3533:	75 20                	jne    3555 <decode+0xaa>
    3535:	8b 45 fc             	mov    -0x4(%rbp),%eax
    3538:	48 98                	cltq
    353a:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    353e:	48 01 d0             	add    %rdx,%rax
    3541:	0f b6 10             	movzbl (%rax),%edx
    3544:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3548:	48 8d 48 01          	lea    0x1(%rax),%rcx
    354c:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    3550:	83 e2 0f             	and    $0xf,%edx
    3553:	88 10                	mov    %dl,(%rax)
    3555:	90                   	nop
    3556:	5d                   	pop    %rbp
    3557:	c3                   	ret

0000000000003558 <encode>:
    3558:	f3 0f 1e fa          	endbr64
    355c:	55                   	push   %rbp
    355d:	48 89 e5             	mov    %rsp,%rbp
    3560:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3564:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    3568:	89 55 dc             	mov    %edx,-0x24(%rbp)
    356b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    3572:	eb 37                	jmp    35ab <encode+0x53>
    3574:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3578:	0f b6 00             	movzbl (%rax),%eax
    357b:	89 c2                	mov    %eax,%edx
    357d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3581:	48 83 c0 01          	add    $0x1,%rax
    3585:	0f b6 00             	movzbl (%rax),%eax
    3588:	0f b6 c0             	movzbl %al,%eax
    358b:	c1 e0 04             	shl    $0x4,%eax
    358e:	89 d1                	mov    %edx,%ecx
    3590:	09 c1                	or     %eax,%ecx
    3592:	8b 45 fc             	mov    -0x4(%rbp),%eax
    3595:	48 98                	cltq
    3597:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    359b:	48 01 d0             	add    %rdx,%rax
    359e:	89 ca                	mov    %ecx,%edx
    35a0:	88 10                	mov    %dl,(%rax)
    35a2:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    35a6:	48 83 45 e8 02       	addq   $0x2,-0x18(%rbp)
    35ab:	8b 45 dc             	mov    -0x24(%rbp),%eax
    35ae:	89 c2                	mov    %eax,%edx
    35b0:	c1 ea 1f             	shr    $0x1f,%edx
    35b3:	01 d0                	add    %edx,%eax
    35b5:	d1 f8                	sar    $1,%eax
    35b7:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    35ba:	7c b8                	jl     3574 <encode+0x1c>
    35bc:	8b 55 dc             	mov    -0x24(%rbp),%edx
    35bf:	89 d0                	mov    %edx,%eax
    35c1:	c1 f8 1f             	sar    $0x1f,%eax
    35c4:	c1 e8 1f             	shr    $0x1f,%eax
    35c7:	01 c2                	add    %eax,%edx
    35c9:	83 e2 01             	and    $0x1,%edx
    35cc:	29 c2                	sub    %eax,%edx
    35ce:	89 d0                	mov    %edx,%eax
    35d0:	83 f8 01             	cmp    $0x1,%eax
    35d3:	75 15                	jne    35ea <encode+0x92>
    35d5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    35d8:	48 98                	cltq
    35da:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    35de:	48 01 c2             	add    %rax,%rdx
    35e1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    35e5:	0f b6 00             	movzbl (%rax),%eax
    35e8:	88 02                	mov    %al,(%rdx)
    35ea:	90                   	nop
    35eb:	5d                   	pop    %rbp
    35ec:	c3                   	ret

00000000000035ed <compute_rhs>:
    35ed:	f3 0f 1e fa          	endbr64
    35f1:	55                   	push   %rbp
    35f2:	48 89 e5             	mov    %rsp,%rbp
    35f5:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
    35fc:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    3603:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
    360a:	48 89 95 48 ff ff ff 	mov    %rdx,-0xb8(%rbp)
    3611:	48 89 8d 40 ff ff ff 	mov    %rcx,-0xc0(%rbp)
    3618:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    361f:	00 00 
    3621:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3625:	31 c0                	xor    %eax,%eax
    3627:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    362e:	8b 00                	mov    (%rax),%eax
    3630:	8d 50 ff             	lea    -0x1(%rax),%edx
    3633:	89 d0                	mov    %edx,%eax
    3635:	c1 f8 1f             	sar    $0x1f,%eax
    3638:	c1 e8 1c             	shr    $0x1c,%eax
    363b:	01 c2                	add    %eax,%edx
    363d:	83 e2 0f             	and    $0xf,%edx
    3640:	29 c2                	sub    %eax,%edx
    3642:	89 d0                	mov    %edx,%eax
    3644:	c1 e0 02             	shl    $0x2,%eax
    3647:	48 98                	cltq
    3649:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    364d:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3654:	8b 40 5c             	mov    0x5c(%rax),%eax
    3657:	48 98                	cltq
    3659:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    365d:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3664:	8b 00                	mov    (%rax),%eax
    3666:	83 e0 0f             	and    $0xf,%eax
    3669:	85 c0                	test   %eax,%eax
    366b:	0f 84 b3 00 00 00    	je     3724 <compute_rhs+0x137>
    3671:	48 c7 45 a0 01 00 00 	movq   $0x1,-0x60(%rbp)
    3678:	00 
    3679:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3680:	8b 10                	mov    (%rax),%edx
    3682:	89 d0                	mov    %edx,%eax
    3684:	c1 f8 1f             	sar    $0x1f,%eax
    3687:	c1 e8 1c             	shr    $0x1c,%eax
    368a:	01 c2                	add    %eax,%edx
    368c:	83 e2 0f             	and    $0xf,%edx
    368f:	29 c2                	sub    %eax,%edx
    3691:	89 d0                	mov    %edx,%eax
    3693:	c1 e0 02             	shl    $0x2,%eax
    3696:	89 c1                	mov    %eax,%ecx
    3698:	48 d3 65 a0          	shlq   %cl,-0x60(%rbp)
    369c:	48 83 6d a0 01       	subq   $0x1,-0x60(%rbp)
    36a1:	c7 85 70 ff ff ff 00 	movl   $0x0,-0x90(%rbp)
    36a8:	00 00 00 
    36ab:	eb 58                	jmp    3705 <compute_rhs+0x118>
    36ad:	8b 85 70 ff ff ff    	mov    -0x90(%rbp),%eax
    36b3:	48 98                	cltq
    36b5:	48 83 c0 01          	add    $0x1,%rax
    36b9:	48 0f af 45 98       	imul   -0x68(%rbp),%rax
    36be:	48 c1 e0 03          	shl    $0x3,%rax
    36c2:	48 8d 50 f8          	lea    -0x8(%rax),%rdx
    36c6:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    36cd:	48 01 d0             	add    %rdx,%rax
    36d0:	48 8b 00             	mov    (%rax),%rax
    36d3:	8b 95 70 ff ff ff    	mov    -0x90(%rbp),%edx
    36d9:	48 63 d2             	movslq %edx,%rdx
    36dc:	48 83 c2 01          	add    $0x1,%rdx
    36e0:	48 0f af 55 98       	imul   -0x68(%rbp),%rdx
    36e5:	48 c1 e2 03          	shl    $0x3,%rdx
    36e9:	48 8d 4a f8          	lea    -0x8(%rdx),%rcx
    36ed:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    36f4:	48 01 ca             	add    %rcx,%rdx
    36f7:	48 23 45 a0          	and    -0x60(%rbp),%rax
    36fb:	48 89 02             	mov    %rax,(%rdx)
    36fe:	83 85 70 ff ff ff 01 	addl   $0x1,-0x90(%rbp)
    3705:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    370c:	8b 50 0c             	mov    0xc(%rax),%edx
    370f:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3716:	8b 40 0c             	mov    0xc(%rax),%eax
    3719:	0f af c2             	imul   %edx,%eax
    371c:	39 85 70 ff ff ff    	cmp    %eax,-0x90(%rbp)
    3722:	7c 89                	jl     36ad <compute_rhs+0xc0>
    3724:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    372b:	00 
    372c:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    3733:	00 
    3734:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    373b:	00 
    373c:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    3743:	00 
    3744:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    374b:	00 
    374c:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3753:	00 
    3754:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    375b:	00 
    375c:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3763:	00 
    3764:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    376b:	00 
    376c:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    3770:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    3774:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    377b:	8b 40 0c             	mov    0xc(%rax),%eax
    377e:	83 e8 01             	sub    $0x1,%eax
    3781:	89 85 74 ff ff ff    	mov    %eax,-0x8c(%rbp)
    3787:	e9 8e 02 00 00       	jmp    3a1a <compute_rhs+0x42d>
    378c:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    3792:	89 85 78 ff ff ff    	mov    %eax,-0x88(%rbp)
    3798:	e9 60 02 00 00       	jmp    39fd <compute_rhs+0x410>
    379d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    37a1:	48 83 e8 01          	sub    $0x1,%rax
    37a5:	48 8b 44 c5 b0       	mov    -0x50(%rbp,%rax,8),%rax
    37aa:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    37ae:	89 d1                	mov    %edx,%ecx
    37b0:	48 d3 e8             	shr    %cl,%rax
    37b3:	83 e0 0f             	and    $0xf,%eax
    37b6:	88 85 6f ff ff ff    	mov    %al,-0x91(%rbp)
    37bc:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    37c0:	48 83 e8 01          	sub    $0x1,%rax
    37c4:	48 8b 54 c5 b0       	mov    -0x50(%rbp,%rax,8),%rdx
    37c9:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    37cd:	48 83 e8 01          	sub    $0x1,%rax
    37d1:	48 c1 e2 04          	shl    $0x4,%rdx
    37d5:	48 89 54 c5 b0       	mov    %rdx,-0x50(%rbp,%rax,8)
    37da:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    37de:	83 e8 02             	sub    $0x2,%eax
    37e1:	89 85 7c ff ff ff    	mov    %eax,-0x84(%rbp)
    37e7:	eb 5f                	jmp    3848 <compute_rhs+0x25b>
    37e9:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    37ef:	83 c0 01             	add    $0x1,%eax
    37f2:	48 98                	cltq
    37f4:	48 8b 4c c5 b0       	mov    -0x50(%rbp,%rax,8),%rcx
    37f9:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    37ff:	48 98                	cltq
    3801:	48 8b 44 c5 b0       	mov    -0x50(%rbp,%rax,8),%rax
    3806:	48 c1 e8 3c          	shr    $0x3c,%rax
    380a:	48 89 c2             	mov    %rax,%rdx
    380d:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    3813:	83 c0 01             	add    $0x1,%eax
    3816:	48 31 ca             	xor    %rcx,%rdx
    3819:	48 98                	cltq
    381b:	48 89 54 c5 b0       	mov    %rdx,-0x50(%rbp,%rax,8)
    3820:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    3826:	48 98                	cltq
    3828:	48 8b 44 c5 b0       	mov    -0x50(%rbp,%rax,8),%rax
    382d:	48 c1 e0 04          	shl    $0x4,%rax
    3831:	48 89 c2             	mov    %rax,%rdx
    3834:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    383a:	48 98                	cltq
    383c:	48 89 54 c5 b0       	mov    %rdx,-0x50(%rbp,%rax,8)
    3841:	83 ad 7c ff ff ff 01 	subl   $0x1,-0x84(%rbp)
    3848:	83 bd 7c ff ff ff 00 	cmpl   $0x0,-0x84(%rbp)
    384f:	79 98                	jns    37e9 <compute_rhs+0x1fc>
    3851:	c7 45 80 00 00 00 00 	movl   $0x0,-0x80(%rbp)
    3858:	e9 c6 00 00 00       	jmp    3923 <compute_rhs+0x336>
    385d:	8b 45 80             	mov    -0x80(%rbp),%eax
    3860:	83 e0 01             	and    $0x1,%eax
    3863:	85 c0                	test   %eax,%eax
    3865:	75 56                	jne    38bd <compute_rhs+0x2d0>
    3867:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    386e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    3872:	8b 45 80             	mov    -0x80(%rbp),%eax
    3875:	48 98                	cltq
    3877:	48 01 d0             	add    %rdx,%rax
    387a:	0f b6 00             	movzbl (%rax),%eax
    387d:	0f b6 d0             	movzbl %al,%edx
    3880:	0f b6 85 6f ff ff ff 	movzbl -0x91(%rbp),%eax
    3887:	89 d6                	mov    %edx,%esi
    3889:	89 c7                	mov    %eax,%edi
    388b:	e8 07 e3 ff ff       	call   1b97 <mul_f>
    3890:	89 c2                	mov    %eax,%edx
    3892:	8b 45 80             	mov    -0x80(%rbp),%eax
    3895:	89 c1                	mov    %eax,%ecx
    3897:	c1 e9 1f             	shr    $0x1f,%ecx
    389a:	01 c8                	add    %ecx,%eax
    389c:	d1 f8                	sar    $1,%eax
    389e:	89 c7                	mov    %eax,%edi
    38a0:	48 63 c7             	movslq %edi,%rax
    38a3:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    38a7:	48 01 c8             	add    %rcx,%rax
    38aa:	0f b6 30             	movzbl (%rax),%esi
    38ad:	48 63 c7             	movslq %edi,%rax
    38b0:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    38b4:	48 01 c8             	add    %rcx,%rax
    38b7:	31 f2                	xor    %esi,%edx
    38b9:	88 10                	mov    %dl,(%rax)
    38bb:	eb 62                	jmp    391f <compute_rhs+0x332>
    38bd:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    38c4:	48 8b 50 18          	mov    0x18(%rax),%rdx
    38c8:	8b 45 80             	mov    -0x80(%rbp),%eax
    38cb:	48 98                	cltq
    38cd:	48 01 d0             	add    %rdx,%rax
    38d0:	0f b6 00             	movzbl (%rax),%eax
    38d3:	0f b6 d0             	movzbl %al,%edx
    38d6:	0f b6 85 6f ff ff ff 	movzbl -0x91(%rbp),%eax
    38dd:	89 d6                	mov    %edx,%esi
    38df:	89 c7                	mov    %eax,%edi
    38e1:	e8 b1 e2 ff ff       	call   1b97 <mul_f>
    38e6:	0f b6 c0             	movzbl %al,%eax
    38e9:	c1 e0 04             	shl    $0x4,%eax
    38ec:	89 c6                	mov    %eax,%esi
    38ee:	8b 45 80             	mov    -0x80(%rbp),%eax
    38f1:	89 c2                	mov    %eax,%edx
    38f3:	c1 ea 1f             	shr    $0x1f,%edx
    38f6:	01 d0                	add    %edx,%eax
    38f8:	d1 f8                	sar    $1,%eax
    38fa:	89 c1                	mov    %eax,%ecx
    38fc:	48 63 c1             	movslq %ecx,%rax
    38ff:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3903:	48 01 d0             	add    %rdx,%rax
    3906:	0f b6 00             	movzbl (%rax),%eax
    3909:	89 c2                	mov    %eax,%edx
    390b:	89 f0                	mov    %esi,%eax
    390d:	89 d6                	mov    %edx,%esi
    390f:	31 c6                	xor    %eax,%esi
    3911:	48 63 c1             	movslq %ecx,%rax
    3914:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3918:	48 01 d0             	add    %rdx,%rax
    391b:	89 f2                	mov    %esi,%edx
    391d:	88 10                	mov    %dl,(%rax)
    391f:	83 45 80 01          	addl   $0x1,-0x80(%rbp)
    3923:	83 7d 80 03          	cmpl   $0x3,-0x80(%rbp)
    3927:	0f 8e 30 ff ff ff    	jle    385d <compute_rhs+0x270>
    392d:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
    3934:	00 
    3935:	e9 ae 00 00 00       	jmp    39e8 <compute_rhs+0x3fb>
    393a:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    393e:	48 8b 4c c5 b0       	mov    -0x50(%rbp,%rax,8),%rcx
    3943:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    394a:	8b 40 0c             	mov    0xc(%rax),%eax
    394d:	0f af 85 74 ff ff ff 	imul   -0x8c(%rbp),%eax
    3954:	8b 95 78 ff ff ff    	mov    -0x88(%rbp),%edx
    395a:	01 d0                	add    %edx,%eax
    395c:	48 98                	cltq
    395e:	48 0f af 45 98       	imul   -0x68(%rbp),%rax
    3963:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    3967:	48 01 d0             	add    %rdx,%rax
    396a:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3971:	00 
    3972:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    3979:	48 01 d0             	add    %rdx,%rax
    397c:	48 8b 30             	mov    (%rax),%rsi
    397f:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    3985:	3b 85 78 ff ff ff    	cmp    -0x88(%rbp),%eax
    398b:	0f 95 c0             	setne  %al
    398e:	0f b6 d0             	movzbl %al,%edx
    3991:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3998:	8b 40 0c             	mov    0xc(%rax),%eax
    399b:	0f af 85 78 ff ff ff 	imul   -0x88(%rbp),%eax
    39a2:	8b bd 74 ff ff ff    	mov    -0x8c(%rbp),%edi
    39a8:	01 f8                	add    %edi,%eax
    39aa:	48 98                	cltq
    39ac:	48 0f af 45 98       	imul   -0x68(%rbp),%rax
    39b1:	48 8b 7d 88          	mov    -0x78(%rbp),%rdi
    39b5:	48 01 f8             	add    %rdi,%rax
    39b8:	48 8d 3c c5 00 00 00 	lea    0x0(,%rax,8),%rdi
    39bf:	00 
    39c0:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    39c7:	48 01 f8             	add    %rdi,%rax
    39ca:	48 8b 00             	mov    (%rax),%rax
    39cd:	48 0f af c2          	imul   %rdx,%rax
    39d1:	48 31 f0             	xor    %rsi,%rax
    39d4:	48 31 c1             	xor    %rax,%rcx
    39d7:	48 89 ca             	mov    %rcx,%rdx
    39da:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    39de:	48 89 54 c5 b0       	mov    %rdx,-0x50(%rbp,%rax,8)
    39e3:	48 83 45 88 01       	addq   $0x1,-0x78(%rbp)
    39e8:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    39ec:	48 3b 45 98          	cmp    -0x68(%rbp),%rax
    39f0:	0f 82 44 ff ff ff    	jb     393a <compute_rhs+0x34d>
    39f6:	83 85 78 ff ff ff 01 	addl   $0x1,-0x88(%rbp)
    39fd:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3a04:	8b 40 0c             	mov    0xc(%rax),%eax
    3a07:	39 85 78 ff ff ff    	cmp    %eax,-0x88(%rbp)
    3a0d:	0f 8c 8a fd ff ff    	jl     379d <compute_rhs+0x1b0>
    3a13:	83 ad 74 ff ff ff 01 	subl   $0x1,-0x8c(%rbp)
    3a1a:	83 bd 74 ff ff ff 00 	cmpl   $0x0,-0x8c(%rbp)
    3a21:	0f 89 65 fd ff ff    	jns    378c <compute_rhs+0x19f>
    3a27:	c7 45 84 00 00 00 00 	movl   $0x0,-0x7c(%rbp)
    3a2e:	e9 94 00 00 00       	jmp    3ac7 <compute_rhs+0x4da>
    3a33:	8b 45 84             	mov    -0x7c(%rbp),%eax
    3a36:	48 98                	cltq
    3a38:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    3a3f:	48 01 d0             	add    %rdx,%rax
    3a42:	0f b6 00             	movzbl (%rax),%eax
    3a45:	89 c1                	mov    %eax,%ecx
    3a47:	8b 45 84             	mov    -0x7c(%rbp),%eax
    3a4a:	89 c2                	mov    %eax,%edx
    3a4c:	c1 ea 1f             	shr    $0x1f,%edx
    3a4f:	01 d0                	add    %edx,%eax
    3a51:	d1 f8                	sar    $1,%eax
    3a53:	48 98                	cltq
    3a55:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3a59:	48 01 d0             	add    %rdx,%rax
    3a5c:	0f b6 00             	movzbl (%rax),%eax
    3a5f:	83 e0 0f             	and    $0xf,%eax
    3a62:	31 c1                	xor    %eax,%ecx
    3a64:	8b 45 84             	mov    -0x7c(%rbp),%eax
    3a67:	48 98                	cltq
    3a69:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    3a70:	48 01 d0             	add    %rdx,%rax
    3a73:	89 ca                	mov    %ecx,%edx
    3a75:	88 10                	mov    %dl,(%rax)
    3a77:	8b 45 84             	mov    -0x7c(%rbp),%eax
    3a7a:	48 98                	cltq
    3a7c:	48 8d 50 01          	lea    0x1(%rax),%rdx
    3a80:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    3a87:	48 01 d0             	add    %rdx,%rax
    3a8a:	0f b6 08             	movzbl (%rax),%ecx
    3a8d:	8b 45 84             	mov    -0x7c(%rbp),%eax
    3a90:	89 c2                	mov    %eax,%edx
    3a92:	c1 ea 1f             	shr    $0x1f,%edx
    3a95:	01 d0                	add    %edx,%eax
    3a97:	d1 f8                	sar    $1,%eax
    3a99:	48 98                	cltq
    3a9b:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3a9f:	48 01 d0             	add    %rdx,%rax
    3aa2:	0f b6 00             	movzbl (%rax),%eax
    3aa5:	c0 e8 04             	shr    $0x4,%al
    3aa8:	89 c6                	mov    %eax,%esi
    3aaa:	8b 45 84             	mov    -0x7c(%rbp),%eax
    3aad:	48 98                	cltq
    3aaf:	48 8d 50 01          	lea    0x1(%rax),%rdx
    3ab3:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    3aba:	48 01 d0             	add    %rdx,%rax
    3abd:	31 f1                	xor    %esi,%ecx
    3abf:	89 ca                	mov    %ecx,%edx
    3ac1:	88 10                	mov    %dl,(%rax)
    3ac3:	83 45 84 02          	addl   $0x2,-0x7c(%rbp)
    3ac7:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    3ace:	8b 00                	mov    (%rax),%eax
    3ad0:	39 45 84             	cmp    %eax,-0x7c(%rbp)
    3ad3:	0f 8c 5a ff ff ff    	jl     3a33 <compute_rhs+0x446>
    3ad9:	90                   	nop
    3ada:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3ade:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    3ae5:	00 00 
    3ae7:	74 05                	je     3aee <compute_rhs+0x501>
    3ae9:	e8 e2 d6 ff ff       	call   11d0 <__stack_chk_fail@plt>
    3aee:	c9                   	leave
    3aef:	c3                   	ret

0000000000003af0 <transpose_16x16_nibbles>:
    3af0:	f3 0f 1e fa          	endbr64
    3af4:	55                   	push   %rbp
    3af5:	48 89 e5             	mov    %rsp,%rbp
    3af8:	48 89 7d a8          	mov    %rdi,-0x58(%rbp)
    3afc:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    3b03:	00 
    3b04:	e9 bf 00 00 00       	jmp    3bc8 <transpose_16x16_nibbles+0xd8>
    3b09:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    3b0d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3b14:	00 
    3b15:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3b19:	48 01 d0             	add    %rdx,%rax
    3b1c:	48 8b 00             	mov    (%rax),%rax
    3b1f:	48 c1 e8 04          	shr    $0x4,%rax
    3b23:	48 89 c2             	mov    %rax,%rdx
    3b26:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    3b2a:	48 83 c0 01          	add    $0x1,%rax
    3b2e:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    3b35:	00 
    3b36:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3b3a:	48 01 c8             	add    %rcx,%rax
    3b3d:	48 8b 00             	mov    (%rax),%rax
    3b40:	48 31 c2             	xor    %rax,%rdx
    3b43:	48 8b 05 76 a5 00 00 	mov    0xa576(%rip),%rax        # e0c0 <even_nibbles.3407>
    3b4a:	48 21 d0             	and    %rdx,%rax
    3b4d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3b51:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    3b55:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3b5c:	00 
    3b5d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3b61:	48 01 d0             	add    %rdx,%rax
    3b64:	48 8b 08             	mov    (%rax),%rcx
    3b67:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3b6b:	48 c1 e0 04          	shl    $0x4,%rax
    3b6f:	48 89 c2             	mov    %rax,%rdx
    3b72:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    3b76:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    3b7d:	00 
    3b7e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3b82:	48 01 f0             	add    %rsi,%rax
    3b85:	48 31 ca             	xor    %rcx,%rdx
    3b88:	48 89 10             	mov    %rdx,(%rax)
    3b8b:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    3b8f:	48 83 c0 01          	add    $0x1,%rax
    3b93:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3b9a:	00 
    3b9b:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3b9f:	48 01 d0             	add    %rdx,%rax
    3ba2:	48 8b 00             	mov    (%rax),%rax
    3ba5:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    3ba9:	48 83 c2 01          	add    $0x1,%rdx
    3bad:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    3bb4:	00 
    3bb5:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3bb9:	48 01 ca             	add    %rcx,%rdx
    3bbc:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    3bc0:	48 89 02             	mov    %rax,(%rdx)
    3bc3:	48 83 45 b0 02       	addq   $0x2,-0x50(%rbp)
    3bc8:	48 83 7d b0 0f       	cmpq   $0xf,-0x50(%rbp)
    3bcd:	0f 86 36 ff ff ff    	jbe    3b09 <transpose_16x16_nibbles+0x19>
    3bd3:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    3bda:	00 
    3bdb:	e9 85 01 00 00       	jmp    3d65 <transpose_16x16_nibbles+0x275>
    3be0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3be4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3beb:	00 
    3bec:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3bf0:	48 01 d0             	add    %rdx,%rax
    3bf3:	48 8b 00             	mov    (%rax),%rax
    3bf6:	48 c1 e8 08          	shr    $0x8,%rax
    3bfa:	48 89 c2             	mov    %rax,%rdx
    3bfd:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3c01:	48 83 c0 02          	add    $0x2,%rax
    3c05:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    3c0c:	00 
    3c0d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3c11:	48 01 c8             	add    %rcx,%rax
    3c14:	48 8b 00             	mov    (%rax),%rax
    3c17:	48 31 c2             	xor    %rax,%rdx
    3c1a:	48 8b 05 a7 a4 00 00 	mov    0xa4a7(%rip),%rax        # e0c8 <even_bytes.3408>
    3c21:	48 21 d0             	and    %rdx,%rax
    3c24:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3c28:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3c2c:	48 83 c0 01          	add    $0x1,%rax
    3c30:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3c37:	00 
    3c38:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3c3c:	48 01 d0             	add    %rdx,%rax
    3c3f:	48 8b 00             	mov    (%rax),%rax
    3c42:	48 c1 e8 08          	shr    $0x8,%rax
    3c46:	48 89 c2             	mov    %rax,%rdx
    3c49:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3c4d:	48 83 c0 03          	add    $0x3,%rax
    3c51:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    3c58:	00 
    3c59:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3c5d:	48 01 c8             	add    %rcx,%rax
    3c60:	48 8b 00             	mov    (%rax),%rax
    3c63:	48 31 c2             	xor    %rax,%rdx
    3c66:	48 8b 05 5b a4 00 00 	mov    0xa45b(%rip),%rax        # e0c8 <even_bytes.3408>
    3c6d:	48 21 d0             	and    %rdx,%rax
    3c70:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3c74:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3c78:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3c7f:	00 
    3c80:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3c84:	48 01 d0             	add    %rdx,%rax
    3c87:	48 8b 08             	mov    (%rax),%rcx
    3c8a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3c8e:	48 c1 e0 08          	shl    $0x8,%rax
    3c92:	48 89 c2             	mov    %rax,%rdx
    3c95:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3c99:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    3ca0:	00 
    3ca1:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3ca5:	48 01 f0             	add    %rsi,%rax
    3ca8:	48 31 ca             	xor    %rcx,%rdx
    3cab:	48 89 10             	mov    %rdx,(%rax)
    3cae:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3cb2:	48 83 c0 01          	add    $0x1,%rax
    3cb6:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3cbd:	00 
    3cbe:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3cc2:	48 01 d0             	add    %rdx,%rax
    3cc5:	48 8b 08             	mov    (%rax),%rcx
    3cc8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3ccc:	48 c1 e0 08          	shl    $0x8,%rax
    3cd0:	48 89 c2             	mov    %rax,%rdx
    3cd3:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3cd7:	48 83 c0 01          	add    $0x1,%rax
    3cdb:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    3ce2:	00 
    3ce3:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3ce7:	48 01 f0             	add    %rsi,%rax
    3cea:	48 31 ca             	xor    %rcx,%rdx
    3ced:	48 89 10             	mov    %rdx,(%rax)
    3cf0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3cf4:	48 83 c0 02          	add    $0x2,%rax
    3cf8:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3cff:	00 
    3d00:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3d04:	48 01 d0             	add    %rdx,%rax
    3d07:	48 8b 00             	mov    (%rax),%rax
    3d0a:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    3d0e:	48 83 c2 02          	add    $0x2,%rdx
    3d12:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    3d19:	00 
    3d1a:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3d1e:	48 01 ca             	add    %rcx,%rdx
    3d21:	48 33 45 e8          	xor    -0x18(%rbp),%rax
    3d25:	48 89 02             	mov    %rax,(%rdx)
    3d28:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3d2c:	48 83 c0 03          	add    $0x3,%rax
    3d30:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3d37:	00 
    3d38:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3d3c:	48 01 d0             	add    %rdx,%rax
    3d3f:	48 8b 00             	mov    (%rax),%rax
    3d42:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    3d46:	48 83 c2 03          	add    $0x3,%rdx
    3d4a:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    3d51:	00 
    3d52:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3d56:	48 01 ca             	add    %rcx,%rdx
    3d59:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    3d5d:	48 89 02             	mov    %rax,(%rdx)
    3d60:	48 83 45 b8 04       	addq   $0x4,-0x48(%rbp)
    3d65:	48 83 7d b8 0f       	cmpq   $0xf,-0x48(%rbp)
    3d6a:	0f 86 70 fe ff ff    	jbe    3be0 <transpose_16x16_nibbles+0xf0>
    3d70:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    3d77:	00 
    3d78:	e9 85 01 00 00       	jmp    3f02 <transpose_16x16_nibbles+0x412>
    3d7d:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3d81:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3d88:	00 
    3d89:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3d8d:	48 01 d0             	add    %rdx,%rax
    3d90:	48 8b 00             	mov    (%rax),%rax
    3d93:	48 c1 e8 10          	shr    $0x10,%rax
    3d97:	48 89 c2             	mov    %rax,%rdx
    3d9a:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3d9e:	48 83 c0 04          	add    $0x4,%rax
    3da2:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    3da9:	00 
    3daa:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3dae:	48 01 c8             	add    %rcx,%rax
    3db1:	48 8b 00             	mov    (%rax),%rax
    3db4:	48 31 c2             	xor    %rax,%rdx
    3db7:	48 8b 05 12 a3 00 00 	mov    0xa312(%rip),%rax        # e0d0 <even_2bytes.3409>
    3dbe:	48 21 d0             	and    %rdx,%rax
    3dc1:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    3dc5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3dc9:	48 83 c0 08          	add    $0x8,%rax
    3dcd:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3dd4:	00 
    3dd5:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3dd9:	48 01 d0             	add    %rdx,%rax
    3ddc:	48 8b 00             	mov    (%rax),%rax
    3ddf:	48 c1 e8 10          	shr    $0x10,%rax
    3de3:	48 89 c2             	mov    %rax,%rdx
    3de6:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3dea:	48 83 c0 0c          	add    $0xc,%rax
    3dee:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    3df5:	00 
    3df6:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3dfa:	48 01 c8             	add    %rcx,%rax
    3dfd:	48 8b 00             	mov    (%rax),%rax
    3e00:	48 31 c2             	xor    %rax,%rdx
    3e03:	48 8b 05 c6 a2 00 00 	mov    0xa2c6(%rip),%rax        # e0d0 <even_2bytes.3409>
    3e0a:	48 21 d0             	and    %rdx,%rax
    3e0d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    3e11:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3e15:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3e1c:	00 
    3e1d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3e21:	48 01 d0             	add    %rdx,%rax
    3e24:	48 8b 08             	mov    (%rax),%rcx
    3e27:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3e2b:	48 c1 e0 10          	shl    $0x10,%rax
    3e2f:	48 89 c2             	mov    %rax,%rdx
    3e32:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3e36:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    3e3d:	00 
    3e3e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3e42:	48 01 f0             	add    %rsi,%rax
    3e45:	48 31 ca             	xor    %rcx,%rdx
    3e48:	48 89 10             	mov    %rdx,(%rax)
    3e4b:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3e4f:	48 83 c0 08          	add    $0x8,%rax
    3e53:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3e5a:	00 
    3e5b:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3e5f:	48 01 d0             	add    %rdx,%rax
    3e62:	48 8b 08             	mov    (%rax),%rcx
    3e65:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e69:	48 c1 e0 10          	shl    $0x10,%rax
    3e6d:	48 89 c2             	mov    %rax,%rdx
    3e70:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3e74:	48 83 c0 08          	add    $0x8,%rax
    3e78:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    3e7f:	00 
    3e80:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3e84:	48 01 f0             	add    %rsi,%rax
    3e87:	48 31 ca             	xor    %rcx,%rdx
    3e8a:	48 89 10             	mov    %rdx,(%rax)
    3e8d:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3e91:	48 83 c0 04          	add    $0x4,%rax
    3e95:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3e9c:	00 
    3e9d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3ea1:	48 01 d0             	add    %rdx,%rax
    3ea4:	48 8b 00             	mov    (%rax),%rax
    3ea7:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    3eab:	48 83 c2 04          	add    $0x4,%rdx
    3eaf:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    3eb6:	00 
    3eb7:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3ebb:	48 01 ca             	add    %rcx,%rdx
    3ebe:	48 33 45 d8          	xor    -0x28(%rbp),%rax
    3ec2:	48 89 02             	mov    %rax,(%rdx)
    3ec5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    3ec9:	48 83 c0 0c          	add    $0xc,%rax
    3ecd:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3ed4:	00 
    3ed5:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3ed9:	48 01 d0             	add    %rdx,%rax
    3edc:	48 8b 00             	mov    (%rax),%rax
    3edf:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    3ee3:	48 83 c2 0c          	add    $0xc,%rdx
    3ee7:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    3eee:	00 
    3eef:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3ef3:	48 01 ca             	add    %rcx,%rdx
    3ef6:	48 33 45 e0          	xor    -0x20(%rbp),%rax
    3efa:	48 89 02             	mov    %rax,(%rdx)
    3efd:	48 83 45 c0 01       	addq   $0x1,-0x40(%rbp)
    3f02:	48 83 7d c0 03       	cmpq   $0x3,-0x40(%rbp)
    3f07:	0f 86 70 fe ff ff    	jbe    3d7d <transpose_16x16_nibbles+0x28d>
    3f0d:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    3f14:	00 
    3f15:	e9 bf 00 00 00       	jmp    3fd9 <transpose_16x16_nibbles+0x4e9>
    3f1a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f1e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3f25:	00 
    3f26:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3f2a:	48 01 d0             	add    %rdx,%rax
    3f2d:	48 8b 00             	mov    (%rax),%rax
    3f30:	48 c1 e8 20          	shr    $0x20,%rax
    3f34:	48 89 c2             	mov    %rax,%rdx
    3f37:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f3b:	48 83 c0 08          	add    $0x8,%rax
    3f3f:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    3f46:	00 
    3f47:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3f4b:	48 01 c8             	add    %rcx,%rax
    3f4e:	48 8b 00             	mov    (%rax),%rax
    3f51:	48 31 c2             	xor    %rax,%rdx
    3f54:	48 8b 05 7d a1 00 00 	mov    0xa17d(%rip),%rax        # e0d8 <even_half.3410>
    3f5b:	48 21 d0             	and    %rdx,%rax
    3f5e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    3f62:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f66:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3f6d:	00 
    3f6e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3f72:	48 01 d0             	add    %rdx,%rax
    3f75:	48 8b 08             	mov    (%rax),%rcx
    3f78:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3f7c:	48 c1 e0 20          	shl    $0x20,%rax
    3f80:	48 89 c2             	mov    %rax,%rdx
    3f83:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f87:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    3f8e:	00 
    3f8f:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3f93:	48 01 f0             	add    %rsi,%rax
    3f96:	48 31 ca             	xor    %rcx,%rdx
    3f99:	48 89 10             	mov    %rdx,(%rax)
    3f9c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3fa0:	48 83 c0 08          	add    $0x8,%rax
    3fa4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3fab:	00 
    3fac:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3fb0:	48 01 d0             	add    %rdx,%rax
    3fb3:	48 8b 00             	mov    (%rax),%rax
    3fb6:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    3fba:	48 83 c2 08          	add    $0x8,%rdx
    3fbe:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    3fc5:	00 
    3fc6:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    3fca:	48 01 ca             	add    %rcx,%rdx
    3fcd:	48 33 45 d0          	xor    -0x30(%rbp),%rax
    3fd1:	48 89 02             	mov    %rax,(%rdx)
    3fd4:	48 83 45 c8 01       	addq   $0x1,-0x38(%rbp)
    3fd9:	48 83 7d c8 07       	cmpq   $0x7,-0x38(%rbp)
    3fde:	0f 86 36 ff ff ff    	jbe    3f1a <transpose_16x16_nibbles+0x42a>
    3fe4:	90                   	nop
    3fe5:	90                   	nop
    3fe6:	5d                   	pop    %rbp
    3fe7:	c3                   	ret

0000000000003fe8 <compute_A>:
    3fe8:	f3 0f 1e fa          	endbr64
    3fec:	55                   	push   %rbp
    3fed:	48 89 e5             	mov    %rsp,%rbp
    3ff0:	53                   	push   %rbx
    3ff1:	4c 8d 9c 24 00 90 ff 	lea    -0x7000(%rsp),%r11
    3ff8:	ff 
    3ff9:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    4000:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    4005:	4c 39 dc             	cmp    %r11,%rsp
    4008:	75 ef                	jne    3ff9 <compute_A+0x11>
    400a:	48 81 ec f8 05 00 00 	sub    $0x5f8,%rsp
    4011:	48 89 bd 18 8a ff ff 	mov    %rdi,-0x75e8(%rbp)
    4018:	48 89 b5 10 8a ff ff 	mov    %rsi,-0x75f0(%rbp)
    401f:	48 89 95 08 8a ff ff 	mov    %rdx,-0x75f8(%rbp)
    4026:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    402d:	00 00 
    402f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    4033:	31 c0                	xor    %eax,%eax
    4035:	c7 85 28 8a ff ff 00 	movl   $0x0,-0x75d8(%rbp)
    403c:	00 00 00 
    403f:	c7 85 2c 8a ff ff 00 	movl   $0x0,-0x75d4(%rbp)
    4046:	00 00 00 
    4049:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4050:	8b 40 5c             	mov    0x5c(%rax),%eax
    4053:	89 85 5c 8a ff ff    	mov    %eax,-0x75a4(%rbp)
    4059:	48 8d 85 d0 8a ff ff 	lea    -0x7530(%rbp),%rax
    4060:	ba 00 75 00 00       	mov    $0x7500,%edx
    4065:	be 00 00 00 00       	mov    $0x0,%esi
    406a:	48 89 c7             	mov    %rax,%rdi
    406d:	e8 8e d1 ff ff       	call   1200 <memset@plt>
    4072:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4079:	8b 50 08             	mov    0x8(%rax),%edx
    407c:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4083:	8b 40 0c             	mov    0xc(%rax),%eax
    4086:	0f af c2             	imul   %edx,%eax
    4089:	83 c0 0f             	add    $0xf,%eax
    408c:	8d 50 0f             	lea    0xf(%rax),%edx
    408f:	85 c0                	test   %eax,%eax
    4091:	0f 48 c2             	cmovs  %edx,%eax
    4094:	c1 f8 04             	sar    $0x4,%eax
    4097:	c1 e0 04             	shl    $0x4,%eax
    409a:	48 98                	cltq
    409c:	48 89 85 80 8a ff ff 	mov    %rax,-0x7580(%rbp)
    40a3:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    40aa:	8b 00                	mov    (%rax),%eax
    40ac:	83 e0 0f             	and    $0xf,%eax
    40af:	85 c0                	test   %eax,%eax
    40b1:	0f 84 cf 00 00 00    	je     4186 <compute_A+0x19e>
    40b7:	48 c7 85 88 8a ff ff 	movq   $0x1,-0x7578(%rbp)
    40be:	01 00 00 00 
    40c2:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    40c9:	8b 10                	mov    (%rax),%edx
    40cb:	89 d0                	mov    %edx,%eax
    40cd:	c1 f8 1f             	sar    $0x1f,%eax
    40d0:	c1 e8 1c             	shr    $0x1c,%eax
    40d3:	01 c2                	add    %eax,%edx
    40d5:	83 e2 0f             	and    $0xf,%edx
    40d8:	29 c2                	sub    %eax,%edx
    40da:	89 d0                	mov    %edx,%eax
    40dc:	c1 e0 02             	shl    $0x2,%eax
    40df:	89 c1                	mov    %eax,%ecx
    40e1:	48 d3 a5 88 8a ff ff 	shlq   %cl,-0x7578(%rbp)
    40e8:	48 83 ad 88 8a ff ff 	subq   $0x1,-0x7578(%rbp)
    40ef:	01 
    40f0:	c7 85 30 8a ff ff 00 	movl   $0x0,-0x75d0(%rbp)
    40f7:	00 00 00 
    40fa:	eb 67                	jmp    4163 <compute_A+0x17b>
    40fc:	8b 85 30 8a ff ff    	mov    -0x75d0(%rbp),%eax
    4102:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    4109:	8b 95 5c 8a ff ff    	mov    -0x75a4(%rbp),%edx
    410f:	01 d0                	add    %edx,%eax
    4111:	48 98                	cltq
    4113:	48 c1 e0 03          	shl    $0x3,%rax
    4117:	48 8d 50 f8          	lea    -0x8(%rax),%rdx
    411b:	48 8b 85 10 8a ff ff 	mov    -0x75f0(%rbp),%rax
    4122:	48 01 d0             	add    %rdx,%rax
    4125:	48 8b 00             	mov    (%rax),%rax
    4128:	8b 95 30 8a ff ff    	mov    -0x75d0(%rbp),%edx
    412e:	0f af 95 5c 8a ff ff 	imul   -0x75a4(%rbp),%edx
    4135:	8b 8d 5c 8a ff ff    	mov    -0x75a4(%rbp),%ecx
    413b:	01 ca                	add    %ecx,%edx
    413d:	48 63 d2             	movslq %edx,%rdx
    4140:	48 c1 e2 03          	shl    $0x3,%rdx
    4144:	48 8d 4a f8          	lea    -0x8(%rdx),%rcx
    4148:	48 8b 95 10 8a ff ff 	mov    -0x75f0(%rbp),%rdx
    414f:	48 01 ca             	add    %rcx,%rdx
    4152:	48 23 85 88 8a ff ff 	and    -0x7578(%rbp),%rax
    4159:	48 89 02             	mov    %rax,(%rdx)
    415c:	83 85 30 8a ff ff 01 	addl   $0x1,-0x75d0(%rbp)
    4163:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    416a:	8b 50 08             	mov    0x8(%rax),%edx
    416d:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4174:	8b 40 0c             	mov    0xc(%rax),%eax
    4177:	0f af c2             	imul   %edx,%eax
    417a:	39 85 30 8a ff ff    	cmp    %eax,-0x75d0(%rbp)
    4180:	0f 8c 76 ff ff ff    	jl     40fc <compute_A+0x114>
    4186:	c7 85 34 8a ff ff 00 	movl   $0x0,-0x75cc(%rbp)
    418d:	00 00 00 
    4190:	e9 a5 04 00 00       	jmp    463a <compute_A+0x652>
    4195:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    419c:	8b 40 0c             	mov    0xc(%rax),%eax
    419f:	83 e8 01             	sub    $0x1,%eax
    41a2:	89 85 38 8a ff ff    	mov    %eax,-0x75c8(%rbp)
    41a8:	e9 74 04 00 00       	jmp    4621 <compute_A+0x639>
    41ad:	8b 85 38 8a ff ff    	mov    -0x75c8(%rbp),%eax
    41b3:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    41ba:	48 8b 95 18 8a ff ff 	mov    -0x75e8(%rbp),%rdx
    41c1:	8b 52 08             	mov    0x8(%rdx),%edx
    41c4:	0f af c2             	imul   %edx,%eax
    41c7:	48 98                	cltq
    41c9:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    41d0:	00 
    41d1:	48 8b 85 10 8a ff ff 	mov    -0x75f0(%rbp),%rax
    41d8:	48 01 d0             	add    %rdx,%rax
    41db:	48 89 85 c0 8a ff ff 	mov    %rax,-0x7540(%rbp)
    41e2:	c7 85 3c 8a ff ff 00 	movl   $0x0,-0x75c4(%rbp)
    41e9:	00 00 00 
    41ec:	e9 c3 01 00 00       	jmp    43b4 <compute_A+0x3cc>
    41f1:	c7 85 40 8a ff ff 00 	movl   $0x0,-0x75c0(%rbp)
    41f8:	00 00 00 
    41fb:	e9 9b 01 00 00       	jmp    439b <compute_A+0x3b3>
    4200:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4207:	8b 40 08             	mov    0x8(%rax),%eax
    420a:	0f af 85 34 8a ff ff 	imul   -0x75cc(%rbp),%eax
    4211:	8b 95 3c 8a ff ff    	mov    -0x75c4(%rbp),%edx
    4217:	01 d0                	add    %edx,%eax
    4219:	48 63 d0             	movslq %eax,%rdx
    421c:	8b 8d 40 8a ff ff    	mov    -0x75c0(%rbp),%ecx
    4222:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    4228:	01 c8                	add    %ecx,%eax
    422a:	48 98                	cltq
    422c:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    4233:	ff 
    4234:	48 01 d0             	add    %rdx,%rax
    4237:	48 8b b4 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rsi
    423e:	ff 
    423f:	8b 85 3c 8a ff ff    	mov    -0x75c4(%rbp),%eax
    4245:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    424c:	8b 95 40 8a ff ff    	mov    -0x75c0(%rbp),%edx
    4252:	01 d0                	add    %edx,%eax
    4254:	48 98                	cltq
    4256:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    425d:	00 
    425e:	48 8b 85 c0 8a ff ff 	mov    -0x7540(%rbp),%rax
    4265:	48 01 d0             	add    %rdx,%rax
    4268:	48 8b 10             	mov    (%rax),%rdx
    426b:	8b 85 28 8a ff ff    	mov    -0x75d8(%rbp),%eax
    4271:	89 c1                	mov    %eax,%ecx
    4273:	48 d3 e2             	shl    %cl,%rdx
    4276:	48 89 d1             	mov    %rdx,%rcx
    4279:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4280:	8b 40 08             	mov    0x8(%rax),%eax
    4283:	0f af 85 34 8a ff ff 	imul   -0x75cc(%rbp),%eax
    428a:	8b 95 3c 8a ff ff    	mov    -0x75c4(%rbp),%edx
    4290:	01 d0                	add    %edx,%eax
    4292:	48 63 d0             	movslq %eax,%rdx
    4295:	8b bd 40 8a ff ff    	mov    -0x75c0(%rbp),%edi
    429b:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    42a1:	01 f8                	add    %edi,%eax
    42a3:	48 98                	cltq
    42a5:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    42ac:	ff 
    42ad:	48 01 d0             	add    %rdx,%rax
    42b0:	48 31 ce             	xor    %rcx,%rsi
    42b3:	48 89 f2             	mov    %rsi,%rdx
    42b6:	48 89 94 c5 d0 8a ff 	mov    %rdx,-0x7530(%rbp,%rax,8)
    42bd:	ff 
    42be:	83 bd 28 8a ff ff 00 	cmpl   $0x0,-0x75d8(%rbp)
    42c5:	0f 8e c9 00 00 00    	jle    4394 <compute_A+0x3ac>
    42cb:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    42d2:	8b 40 08             	mov    0x8(%rax),%eax
    42d5:	0f af 85 34 8a ff ff 	imul   -0x75cc(%rbp),%eax
    42dc:	8b 95 3c 8a ff ff    	mov    -0x75c4(%rbp),%edx
    42e2:	01 d0                	add    %edx,%eax
    42e4:	48 63 d0             	movslq %eax,%rdx
    42e7:	8b 8d 40 8a ff ff    	mov    -0x75c0(%rbp),%ecx
    42ed:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    42f3:	01 c8                	add    %ecx,%eax
    42f5:	83 c0 01             	add    $0x1,%eax
    42f8:	48 98                	cltq
    42fa:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    4301:	ff 
    4302:	48 01 d0             	add    %rdx,%rax
    4305:	48 8b b4 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rsi
    430c:	ff 
    430d:	8b 85 3c 8a ff ff    	mov    -0x75c4(%rbp),%eax
    4313:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    431a:	8b 95 40 8a ff ff    	mov    -0x75c0(%rbp),%edx
    4320:	01 d0                	add    %edx,%eax
    4322:	48 98                	cltq
    4324:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    432b:	00 
    432c:	48 8b 85 c0 8a ff ff 	mov    -0x7540(%rbp),%rax
    4333:	48 01 d0             	add    %rdx,%rax
    4336:	48 8b 10             	mov    (%rax),%rdx
    4339:	b8 40 00 00 00       	mov    $0x40,%eax
    433e:	2b 85 28 8a ff ff    	sub    -0x75d8(%rbp),%eax
    4344:	89 c1                	mov    %eax,%ecx
    4346:	48 d3 ea             	shr    %cl,%rdx
    4349:	48 89 d1             	mov    %rdx,%rcx
    434c:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4353:	8b 40 08             	mov    0x8(%rax),%eax
    4356:	0f af 85 34 8a ff ff 	imul   -0x75cc(%rbp),%eax
    435d:	8b 95 3c 8a ff ff    	mov    -0x75c4(%rbp),%edx
    4363:	01 d0                	add    %edx,%eax
    4365:	48 63 d0             	movslq %eax,%rdx
    4368:	8b bd 40 8a ff ff    	mov    -0x75c0(%rbp),%edi
    436e:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    4374:	01 f8                	add    %edi,%eax
    4376:	83 c0 01             	add    $0x1,%eax
    4379:	48 98                	cltq
    437b:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    4382:	ff 
    4383:	48 01 d0             	add    %rdx,%rax
    4386:	48 31 ce             	xor    %rcx,%rsi
    4389:	48 89 f2             	mov    %rsi,%rdx
    438c:	48 89 94 c5 d0 8a ff 	mov    %rdx,-0x7530(%rbp,%rax,8)
    4393:	ff 
    4394:	83 85 40 8a ff ff 01 	addl   $0x1,-0x75c0(%rbp)
    439b:	8b 85 40 8a ff ff    	mov    -0x75c0(%rbp),%eax
    43a1:	3b 85 5c 8a ff ff    	cmp    -0x75a4(%rbp),%eax
    43a7:	0f 8c 53 fe ff ff    	jl     4200 <compute_A+0x218>
    43ad:	83 85 3c 8a ff ff 01 	addl   $0x1,-0x75c4(%rbp)
    43b4:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    43bb:	8b 40 08             	mov    0x8(%rax),%eax
    43be:	39 85 3c 8a ff ff    	cmp    %eax,-0x75c4(%rbp)
    43c4:	0f 8c 27 fe ff ff    	jl     41f1 <compute_A+0x209>
    43ca:	8b 85 34 8a ff ff    	mov    -0x75cc(%rbp),%eax
    43d0:	3b 85 38 8a ff ff    	cmp    -0x75c8(%rbp),%eax
    43d6:	0f 84 1d 02 00 00    	je     45f9 <compute_A+0x611>
    43dc:	8b 85 34 8a ff ff    	mov    -0x75cc(%rbp),%eax
    43e2:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    43e9:	48 8b 95 18 8a ff ff 	mov    -0x75e8(%rbp),%rdx
    43f0:	8b 52 08             	mov    0x8(%rdx),%edx
    43f3:	0f af c2             	imul   %edx,%eax
    43f6:	48 98                	cltq
    43f8:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    43ff:	00 
    4400:	48 8b 85 10 8a ff ff 	mov    -0x75f0(%rbp),%rax
    4407:	48 01 d0             	add    %rdx,%rax
    440a:	48 89 85 c8 8a ff ff 	mov    %rax,-0x7538(%rbp)
    4411:	c7 85 44 8a ff ff 00 	movl   $0x0,-0x75bc(%rbp)
    4418:	00 00 00 
    441b:	e9 c3 01 00 00       	jmp    45e3 <compute_A+0x5fb>
    4420:	c7 85 48 8a ff ff 00 	movl   $0x0,-0x75b8(%rbp)
    4427:	00 00 00 
    442a:	e9 9b 01 00 00       	jmp    45ca <compute_A+0x5e2>
    442f:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4436:	8b 40 08             	mov    0x8(%rax),%eax
    4439:	0f af 85 38 8a ff ff 	imul   -0x75c8(%rbp),%eax
    4440:	8b 95 44 8a ff ff    	mov    -0x75bc(%rbp),%edx
    4446:	01 d0                	add    %edx,%eax
    4448:	48 63 d0             	movslq %eax,%rdx
    444b:	8b 8d 48 8a ff ff    	mov    -0x75b8(%rbp),%ecx
    4451:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    4457:	01 c8                	add    %ecx,%eax
    4459:	48 98                	cltq
    445b:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    4462:	ff 
    4463:	48 01 d0             	add    %rdx,%rax
    4466:	48 8b b4 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rsi
    446d:	ff 
    446e:	8b 85 44 8a ff ff    	mov    -0x75bc(%rbp),%eax
    4474:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    447b:	8b 95 48 8a ff ff    	mov    -0x75b8(%rbp),%edx
    4481:	01 d0                	add    %edx,%eax
    4483:	48 98                	cltq
    4485:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    448c:	00 
    448d:	48 8b 85 c8 8a ff ff 	mov    -0x7538(%rbp),%rax
    4494:	48 01 d0             	add    %rdx,%rax
    4497:	48 8b 10             	mov    (%rax),%rdx
    449a:	8b 85 28 8a ff ff    	mov    -0x75d8(%rbp),%eax
    44a0:	89 c1                	mov    %eax,%ecx
    44a2:	48 d3 e2             	shl    %cl,%rdx
    44a5:	48 89 d1             	mov    %rdx,%rcx
    44a8:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    44af:	8b 40 08             	mov    0x8(%rax),%eax
    44b2:	0f af 85 38 8a ff ff 	imul   -0x75c8(%rbp),%eax
    44b9:	8b 95 44 8a ff ff    	mov    -0x75bc(%rbp),%edx
    44bf:	01 d0                	add    %edx,%eax
    44c1:	48 63 d0             	movslq %eax,%rdx
    44c4:	8b bd 48 8a ff ff    	mov    -0x75b8(%rbp),%edi
    44ca:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    44d0:	01 f8                	add    %edi,%eax
    44d2:	48 98                	cltq
    44d4:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    44db:	ff 
    44dc:	48 01 d0             	add    %rdx,%rax
    44df:	48 31 ce             	xor    %rcx,%rsi
    44e2:	48 89 f2             	mov    %rsi,%rdx
    44e5:	48 89 94 c5 d0 8a ff 	mov    %rdx,-0x7530(%rbp,%rax,8)
    44ec:	ff 
    44ed:	83 bd 28 8a ff ff 00 	cmpl   $0x0,-0x75d8(%rbp)
    44f4:	0f 8e c9 00 00 00    	jle    45c3 <compute_A+0x5db>
    44fa:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4501:	8b 40 08             	mov    0x8(%rax),%eax
    4504:	0f af 85 38 8a ff ff 	imul   -0x75c8(%rbp),%eax
    450b:	8b 95 44 8a ff ff    	mov    -0x75bc(%rbp),%edx
    4511:	01 d0                	add    %edx,%eax
    4513:	48 63 d0             	movslq %eax,%rdx
    4516:	8b 8d 48 8a ff ff    	mov    -0x75b8(%rbp),%ecx
    451c:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    4522:	01 c8                	add    %ecx,%eax
    4524:	83 c0 01             	add    $0x1,%eax
    4527:	48 98                	cltq
    4529:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    4530:	ff 
    4531:	48 01 d0             	add    %rdx,%rax
    4534:	48 8b b4 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rsi
    453b:	ff 
    453c:	8b 85 44 8a ff ff    	mov    -0x75bc(%rbp),%eax
    4542:	0f af 85 5c 8a ff ff 	imul   -0x75a4(%rbp),%eax
    4549:	8b 95 48 8a ff ff    	mov    -0x75b8(%rbp),%edx
    454f:	01 d0                	add    %edx,%eax
    4551:	48 98                	cltq
    4553:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    455a:	00 
    455b:	48 8b 85 c8 8a ff ff 	mov    -0x7538(%rbp),%rax
    4562:	48 01 d0             	add    %rdx,%rax
    4565:	48 8b 10             	mov    (%rax),%rdx
    4568:	b8 40 00 00 00       	mov    $0x40,%eax
    456d:	2b 85 28 8a ff ff    	sub    -0x75d8(%rbp),%eax
    4573:	89 c1                	mov    %eax,%ecx
    4575:	48 d3 ea             	shr    %cl,%rdx
    4578:	48 89 d1             	mov    %rdx,%rcx
    457b:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4582:	8b 40 08             	mov    0x8(%rax),%eax
    4585:	0f af 85 38 8a ff ff 	imul   -0x75c8(%rbp),%eax
    458c:	8b 95 44 8a ff ff    	mov    -0x75bc(%rbp),%edx
    4592:	01 d0                	add    %edx,%eax
    4594:	48 63 d0             	movslq %eax,%rdx
    4597:	8b bd 48 8a ff ff    	mov    -0x75b8(%rbp),%edi
    459d:	8b 85 2c 8a ff ff    	mov    -0x75d4(%rbp),%eax
    45a3:	01 f8                	add    %edi,%eax
    45a5:	83 c0 01             	add    $0x1,%eax
    45a8:	48 98                	cltq
    45aa:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    45b1:	ff 
    45b2:	48 01 d0             	add    %rdx,%rax
    45b5:	48 31 ce             	xor    %rcx,%rsi
    45b8:	48 89 f2             	mov    %rsi,%rdx
    45bb:	48 89 94 c5 d0 8a ff 	mov    %rdx,-0x7530(%rbp,%rax,8)
    45c2:	ff 
    45c3:	83 85 48 8a ff ff 01 	addl   $0x1,-0x75b8(%rbp)
    45ca:	8b 85 48 8a ff ff    	mov    -0x75b8(%rbp),%eax
    45d0:	3b 85 5c 8a ff ff    	cmp    -0x75a4(%rbp),%eax
    45d6:	0f 8c 53 fe ff ff    	jl     442f <compute_A+0x447>
    45dc:	83 85 44 8a ff ff 01 	addl   $0x1,-0x75bc(%rbp)
    45e3:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    45ea:	8b 40 08             	mov    0x8(%rax),%eax
    45ed:	39 85 44 8a ff ff    	cmp    %eax,-0x75bc(%rbp)
    45f3:	0f 8c 27 fe ff ff    	jl     4420 <compute_A+0x438>
    45f9:	83 85 28 8a ff ff 04 	addl   $0x4,-0x75d8(%rbp)
    4600:	83 bd 28 8a ff ff 40 	cmpl   $0x40,-0x75d8(%rbp)
    4607:	75 11                	jne    461a <compute_A+0x632>
    4609:	83 85 2c 8a ff ff 01 	addl   $0x1,-0x75d4(%rbp)
    4610:	c7 85 28 8a ff ff 00 	movl   $0x0,-0x75d8(%rbp)
    4617:	00 00 00 
    461a:	83 ad 38 8a ff ff 01 	subl   $0x1,-0x75c8(%rbp)
    4621:	8b 85 38 8a ff ff    	mov    -0x75c8(%rbp),%eax
    4627:	3b 85 34 8a ff ff    	cmp    -0x75cc(%rbp),%eax
    462d:	0f 8d 7a fb ff ff    	jge    41ad <compute_A+0x1c5>
    4633:	83 85 34 8a ff ff 01 	addl   $0x1,-0x75cc(%rbp)
    463a:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4641:	8b 40 0c             	mov    0xc(%rax),%eax
    4644:	39 85 34 8a ff ff    	cmp    %eax,-0x75cc(%rbp)
    464a:	0f 8c 45 fb ff ff    	jl     4195 <compute_A+0x1ad>
    4650:	48 c7 85 60 8a ff ff 	movq   $0x0,-0x75a0(%rbp)
    4657:	00 00 00 00 
    465b:	eb 29                	jmp    4686 <compute_A+0x69e>
    465d:	48 8b 85 60 8a ff ff 	mov    -0x75a0(%rbp),%rax
    4664:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    466b:	00 
    466c:	48 8d 85 d0 8a ff ff 	lea    -0x7530(%rbp),%rax
    4673:	48 01 d0             	add    %rdx,%rax
    4676:	48 89 c7             	mov    %rax,%rdi
    4679:	e8 72 f4 ff ff       	call   3af0 <transpose_16x16_nibbles>
    467e:	48 83 85 60 8a ff ff 	addq   $0x10,-0x75a0(%rbp)
    4685:	10 
    4686:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    468d:	8b 10                	mov    (%rax),%edx
    468f:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4696:	8b 40 0c             	mov    0xc(%rax),%eax
    4699:	8d 48 01             	lea    0x1(%rax),%ecx
    469c:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    46a3:	8b 40 0c             	mov    0xc(%rax),%eax
    46a6:	0f af c1             	imul   %ecx,%eax
    46a9:	89 c1                	mov    %eax,%ecx
    46ab:	c1 e9 1f             	shr    $0x1f,%ecx
    46ae:	01 c8                	add    %ecx,%eax
    46b0:	d1 f8                	sar    $1,%eax
    46b2:	01 d0                	add    %edx,%eax
    46b4:	83 c0 0f             	add    $0xf,%eax
    46b7:	8d 50 0f             	lea    0xf(%rax),%edx
    46ba:	85 c0                	test   %eax,%eax
    46bc:	0f 48 c2             	cmovs  %edx,%eax
    46bf:	c1 f8 04             	sar    $0x4,%eax
    46c2:	48 98                	cltq
    46c4:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    46cb:	ff 
    46cc:	48 39 85 60 8a ff ff 	cmp    %rax,-0x75a0(%rbp)
    46d3:	72 88                	jb     465d <compute_A+0x675>
    46d5:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    46dc:	00 
    46dd:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    46e4:	00 
    46e5:	48 c7 85 68 8a ff ff 	movq   $0x0,-0x7598(%rbp)
    46ec:	00 00 00 00 
    46f0:	e9 f0 00 00 00       	jmp    47e5 <compute_A+0x7fd>
    46f5:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    46fc:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4700:	48 8b 85 68 8a ff ff 	mov    -0x7598(%rbp),%rax
    4707:	48 01 d0             	add    %rdx,%rax
    470a:	0f b6 00             	movzbl (%rax),%eax
    470d:	0f b6 c0             	movzbl %al,%eax
    4710:	48 8b 95 68 8a ff ff 	mov    -0x7598(%rbp),%rdx
    4717:	48 8d 1c 95 00 00 00 	lea    0x0(,%rdx,4),%rbx
    471e:	00 
    471f:	be 01 00 00 00       	mov    $0x1,%esi
    4724:	89 c7                	mov    %eax,%edi
    4726:	e8 6c d4 ff ff       	call   1b97 <mul_f>
    472b:	88 44 1d d0          	mov    %al,-0x30(%rbp,%rbx,1)
    472f:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4736:	48 8b 50 18          	mov    0x18(%rax),%rdx
    473a:	48 8b 85 68 8a ff ff 	mov    -0x7598(%rbp),%rax
    4741:	48 01 d0             	add    %rdx,%rax
    4744:	0f b6 00             	movzbl (%rax),%eax
    4747:	0f b6 c0             	movzbl %al,%eax
    474a:	48 8b 95 68 8a ff ff 	mov    -0x7598(%rbp),%rdx
    4751:	48 c1 e2 02          	shl    $0x2,%rdx
    4755:	48 8d 5a 01          	lea    0x1(%rdx),%rbx
    4759:	be 02 00 00 00       	mov    $0x2,%esi
    475e:	89 c7                	mov    %eax,%edi
    4760:	e8 32 d4 ff ff       	call   1b97 <mul_f>
    4765:	88 44 1d d0          	mov    %al,-0x30(%rbp,%rbx,1)
    4769:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4770:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4774:	48 8b 85 68 8a ff ff 	mov    -0x7598(%rbp),%rax
    477b:	48 01 d0             	add    %rdx,%rax
    477e:	0f b6 00             	movzbl (%rax),%eax
    4781:	0f b6 c0             	movzbl %al,%eax
    4784:	48 8b 95 68 8a ff ff 	mov    -0x7598(%rbp),%rdx
    478b:	48 c1 e2 02          	shl    $0x2,%rdx
    478f:	48 8d 5a 02          	lea    0x2(%rdx),%rbx
    4793:	be 04 00 00 00       	mov    $0x4,%esi
    4798:	89 c7                	mov    %eax,%edi
    479a:	e8 f8 d3 ff ff       	call   1b97 <mul_f>
    479f:	88 44 1d d0          	mov    %al,-0x30(%rbp,%rbx,1)
    47a3:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    47aa:	48 8b 50 18          	mov    0x18(%rax),%rdx
    47ae:	48 8b 85 68 8a ff ff 	mov    -0x7598(%rbp),%rax
    47b5:	48 01 d0             	add    %rdx,%rax
    47b8:	0f b6 00             	movzbl (%rax),%eax
    47bb:	0f b6 c0             	movzbl %al,%eax
    47be:	48 8b 95 68 8a ff ff 	mov    -0x7598(%rbp),%rdx
    47c5:	48 c1 e2 02          	shl    $0x2,%rdx
    47c9:	48 8d 5a 03          	lea    0x3(%rdx),%rbx
    47cd:	be 08 00 00 00       	mov    $0x8,%esi
    47d2:	89 c7                	mov    %eax,%edi
    47d4:	e8 be d3 ff ff       	call   1b97 <mul_f>
    47d9:	88 44 1d d0          	mov    %al,-0x30(%rbp,%rbx,1)
    47dd:	48 83 85 68 8a ff ff 	addq   $0x1,-0x7598(%rbp)
    47e4:	01 
    47e5:	48 83 bd 68 8a ff ff 	cmpq   $0x3,-0x7598(%rbp)
    47ec:	03 
    47ed:	0f 86 02 ff ff ff    	jbe    46f5 <compute_A+0x70d>
    47f3:	48 b8 11 11 11 11 11 	movabs $0x1111111111111111,%rax
    47fa:	11 11 11 
    47fd:	48 89 85 90 8a ff ff 	mov    %rax,-0x7570(%rbp)
    4804:	48 c7 85 70 8a ff ff 	movq   $0x0,-0x7590(%rbp)
    480b:	00 00 00 00 
    480f:	e9 84 02 00 00       	jmp    4a98 <compute_A+0xab0>
    4814:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    481b:	8b 00                	mov    (%rax),%eax
    481d:	89 85 4c 8a ff ff    	mov    %eax,-0x75b4(%rbp)
    4823:	e9 2e 02 00 00       	jmp    4a56 <compute_A+0xa6e>
    4828:	8b 85 4c 8a ff ff    	mov    -0x75b4(%rbp),%eax
    482e:	8d 50 0f             	lea    0xf(%rax),%edx
    4831:	85 c0                	test   %eax,%eax
    4833:	0f 48 c2             	cmovs  %edx,%eax
    4836:	c1 f8 04             	sar    $0x4,%eax
    4839:	48 98                	cltq
    483b:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    4842:	ff 
    4843:	48 8b 95 70 8a ff ff 	mov    -0x7590(%rbp),%rdx
    484a:	48 8d 0c 10          	lea    (%rax,%rdx,1),%rcx
    484e:	8b 95 4c 8a ff ff    	mov    -0x75b4(%rbp),%edx
    4854:	89 d0                	mov    %edx,%eax
    4856:	c1 f8 1f             	sar    $0x1f,%eax
    4859:	c1 e8 1c             	shr    $0x1c,%eax
    485c:	01 c2                	add    %eax,%edx
    485e:	83 e2 0f             	and    $0xf,%edx
    4861:	29 c2                	sub    %eax,%edx
    4863:	89 d0                	mov    %edx,%eax
    4865:	48 98                	cltq
    4867:	48 01 c8             	add    %rcx,%rax
    486a:	48 89 85 98 8a ff ff 	mov    %rax,-0x7568(%rbp)
    4871:	48 8b 85 98 8a ff ff 	mov    -0x7568(%rbp),%rax
    4878:	48 8b 84 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rax
    487f:	ff 
    4880:	48 23 85 90 8a ff ff 	and    -0x7570(%rbp),%rax
    4887:	48 89 85 a0 8a ff ff 	mov    %rax,-0x7560(%rbp)
    488e:	48 8b 85 98 8a ff ff 	mov    -0x7568(%rbp),%rax
    4895:	48 8b 84 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rax
    489c:	ff 
    489d:	48 d1 e8             	shr    $1,%rax
    48a0:	48 23 85 90 8a ff ff 	and    -0x7570(%rbp),%rax
    48a7:	48 89 85 a8 8a ff ff 	mov    %rax,-0x7558(%rbp)
    48ae:	48 8b 85 98 8a ff ff 	mov    -0x7568(%rbp),%rax
    48b5:	48 8b 84 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rax
    48bc:	ff 
    48bd:	48 c1 e8 02          	shr    $0x2,%rax
    48c1:	48 23 85 90 8a ff ff 	and    -0x7570(%rbp),%rax
    48c8:	48 89 85 b0 8a ff ff 	mov    %rax,-0x7550(%rbp)
    48cf:	48 8b 85 98 8a ff ff 	mov    -0x7568(%rbp),%rax
    48d6:	48 8b 84 c5 d0 8a ff 	mov    -0x7530(%rbp,%rax,8),%rax
    48dd:	ff 
    48de:	48 c1 e8 03          	shr    $0x3,%rax
    48e2:	48 23 85 90 8a ff ff 	and    -0x7570(%rbp),%rax
    48e9:	48 89 85 b8 8a ff ff 	mov    %rax,-0x7548(%rbp)
    48f0:	48 c7 85 78 8a ff ff 	movq   $0x0,-0x7588(%rbp)
    48f7:	00 00 00 00 
    48fb:	e9 41 01 00 00       	jmp    4a41 <compute_A+0xa59>
    4900:	8b 85 4c 8a ff ff    	mov    -0x75b4(%rbp),%eax
    4906:	48 98                	cltq
    4908:	48 8b 95 78 8a ff ff 	mov    -0x7588(%rbp),%rdx
    490f:	48 01 c2             	add    %rax,%rdx
    4912:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4919:	8b 00                	mov    (%rax),%eax
    491b:	48 98                	cltq
    491d:	48 29 c2             	sub    %rax,%rdx
    4920:	48 89 d0             	mov    %rdx,%rax
    4923:	48 c1 e8 04          	shr    $0x4,%rax
    4927:	48 89 c2             	mov    %rax,%rdx
    492a:	48 0f af 95 80 8a ff 	imul   -0x7580(%rbp),%rdx
    4931:	ff 
    4932:	48 8b 8d 70 8a ff ff 	mov    -0x7590(%rbp),%rcx
    4939:	48 01 d1             	add    %rdx,%rcx
    493c:	8b 95 4c 8a ff ff    	mov    -0x75b4(%rbp),%edx
    4942:	48 63 d2             	movslq %edx,%rdx
    4945:	48 8b b5 78 8a ff ff 	mov    -0x7588(%rbp),%rsi
    494c:	48 01 d6             	add    %rdx,%rsi
    494f:	48 8b 95 18 8a ff ff 	mov    -0x75e8(%rbp),%rdx
    4956:	8b 12                	mov    (%rdx),%edx
    4958:	48 63 d2             	movslq %edx,%rdx
    495b:	48 29 d6             	sub    %rdx,%rsi
    495e:	48 89 f2             	mov    %rsi,%rdx
    4961:	83 e2 0f             	and    $0xf,%edx
    4964:	48 01 ca             	add    %rcx,%rdx
    4967:	48 8b b4 d5 d0 8a ff 	mov    -0x7530(%rbp,%rdx,8),%rsi
    496e:	ff 
    496f:	48 8b 95 78 8a ff ff 	mov    -0x7588(%rbp),%rdx
    4976:	48 c1 e2 02          	shl    $0x2,%rdx
    497a:	0f b6 54 15 d0       	movzbl -0x30(%rbp,%rdx,1),%edx
    497f:	0f b6 d2             	movzbl %dl,%edx
    4982:	48 89 d1             	mov    %rdx,%rcx
    4985:	48 0f af 8d a0 8a ff 	imul   -0x7560(%rbp),%rcx
    498c:	ff 
    498d:	48 8b 95 78 8a ff ff 	mov    -0x7588(%rbp),%rdx
    4994:	48 c1 e2 02          	shl    $0x2,%rdx
    4998:	48 83 c2 01          	add    $0x1,%rdx
    499c:	0f b6 54 15 d0       	movzbl -0x30(%rbp,%rdx,1),%edx
    49a1:	0f b6 d2             	movzbl %dl,%edx
    49a4:	48 0f af 95 a8 8a ff 	imul   -0x7558(%rbp),%rdx
    49ab:	ff 
    49ac:	48 31 d1             	xor    %rdx,%rcx
    49af:	48 8b 95 78 8a ff ff 	mov    -0x7588(%rbp),%rdx
    49b6:	48 c1 e2 02          	shl    $0x2,%rdx
    49ba:	48 83 c2 02          	add    $0x2,%rdx
    49be:	0f b6 54 15 d0       	movzbl -0x30(%rbp,%rdx,1),%edx
    49c3:	0f b6 d2             	movzbl %dl,%edx
    49c6:	48 0f af 95 b0 8a ff 	imul   -0x7550(%rbp),%rdx
    49cd:	ff 
    49ce:	48 31 d1             	xor    %rdx,%rcx
    49d1:	48 8b 95 78 8a ff ff 	mov    -0x7588(%rbp),%rdx
    49d8:	48 c1 e2 02          	shl    $0x2,%rdx
    49dc:	48 83 c2 03          	add    $0x3,%rdx
    49e0:	0f b6 54 15 d0       	movzbl -0x30(%rbp,%rdx,1),%edx
    49e5:	0f b6 d2             	movzbl %dl,%edx
    49e8:	48 0f af 95 b8 8a ff 	imul   -0x7548(%rbp),%rdx
    49ef:	ff 
    49f0:	48 31 ca             	xor    %rcx,%rdx
    49f3:	48 0f af 85 80 8a ff 	imul   -0x7580(%rbp),%rax
    49fa:	ff 
    49fb:	48 8b 8d 70 8a ff ff 	mov    -0x7590(%rbp),%rcx
    4a02:	48 01 c1             	add    %rax,%rcx
    4a05:	8b 85 4c 8a ff ff    	mov    -0x75b4(%rbp),%eax
    4a0b:	48 98                	cltq
    4a0d:	48 8b bd 78 8a ff ff 	mov    -0x7588(%rbp),%rdi
    4a14:	48 01 c7             	add    %rax,%rdi
    4a17:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4a1e:	8b 00                	mov    (%rax),%eax
    4a20:	48 98                	cltq
    4a22:	48 29 c7             	sub    %rax,%rdi
    4a25:	48 89 f8             	mov    %rdi,%rax
    4a28:	83 e0 0f             	and    $0xf,%eax
    4a2b:	48 01 c8             	add    %rcx,%rax
    4a2e:	48 31 f2             	xor    %rsi,%rdx
    4a31:	48 89 94 c5 d0 8a ff 	mov    %rdx,-0x7530(%rbp,%rax,8)
    4a38:	ff 
    4a39:	48 83 85 78 8a ff ff 	addq   $0x1,-0x7588(%rbp)
    4a40:	01 
    4a41:	48 83 bd 78 8a ff ff 	cmpq   $0x3,-0x7588(%rbp)
    4a48:	03 
    4a49:	0f 86 b1 fe ff ff    	jbe    4900 <compute_A+0x918>
    4a4f:	83 85 4c 8a ff ff 01 	addl   $0x1,-0x75b4(%rbp)
    4a56:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4a5d:	8b 10                	mov    (%rax),%edx
    4a5f:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4a66:	8b 40 0c             	mov    0xc(%rax),%eax
    4a69:	8d 48 01             	lea    0x1(%rax),%ecx
    4a6c:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4a73:	8b 40 0c             	mov    0xc(%rax),%eax
    4a76:	0f af c1             	imul   %ecx,%eax
    4a79:	89 c1                	mov    %eax,%ecx
    4a7b:	c1 e9 1f             	shr    $0x1f,%ecx
    4a7e:	01 c8                	add    %ecx,%eax
    4a80:	d1 f8                	sar    $1,%eax
    4a82:	01 d0                	add    %edx,%eax
    4a84:	39 85 4c 8a ff ff    	cmp    %eax,-0x75b4(%rbp)
    4a8a:	0f 8c 98 fd ff ff    	jl     4828 <compute_A+0x840>
    4a90:	48 83 85 70 8a ff ff 	addq   $0x10,-0x7590(%rbp)
    4a97:	10 
    4a98:	48 8b 85 70 8a ff ff 	mov    -0x7590(%rbp),%rax
    4a9f:	48 3b 85 80 8a ff ff 	cmp    -0x7580(%rbp),%rax
    4aa6:	0f 82 68 fd ff ff    	jb     4814 <compute_A+0x82c>
    4aac:	c7 85 50 8a ff ff 00 	movl   $0x0,-0x75b0(%rbp)
    4ab3:	00 00 00 
    4ab6:	e9 2a 01 00 00       	jmp    4be5 <compute_A+0xbfd>
    4abb:	c7 85 54 8a ff ff 00 	movl   $0x0,-0x75ac(%rbp)
    4ac2:	00 00 00 
    4ac5:	e9 f1 00 00 00       	jmp    4bbb <compute_A+0xbd3>
    4aca:	c7 85 58 8a ff ff 00 	movl   $0x0,-0x75a8(%rbp)
    4ad1:	00 00 00 
    4ad4:	e9 bc 00 00 00       	jmp    4b95 <compute_A+0xbad>
    4ad9:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4ae0:	8b 50 0c             	mov    0xc(%rax),%edx
    4ae3:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4aea:	8b 40 08             	mov    0x8(%rax),%eax
    4aed:	0f af c2             	imul   %edx,%eax
    4af0:	2b 85 54 8a ff ff    	sub    -0x75ac(%rbp),%eax
    4af6:	ba 10 00 00 00       	mov    $0x10,%edx
    4afb:	83 f8 10             	cmp    $0x10,%eax
    4afe:	0f 4f c2             	cmovg  %edx,%eax
    4b01:	48 8b 95 18 8a ff ff 	mov    -0x75e8(%rbp),%rdx
    4b08:	8b 4a 0c             	mov    0xc(%rdx),%ecx
    4b0b:	48 8b 95 18 8a ff ff 	mov    -0x75e8(%rbp),%rdx
    4b12:	8b 52 08             	mov    0x8(%rdx),%edx
    4b15:	0f af d1             	imul   %ecx,%edx
    4b18:	8d 4a 01             	lea    0x1(%rdx),%ecx
    4b1b:	8b b5 50 8a ff ff    	mov    -0x75b0(%rbp),%esi
    4b21:	8b 95 58 8a ff ff    	mov    -0x75a8(%rbp),%edx
    4b27:	01 f2                	add    %esi,%edx
    4b29:	0f af d1             	imul   %ecx,%edx
    4b2c:	48 63 ca             	movslq %edx,%rcx
    4b2f:	8b 95 54 8a ff ff    	mov    -0x75ac(%rbp),%edx
    4b35:	48 63 d2             	movslq %edx,%rdx
    4b38:	48 01 d1             	add    %rdx,%rcx
    4b3b:	48 8b 95 08 8a ff ff 	mov    -0x75f8(%rbp),%rdx
    4b42:	48 8d 34 11          	lea    (%rcx,%rdx,1),%rsi
    4b46:	8b 95 50 8a ff ff    	mov    -0x75b0(%rbp),%edx
    4b4c:	48 63 d2             	movslq %edx,%rdx
    4b4f:	48 0f af 95 80 8a ff 	imul   -0x7580(%rbp),%rdx
    4b56:	ff 
    4b57:	48 89 d1             	mov    %rdx,%rcx
    4b5a:	48 c1 e9 04          	shr    $0x4,%rcx
    4b5e:	8b 95 54 8a ff ff    	mov    -0x75ac(%rbp),%edx
    4b64:	48 63 d2             	movslq %edx,%rdx
    4b67:	48 01 d1             	add    %rdx,%rcx
    4b6a:	8b 95 58 8a ff ff    	mov    -0x75a8(%rbp),%edx
    4b70:	48 63 d2             	movslq %edx,%rdx
    4b73:	48 01 d1             	add    %rdx,%rcx
    4b76:	48 8d 95 d0 8a ff ff 	lea    -0x7530(%rbp),%rdx
    4b7d:	48 c1 e1 03          	shl    $0x3,%rcx
    4b81:	48 01 d1             	add    %rdx,%rcx
    4b84:	89 c2                	mov    %eax,%edx
    4b86:	48 89 cf             	mov    %rcx,%rdi
    4b89:	e8 1d e9 ff ff       	call   34ab <decode>
    4b8e:	83 85 58 8a ff ff 01 	addl   $0x1,-0x75a8(%rbp)
    4b95:	8b 95 58 8a ff ff    	mov    -0x75a8(%rbp),%edx
    4b9b:	8b 85 50 8a ff ff    	mov    -0x75b0(%rbp),%eax
    4ba1:	01 c2                	add    %eax,%edx
    4ba3:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4baa:	8b 00                	mov    (%rax),%eax
    4bac:	39 c2                	cmp    %eax,%edx
    4bae:	0f 8c 25 ff ff ff    	jl     4ad9 <compute_A+0xaf1>
    4bb4:	83 85 54 8a ff ff 10 	addl   $0x10,-0x75ac(%rbp)
    4bbb:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4bc2:	8b 50 0c             	mov    0xc(%rax),%edx
    4bc5:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4bcc:	8b 40 08             	mov    0x8(%rax),%eax
    4bcf:	0f af c2             	imul   %edx,%eax
    4bd2:	39 85 54 8a ff ff    	cmp    %eax,-0x75ac(%rbp)
    4bd8:	0f 8c ec fe ff ff    	jl     4aca <compute_A+0xae2>
    4bde:	83 85 50 8a ff ff 10 	addl   $0x10,-0x75b0(%rbp)
    4be5:	48 8b 85 18 8a ff ff 	mov    -0x75e8(%rbp),%rax
    4bec:	8b 00                	mov    (%rax),%eax
    4bee:	39 85 50 8a ff ff    	cmp    %eax,-0x75b0(%rbp)
    4bf4:	0f 8c c1 fe ff ff    	jl     4abb <compute_A+0xad3>
    4bfa:	90                   	nop
    4bfb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4bff:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    4c06:	00 00 
    4c08:	74 05                	je     4c0f <compute_A+0xc27>
    4c0a:	e8 c1 c5 ff ff       	call   11d0 <__stack_chk_fail@plt>
    4c0f:	48 81 c4 f8 75 00 00 	add    $0x75f8,%rsp
    4c16:	5b                   	pop    %rbx
    4c17:	5d                   	pop    %rbp
    4c18:	c3                   	ret

0000000000004c19 <unpack_m_vecs>:
    4c19:	f3 0f 1e fa          	endbr64
    4c1d:	55                   	push   %rbp
    4c1e:	48 89 e5             	mov    %rsp,%rbp
    4c21:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    4c25:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    4c29:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    4c2d:	89 55 8c             	mov    %edx,-0x74(%rbp)
    4c30:	89 4d 88             	mov    %ecx,-0x78(%rbp)
    4c33:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    4c3a:	00 00 
    4c3c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    4c40:	31 c0                	xor    %eax,%eax
    4c42:	8b 45 88             	mov    -0x78(%rbp),%eax
    4c45:	83 c0 0f             	add    $0xf,%eax
    4c48:	8d 50 0f             	lea    0xf(%rax),%edx
    4c4b:	85 c0                	test   %eax,%eax
    4c4d:	0f 48 c2             	cmovs  %edx,%eax
    4c50:	c1 f8 04             	sar    $0x4,%eax
    4c53:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    4c56:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    4c5a:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    4c5e:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    4c65:	00 
    4c66:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    4c6d:	00 
    4c6e:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    4c75:	00 
    4c76:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    4c7d:	00 
    4c7e:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4c85:	00 
    4c86:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    4c8d:	00 
    4c8e:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4c95:	00 
    4c96:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    4c9d:	00 
    4c9e:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    4ca5:	00 
    4ca6:	8b 45 8c             	mov    -0x74(%rbp),%eax
    4ca9:	83 e8 01             	sub    $0x1,%eax
    4cac:	89 45 a0             	mov    %eax,-0x60(%rbp)
    4caf:	eb 6f                	jmp    4d20 <unpack_m_vecs+0x107>
    4cb1:	8b 45 88             	mov    -0x78(%rbp),%eax
    4cb4:	89 c2                	mov    %eax,%edx
    4cb6:	c1 ea 1f             	shr    $0x1f,%edx
    4cb9:	01 d0                	add    %edx,%eax
    4cbb:	d1 f8                	sar    $1,%eax
    4cbd:	48 63 d0             	movslq %eax,%rdx
    4cc0:	8b 45 a0             	mov    -0x60(%rbp),%eax
    4cc3:	0f af 45 88          	imul   -0x78(%rbp),%eax
    4cc7:	89 c1                	mov    %eax,%ecx
    4cc9:	c1 e9 1f             	shr    $0x1f,%ecx
    4ccc:	01 c8                	add    %ecx,%eax
    4cce:	d1 f8                	sar    $1,%eax
    4cd0:	48 98                	cltq
    4cd2:	48 8b 4d 98          	mov    -0x68(%rbp),%rcx
    4cd6:	48 01 c1             	add    %rax,%rcx
    4cd9:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    4cdd:	48 89 ce             	mov    %rcx,%rsi
    4ce0:	48 89 c7             	mov    %rax,%rdi
    4ce3:	e8 48 c5 ff ff       	call   1230 <memcpy@plt>
    4ce8:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    4ceb:	48 98                	cltq
    4ced:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    4cf4:	00 
    4cf5:	8b 45 a0             	mov    -0x60(%rbp),%eax
    4cf8:	0f af 45 a4          	imul   -0x5c(%rbp),%eax
    4cfc:	48 98                	cltq
    4cfe:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    4d05:	00 
    4d06:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4d0a:	48 01 c1             	add    %rax,%rcx
    4d0d:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    4d11:	48 89 c6             	mov    %rax,%rsi
    4d14:	48 89 cf             	mov    %rcx,%rdi
    4d17:	e8 14 c5 ff ff       	call   1230 <memcpy@plt>
    4d1c:	83 6d a0 01          	subl   $0x1,-0x60(%rbp)
    4d20:	83 7d a0 00          	cmpl   $0x0,-0x60(%rbp)
    4d24:	79 8b                	jns    4cb1 <unpack_m_vecs+0x98>
    4d26:	90                   	nop
    4d27:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4d2b:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    4d32:	00 00 
    4d34:	74 05                	je     4d3b <unpack_m_vecs+0x122>
    4d36:	e8 95 c4 ff ff       	call   11d0 <__stack_chk_fail@plt>
    4d3b:	c9                   	leave
    4d3c:	c3                   	ret

0000000000004d3d <pack_m_vecs>:
    4d3d:	f3 0f 1e fa          	endbr64
    4d41:	55                   	push   %rbp
    4d42:	48 89 e5             	mov    %rsp,%rbp
    4d45:	48 83 ec 30          	sub    $0x30,%rsp
    4d49:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    4d4d:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    4d51:	89 55 dc             	mov    %edx,-0x24(%rbp)
    4d54:	89 4d d8             	mov    %ecx,-0x28(%rbp)
    4d57:	8b 45 d8             	mov    -0x28(%rbp),%eax
    4d5a:	83 c0 0f             	add    $0xf,%eax
    4d5d:	8d 50 0f             	lea    0xf(%rax),%edx
    4d60:	85 c0                	test   %eax,%eax
    4d62:	0f 48 c2             	cmovs  %edx,%eax
    4d65:	c1 f8 04             	sar    $0x4,%eax
    4d68:	89 45 f4             	mov    %eax,-0xc(%rbp)
    4d6b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4d6f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    4d73:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    4d7a:	eb 4f                	jmp    4dcb <pack_m_vecs+0x8e>
    4d7c:	8b 45 d8             	mov    -0x28(%rbp),%eax
    4d7f:	89 c2                	mov    %eax,%edx
    4d81:	c1 ea 1f             	shr    $0x1f,%edx
    4d84:	01 d0                	add    %edx,%eax
    4d86:	d1 f8                	sar    $1,%eax
    4d88:	48 63 d0             	movslq %eax,%rdx
    4d8b:	8b 45 f0             	mov    -0x10(%rbp),%eax
    4d8e:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    4d92:	48 98                	cltq
    4d94:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    4d9b:	00 
    4d9c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4da0:	48 01 c1             	add    %rax,%rcx
    4da3:	8b 45 f0             	mov    -0x10(%rbp),%eax
    4da6:	0f af 45 d8          	imul   -0x28(%rbp),%eax
    4daa:	89 c6                	mov    %eax,%esi
    4dac:	c1 ee 1f             	shr    $0x1f,%esi
    4daf:	01 f0                	add    %esi,%eax
    4db1:	d1 f8                	sar    $1,%eax
    4db3:	48 98                	cltq
    4db5:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    4db9:	48 01 f0             	add    %rsi,%rax
    4dbc:	48 89 ce             	mov    %rcx,%rsi
    4dbf:	48 89 c7             	mov    %rax,%rdi
    4dc2:	e8 89 c4 ff ff       	call   1250 <memmove@plt>
    4dc7:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    4dcb:	8b 45 f0             	mov    -0x10(%rbp),%eax
    4dce:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    4dd1:	7c a9                	jl     4d7c <pack_m_vecs+0x3f>
    4dd3:	90                   	nop
    4dd4:	90                   	nop
    4dd5:	c9                   	leave
    4dd6:	c3                   	ret

0000000000004dd7 <expand_P1_P2>:
    4dd7:	f3 0f 1e fa          	endbr64
    4ddb:	55                   	push   %rbp
    4ddc:	48 89 e5             	mov    %rsp,%rbp
    4ddf:	48 83 ec 20          	sub    $0x20,%rsp
    4de3:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    4de7:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    4deb:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    4def:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4df3:	8b 40 58             	mov    0x58(%rax),%eax
    4df6:	48 63 d0             	movslq %eax,%rdx
    4df9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4dfd:	8b 48 34             	mov    0x34(%rax),%ecx
    4e00:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e04:	8b 40 38             	mov    0x38(%rax),%eax
    4e07:	01 c8                	add    %ecx,%eax
    4e09:	48 98                	cltq
    4e0b:	48 8b 75 e8          	mov    -0x18(%rbp),%rsi
    4e0f:	48 8b 7d f0          	mov    -0x10(%rbp),%rdi
    4e13:	48 89 d1             	mov    %rdx,%rcx
    4e16:	48 89 f2             	mov    %rsi,%rdx
    4e19:	48 89 c6             	mov    %rax,%rsi
    4e1c:	e8 bd 64 00 00       	call   b2de <AES_128_CTR>
    4e21:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e25:	8b 08                	mov    (%rax),%ecx
    4e27:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e2b:	8b 50 04             	mov    0x4(%rax),%edx
    4e2e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e32:	8b 40 08             	mov    0x8(%rax),%eax
    4e35:	29 c2                	sub    %eax,%edx
    4e37:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e3b:	8b 70 04             	mov    0x4(%rax),%esi
    4e3e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e42:	8b 40 08             	mov    0x8(%rax),%eax
    4e45:	29 c6                	sub    %eax,%esi
    4e47:	89 f0                	mov    %esi,%eax
    4e49:	83 c0 01             	add    $0x1,%eax
    4e4c:	0f af c2             	imul   %edx,%eax
    4e4f:	89 c2                	mov    %eax,%edx
    4e51:	c1 ea 1f             	shr    $0x1f,%edx
    4e54:	01 d0                	add    %edx,%eax
    4e56:	d1 f8                	sar    $1,%eax
    4e58:	89 c2                	mov    %eax,%edx
    4e5a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e5e:	8b 40 5c             	mov    0x5c(%rax),%eax
    4e61:	0f af d0             	imul   %eax,%edx
    4e64:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e68:	8b 70 04             	mov    0x4(%rax),%esi
    4e6b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e6f:	8b 40 08             	mov    0x8(%rax),%eax
    4e72:	29 c6                	sub    %eax,%esi
    4e74:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4e78:	8b 40 08             	mov    0x8(%rax),%eax
    4e7b:	0f af c6             	imul   %esi,%eax
    4e7e:	48 8b 75 f8          	mov    -0x8(%rbp),%rsi
    4e82:	8b 76 5c             	mov    0x5c(%rsi),%esi
    4e85:	0f af c6             	imul   %esi,%eax
    4e88:	01 d0                	add    %edx,%eax
    4e8a:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    4e8e:	8b 7a 5c             	mov    0x5c(%rdx),%edi
    4e91:	99                   	cltd
    4e92:	f7 ff                	idiv   %edi
    4e94:	89 c2                	mov    %eax,%edx
    4e96:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    4e9a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4e9e:	48 89 c7             	mov    %rax,%rdi
    4ea1:	e8 73 fd ff ff       	call   4c19 <unpack_m_vecs>
    4ea6:	90                   	nop
    4ea7:	c9                   	leave
    4ea8:	c3                   	ret

0000000000004ea9 <eval_public_map>:
    4ea9:	f3 0f 1e fa          	endbr64
    4ead:	55                   	push   %rbp
    4eae:	48 89 e5             	mov    %rsp,%rbp
    4eb1:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    4eb8:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    4ebd:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    4ec4:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    4ec9:	48 81 ec 50 09 00 00 	sub    $0x950,%rsp
    4ed0:	48 89 bd d8 d6 ff ff 	mov    %rdi,-0x2928(%rbp)
    4ed7:	48 89 b5 d0 d6 ff ff 	mov    %rsi,-0x2930(%rbp)
    4ede:	48 89 95 c8 d6 ff ff 	mov    %rdx,-0x2938(%rbp)
    4ee5:	48 89 8d c0 d6 ff ff 	mov    %rcx,-0x2940(%rbp)
    4eec:	4c 89 85 b8 d6 ff ff 	mov    %r8,-0x2948(%rbp)
    4ef3:	4c 89 8d b0 d6 ff ff 	mov    %r9,-0x2950(%rbp)
    4efa:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    4f01:	00 00 
    4f03:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    4f07:	31 c0                	xor    %eax,%eax
    4f09:	48 8d 85 e0 d6 ff ff 	lea    -0x2920(%rbp),%rax
    4f10:	ba 80 28 00 00       	mov    $0x2880,%edx
    4f15:	be 00 00 00 00       	mov    $0x0,%esi
    4f1a:	48 89 c7             	mov    %rax,%rdi
    4f1d:	e8 de c2 ff ff       	call   1200 <memset@plt>
    4f22:	48 8d bd e0 d6 ff ff 	lea    -0x2920(%rbp),%rdi
    4f29:	4c 8b 85 d0 d6 ff ff 	mov    -0x2930(%rbp),%r8
    4f30:	48 8b 8d b8 d6 ff ff 	mov    -0x2948(%rbp),%rcx
    4f37:	48 8b 95 c0 d6 ff ff 	mov    -0x2940(%rbp),%rdx
    4f3e:	48 8b b5 c8 d6 ff ff 	mov    -0x2938(%rbp),%rsi
    4f45:	48 8b 85 d8 d6 ff ff 	mov    -0x2928(%rbp),%rax
    4f4c:	49 89 f9             	mov    %rdi,%r9
    4f4f:	48 89 c7             	mov    %rax,%rdi
    4f52:	e8 10 e4 ff ff       	call   3367 <m_calculate_PS_SPS>
    4f57:	48 c7 85 60 ff ff ff 	movq   $0x0,-0xa0(%rbp)
    4f5e:	00 00 00 00 
    4f62:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
    4f69:	00 00 00 00 
    4f6d:	48 c7 85 70 ff ff ff 	movq   $0x0,-0x90(%rbp)
    4f74:	00 00 00 00 
    4f78:	48 c7 85 78 ff ff ff 	movq   $0x0,-0x88(%rbp)
    4f7f:	00 00 00 00 
    4f83:	48 c7 45 80 00 00 00 	movq   $0x0,-0x80(%rbp)
    4f8a:	00 
    4f8b:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
    4f92:	00 
    4f93:	48 c7 45 90 00 00 00 	movq   $0x0,-0x70(%rbp)
    4f9a:	00 
    4f9b:	48 c7 45 98 00 00 00 	movq   $0x0,-0x68(%rbp)
    4fa2:	00 
    4fa3:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
    4faa:	00 
    4fab:	48 c7 45 a8 00 00 00 	movq   $0x0,-0x58(%rbp)
    4fb2:	00 
    4fb3:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    4fba:	00 
    4fbb:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    4fc2:	00 
    4fc3:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    4fca:	00 
    4fcb:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    4fd2:	00 
    4fd3:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4fda:	00 
    4fdb:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    4fe2:	00 
    4fe3:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4fea:	00 
    4feb:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    4ff2:	66 c7 45 ec 00 00    	movw   $0x0,-0x14(%rbp)
    4ff8:	48 8b 8d b0 d6 ff ff 	mov    -0x2950(%rbp),%rcx
    4fff:	48 8d 95 60 ff ff ff 	lea    -0xa0(%rbp),%rdx
    5006:	48 8d 85 e0 d6 ff ff 	lea    -0x2920(%rbp),%rax
    500d:	48 8b bd d8 d6 ff ff 	mov    -0x2928(%rbp),%rdi
    5014:	48 89 c6             	mov    %rax,%rsi
    5017:	e8 d1 e5 ff ff       	call   35ed <compute_rhs>
    501c:	90                   	nop
    501d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5021:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    5028:	00 00 
    502a:	74 05                	je     5031 <eval_public_map+0x188>
    502c:	e8 9f c1 ff ff       	call   11d0 <__stack_chk_fail@plt>
    5031:	c9                   	leave
    5032:	c3                   	ret

0000000000005033 <mayo_keypair>:
    5033:	f3 0f 1e fa          	endbr64
    5037:	55                   	push   %rbp
    5038:	48 89 e5             	mov    %rsp,%rbp
    503b:	48 83 ec 30          	sub    $0x30,%rsp
    503f:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    5043:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    5047:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    504b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    5052:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    5056:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    505a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    505e:	48 89 ce             	mov    %rcx,%rsi
    5061:	48 89 c7             	mov    %rax,%rdi
    5064:	e8 1b 1a 00 00       	call   6a84 <mayo_keypair_compact>
    5069:	89 45 fc             	mov    %eax,-0x4(%rbp)
    506c:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    5070:	90                   	nop
    5071:	f3 0f 1e fa          	endbr64
    5075:	8b 45 fc             	mov    -0x4(%rbp),%eax
    5078:	c9                   	leave
    5079:	c3                   	ret

000000000000507a <mayo_expand_sk>:
    507a:	f3 0f 1e fa          	endbr64
    507e:	55                   	push   %rbp
    507f:	48 89 e5             	mov    %rsp,%rbp
    5082:	48 81 ec e0 03 00 00 	sub    $0x3e0,%rsp
    5089:	48 89 bd 38 fc ff ff 	mov    %rdi,-0x3c8(%rbp)
    5090:	48 89 b5 30 fc ff ff 	mov    %rsi,-0x3d0(%rbp)
    5097:	48 89 95 28 fc ff ff 	mov    %rdx,-0x3d8(%rbp)
    509e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    50a5:	00 00 
    50a7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    50ab:	31 c0                	xor    %eax,%eax
    50ad:	c7 85 40 fc ff ff 00 	movl   $0x0,-0x3c0(%rbp)
    50b4:	00 00 00 
    50b7:	48 8b 85 28 fc ff ff 	mov    -0x3d8(%rbp),%rax
    50be:	48 89 85 58 fc ff ff 	mov    %rax,-0x3a8(%rbp)
    50c5:	48 8b 85 28 fc ff ff 	mov    -0x3d8(%rbp),%rax
    50cc:	48 05 78 ce 0d 00    	add    $0xdce78,%rax
    50d2:	48 89 85 60 fc ff ff 	mov    %rax,-0x3a0(%rbp)
    50d9:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    50e0:	8b 40 08             	mov    0x8(%rax),%eax
    50e3:	89 85 44 fc ff ff    	mov    %eax,-0x3bc(%rbp)
    50e9:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    50f0:	8b 50 04             	mov    0x4(%rax),%edx
    50f3:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    50fa:	8b 40 08             	mov    0x8(%rax),%eax
    50fd:	29 c2                	sub    %eax,%edx
    50ff:	89 d0                	mov    %edx,%eax
    5101:	89 85 48 fc ff ff    	mov    %eax,-0x3b8(%rbp)
    5107:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    510e:	8b 40 24             	mov    0x24(%rax),%eax
    5111:	89 85 4c fc ff ff    	mov    %eax,-0x3b4(%rbp)
    5117:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    511e:	8b 40 58             	mov    0x58(%rax),%eax
    5121:	89 85 50 fc ff ff    	mov    %eax,-0x3b0(%rbp)
    5127:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    512e:	8b 40 50             	mov    0x50(%rax),%eax
    5131:	89 85 54 fc ff ff    	mov    %eax,-0x3ac(%rbp)
    5137:	48 8b 85 30 fc ff ff 	mov    -0x3d0(%rbp),%rax
    513e:	48 89 85 68 fc ff ff 	mov    %rax,-0x398(%rbp)
    5145:	48 8d 85 90 fc ff ff 	lea    -0x370(%rbp),%rax
    514c:	48 89 85 70 fc ff ff 	mov    %rax,-0x390(%rbp)
    5153:	8b 85 54 fc ff ff    	mov    -0x3ac(%rbp),%eax
    5159:	48 63 d0             	movslq %eax,%rdx
    515c:	8b 8d 50 fc ff ff    	mov    -0x3b0(%rbp),%ecx
    5162:	8b 85 4c fc ff ff    	mov    -0x3b4(%rbp),%eax
    5168:	01 c8                	add    %ecx,%eax
    516a:	48 63 f0             	movslq %eax,%rsi
    516d:	48 8b bd 68 fc ff ff 	mov    -0x398(%rbp),%rdi
    5174:	48 8d 85 90 fc ff ff 	lea    -0x370(%rbp),%rax
    517b:	48 89 d1             	mov    %rdx,%rcx
    517e:	48 89 fa             	mov    %rdi,%rdx
    5181:	48 89 c7             	mov    %rax,%rdi
    5184:	e8 fa 83 00 00       	call   d583 <shake256>
    5189:	8b 85 48 fc ff ff    	mov    -0x3b8(%rbp),%eax
    518f:	0f af 85 44 fc ff ff 	imul   -0x3bc(%rbp),%eax
    5196:	8b 95 50 fc ff ff    	mov    -0x3b0(%rbp),%edx
    519c:	48 63 d2             	movslq %edx,%rdx
    519f:	48 8d 8d 90 fc ff ff 	lea    -0x370(%rbp),%rcx
    51a6:	48 01 d1             	add    %rdx,%rcx
    51a9:	48 8b b5 60 fc ff ff 	mov    -0x3a0(%rbp),%rsi
    51b0:	89 c2                	mov    %eax,%edx
    51b2:	48 89 cf             	mov    %rcx,%rdi
    51b5:	e8 f1 e2 ff ff       	call   34ab <decode>
    51ba:	48 8b 95 70 fc ff ff 	mov    -0x390(%rbp),%rdx
    51c1:	48 8b 8d 58 fc ff ff 	mov    -0x3a8(%rbp),%rcx
    51c8:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    51cf:	48 89 ce             	mov    %rcx,%rsi
    51d2:	48 89 c7             	mov    %rax,%rdi
    51d5:	e8 fd fb ff ff       	call   4dd7 <expand_P1_P2>
    51da:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    51e1:	8b 50 04             	mov    0x4(%rax),%edx
    51e4:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    51eb:	8b 40 08             	mov    0x8(%rax),%eax
    51ee:	29 c2                	sub    %eax,%edx
    51f0:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    51f7:	8b 48 04             	mov    0x4(%rax),%ecx
    51fa:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    5201:	8b 40 08             	mov    0x8(%rax),%eax
    5204:	29 c1                	sub    %eax,%ecx
    5206:	89 c8                	mov    %ecx,%eax
    5208:	83 c0 01             	add    $0x1,%eax
    520b:	0f af c2             	imul   %edx,%eax
    520e:	89 c2                	mov    %eax,%edx
    5210:	c1 ea 1f             	shr    $0x1f,%edx
    5213:	01 d0                	add    %edx,%eax
    5215:	d1 f8                	sar    $1,%eax
    5217:	89 c2                	mov    %eax,%edx
    5219:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    5220:	8b 40 5c             	mov    0x5c(%rax),%eax
    5223:	0f af c2             	imul   %edx,%eax
    5226:	48 98                	cltq
    5228:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    522f:	00 
    5230:	48 8b 85 58 fc ff ff 	mov    -0x3a8(%rbp),%rax
    5237:	48 01 d0             	add    %rdx,%rax
    523a:	48 89 85 78 fc ff ff 	mov    %rax,-0x388(%rbp)
    5241:	48 8b 85 58 fc ff ff 	mov    -0x3a8(%rbp),%rax
    5248:	48 89 85 80 fc ff ff 	mov    %rax,-0x380(%rbp)
    524f:	48 8b 85 78 fc ff ff 	mov    -0x388(%rbp),%rax
    5256:	48 89 85 88 fc ff ff 	mov    %rax,-0x378(%rbp)
    525d:	48 8b 8d 88 fc ff ff 	mov    -0x378(%rbp),%rcx
    5264:	48 8b 95 60 fc ff ff 	mov    -0x3a0(%rbp),%rdx
    526b:	48 8b b5 80 fc ff ff 	mov    -0x380(%rbp),%rsi
    5272:	48 8b 85 38 fc ff ff 	mov    -0x3c8(%rbp),%rax
    5279:	48 89 c7             	mov    %rax,%rdi
    527c:	e8 73 dd ff ff       	call   2ff4 <P1P1t_times_O>
    5281:	48 8d 85 90 fc ff ff 	lea    -0x370(%rbp),%rax
    5288:	be 64 03 00 00       	mov    $0x364,%esi
    528d:	48 89 c7             	mov    %rax,%rdi
    5290:	e8 5c 8c 00 00       	call   def1 <mayo_secure_clear>
    5295:	8b 85 40 fc ff ff    	mov    -0x3c0(%rbp),%eax
    529b:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
    529f:	64 48 33 3c 25 28 00 	xor    %fs:0x28,%rdi
    52a6:	00 00 
    52a8:	74 05                	je     52af <mayo_expand_sk+0x235>
    52aa:	e8 21 bf ff ff       	call   11d0 <__stack_chk_fail@plt>
    52af:	c9                   	leave
    52b0:	c3                   	ret

00000000000052b1 <mayo_sign_signature>:
    52b1:	f3 0f 1e fa          	endbr64
    52b5:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    52ba:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
    52be:	41 ff 72 f8          	push   -0x8(%r10)
    52c2:	55                   	push   %rbp
    52c3:	48 89 e5             	mov    %rsp,%rbp
    52c6:	41 57                	push   %r15
    52c8:	41 56                	push   %r14
    52ca:	41 55                	push   %r13
    52cc:	41 54                	push   %r12
    52ce:	41 52                	push   %r10
    52d0:	53                   	push   %rbx
    52d1:	4c 8d 9c 24 00 60 f1 	lea    -0xea000(%rsp),%r11
    52d8:	ff 
    52d9:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    52e0:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    52e5:	4c 39 dc             	cmp    %r11,%rsp
    52e8:	75 ef                	jne    52d9 <mayo_sign_signature+0x28>
    52ea:	48 81 ec c0 01 00 00 	sub    $0x1c0,%rsp
    52f1:	48 89 fb             	mov    %rdi,%rbx
    52f4:	48 89 b5 28 5e f1 ff 	mov    %rsi,-0xea1d8(%rbp)
    52fb:	48 89 95 20 5e f1 ff 	mov    %rdx,-0xea1e0(%rbp)
    5302:	48 89 8d a0 5e f1 ff 	mov    %rcx,-0xea160(%rbp)
    5309:	4d 89 c4             	mov    %r8,%r12
    530c:	4d 89 cd             	mov    %r9,%r13
    530f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    5316:	00 00 
    5318:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    531c:	31 c0                	xor    %eax,%eax
    531e:	48 c7 85 70 8c ff ff 	movq   $0x0,-0x7390(%rbp)
    5325:	00 00 00 00 
    5329:	48 c7 85 78 8c ff ff 	movq   $0x0,-0x7388(%rbp)
    5330:	00 00 00 00 
    5334:	48 8d bd 80 8c ff ff 	lea    -0x7380(%rbp),%rdi
    533b:	ba 40 73 00 00       	mov    $0x7340,%edx
    5340:	be 00 00 00 00       	mov    $0x0,%esi
    5345:	e8 b6 be ff ff       	call   1200 <memset@plt>
    534a:	48 c7 85 d0 72 ff ff 	movq   $0x0,-0x8d30(%rbp)
    5351:	00 00 00 00 
    5355:	48 c7 85 d8 72 ff ff 	movq   $0x0,-0x8d28(%rbp)
    535c:	00 00 00 00 
    5360:	48 c7 85 e0 72 ff ff 	movq   $0x0,-0x8d20(%rbp)
    5367:	00 00 00 00 
    536b:	48 c7 85 e8 72 ff ff 	movq   $0x0,-0x8d18(%rbp)
    5372:	00 00 00 00 
    5376:	48 c7 85 f0 72 ff ff 	movq   $0x0,-0x8d10(%rbp)
    537d:	00 00 00 00 
    5381:	48 c7 85 f8 72 ff ff 	movq   $0x0,-0x8d08(%rbp)
    5388:	00 00 00 00 
    538c:	48 c7 85 00 73 ff ff 	movq   $0x0,-0x8d00(%rbp)
    5393:	00 00 00 00 
    5397:	48 c7 85 08 73 ff ff 	movq   $0x0,-0x8cf8(%rbp)
    539e:	00 00 00 00 
    53a2:	48 c7 85 10 73 ff ff 	movq   $0x0,-0x8cf0(%rbp)
    53a9:	00 00 00 00 
    53ad:	48 c7 85 18 73 ff ff 	movq   $0x0,-0x8ce8(%rbp)
    53b4:	00 00 00 00 
    53b8:	48 c7 85 20 73 ff ff 	movq   $0x0,-0x8ce0(%rbp)
    53bf:	00 00 00 00 
    53c3:	48 c7 85 28 73 ff ff 	movq   $0x0,-0x8cd8(%rbp)
    53ca:	00 00 00 00 
    53ce:	48 c7 85 30 73 ff ff 	movq   $0x0,-0x8cd0(%rbp)
    53d5:	00 00 00 00 
    53d9:	48 c7 85 38 73 ff ff 	movq   $0x0,-0x8cc8(%rbp)
    53e0:	00 00 00 00 
    53e4:	48 c7 85 40 73 ff ff 	movq   $0x0,-0x8cc0(%rbp)
    53eb:	00 00 00 00 
    53ef:	48 c7 85 48 73 ff ff 	movq   $0x0,-0x8cb8(%rbp)
    53f6:	00 00 00 00 
    53fa:	48 c7 85 50 73 ff ff 	movq   $0x0,-0x8cb0(%rbp)
    5401:	00 00 00 00 
    5405:	48 c7 85 58 73 ff ff 	movq   $0x0,-0x8ca8(%rbp)
    540c:	00 00 00 00 
    5410:	48 c7 85 60 73 ff ff 	movq   $0x0,-0x8ca0(%rbp)
    5417:	00 00 00 00 
    541b:	48 c7 85 68 73 ff ff 	movq   $0x0,-0x8c98(%rbp)
    5422:	00 00 00 00 
    5426:	48 c7 85 70 73 ff ff 	movq   $0x0,-0x8c90(%rbp)
    542d:	00 00 00 00 
    5431:	48 c7 85 78 73 ff ff 	movq   $0x0,-0x8c88(%rbp)
    5438:	00 00 00 00 
    543c:	48 c7 85 80 73 ff ff 	movq   $0x0,-0x8c80(%rbp)
    5443:	00 00 00 00 
    5447:	48 c7 85 88 73 ff ff 	movq   $0x0,-0x8c78(%rbp)
    544e:	00 00 00 00 
    5452:	48 c7 85 90 73 ff ff 	movq   $0x0,-0x8c70(%rbp)
    5459:	00 00 00 00 
    545d:	c7 85 98 73 ff ff 00 	movl   $0x0,-0x8c68(%rbp)
    5464:	00 00 00 
    5467:	c6 85 9c 73 ff ff 00 	movb   $0x0,-0x8c64(%rbp)
    546e:	48 89 d8             	mov    %rbx,%rax
    5471:	44 8b 33             	mov    (%rbx),%r14d
    5474:	8b 73 04             	mov    0x4(%rbx),%esi
    5477:	89 b5 78 5e f1 ff    	mov    %esi,-0xea188(%rbp)
    547d:	8b 73 08             	mov    0x8(%rbx),%esi
    5480:	89 b5 7c 5e f1 ff    	mov    %esi,-0xea184(%rbp)
    5486:	8b 5b 0c             	mov    0xc(%rbx),%ebx
    5489:	89 9d ac 5e f1 ff    	mov    %ebx,-0xea154(%rbp)
    548f:	8b 78 20             	mov    0x20(%rax),%edi
    5492:	89 bd 90 5e f1 ff    	mov    %edi,-0xea170(%rbp)
    5498:	8b 78 28             	mov    0x28(%rax),%edi
    549b:	89 bd 70 5e f1 ff    	mov    %edi,-0xea190(%rbp)
    54a1:	44 8b 58 2c          	mov    0x2c(%rax),%r11d
    54a5:	44 89 9d 60 5e f1 ff 	mov    %r11d,-0xea1a0(%rbp)
    54ac:	44 8b 58 48          	mov    0x48(%rax),%r11d
    54b0:	44 89 9d 34 5e f1 ff 	mov    %r11d,-0xea1cc(%rbp)
    54b7:	44 8b 78 54          	mov    0x54(%rax),%r15d
    54bb:	44 8b 58 50          	mov    0x50(%rax),%r11d
    54bf:	44 89 9d 98 5e f1 ff 	mov    %r11d,-0xea168(%rbp)
    54c6:	8b 58 4c             	mov    0x4c(%rax),%ebx
    54c9:	48 8d 95 10 98 f1 ff 	lea    -0xe67f0(%rbp),%rdx
    54d0:	4c 89 ad 58 5e f1 ff 	mov    %r13,-0xea1a8(%rbp)
    54d7:	4c 89 ee             	mov    %r13,%rsi
    54da:	48 89 85 88 5e f1 ff 	mov    %rax,-0xea178(%rbp)
    54e1:	48 89 c7             	mov    %rax,%rdi
    54e4:	e8 91 fb ff ff       	call   507a <mayo_expand_sk>
    54e9:	89 85 a8 5e f1 ff    	mov    %eax,-0xea158(%rbp)
    54ef:	85 c0                	test   %eax,%eax
    54f1:	0f 84 ca 00 00 00    	je     55c1 <mayo_sign_signature+0x310>
    54f7:	48 8d bd a0 73 ff ff 	lea    -0x8c60(%rbp),%rdi
    54fe:	be 9c 03 00 00       	mov    $0x39c,%esi
    5503:	e8 e9 89 00 00       	call   def1 <mayo_secure_clear>
    5508:	48 8d bd 40 77 ff ff 	lea    -0x88c0(%rbp),%rdi
    550f:	be a8 06 00 00       	mov    $0x6a8,%esi
    5514:	e8 d8 89 00 00       	call   def1 <mayo_secure_clear>
    5519:	48 8d bd 70 8c ff ff 	lea    -0x7390(%rbp),%rdi
    5520:	be 50 73 00 00       	mov    $0x7350,%esi
    5525:	e8 c7 89 00 00       	call   def1 <mayo_secure_clear>
    552a:	48 8d bd d0 72 ff ff 	lea    -0x8d30(%rbp),%rdi
    5531:	be cd 00 00 00       	mov    $0xcd,%esi
    5536:	e8 b6 89 00 00       	call   def1 <mayo_secure_clear>
    553b:	48 8d 9d 10 98 f1 ff 	lea    -0xe67f0(%rbp),%rbx
    5542:	48 8d bd 88 66 ff ff 	lea    -0x9978(%rbp),%rdi
    5549:	be 6e 09 00 00       	mov    $0x96e,%esi
    554e:	e8 9e 89 00 00       	call   def1 <mayo_secure_clear>
    5553:	be e8 d7 0d 00       	mov    $0xdd7e8,%esi
    5558:	48 89 df             	mov    %rbx,%rdi
    555b:	e8 91 89 00 00       	call   def1 <mayo_secure_clear>
    5560:	48 8d bd a0 71 ff ff 	lea    -0x8e60(%rbp),%rdi
    5567:	be 8e 00 00 00       	mov    $0x8e,%esi
    556c:	e8 80 89 00 00       	call   def1 <mayo_secure_clear>
    5571:	48 8d bd 30 72 ff ff 	lea    -0x8dd0(%rbp),%rdi
    5578:	be 91 00 00 00       	mov    $0x91,%esi
    557d:	e8 6f 89 00 00       	call   def1 <mayo_secure_clear>
    5582:	48 8d bd b0 5e f1 ff 	lea    -0xea150(%rbp),%rdi
    5589:	be 60 39 00 00       	mov    $0x3960,%esi
    558e:	e8 5e 89 00 00       	call   def1 <mayo_secure_clear>
    5593:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    5597:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    559e:	00 00 
    55a0:	0f 85 32 13 00 00    	jne    68d8 <mayo_sign_signature+0x1627>
    55a6:	8b 85 a8 5e f1 ff    	mov    -0xea158(%rbp),%eax
    55ac:	48 8d 65 d0          	lea    -0x30(%rbp),%rsp
    55b0:	5b                   	pop    %rbx
    55b1:	41 5a                	pop    %r10
    55b3:	41 5c                	pop    %r12
    55b5:	41 5d                	pop    %r13
    55b7:	41 5e                	pop    %r14
    55b9:	41 5f                	pop    %r15
    55bb:	5d                   	pop    %rbp
    55bc:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    55c0:	c3                   	ret
    55c1:	4d 63 df             	movslq %r15d,%r11
    55c4:	4c 8d ad 30 72 ff ff 	lea    -0x8dd0(%rbp),%r13
    55cb:	4c 89 e1             	mov    %r12,%rcx
    55ce:	48 8b 95 a0 5e f1 ff 	mov    -0xea160(%rbp),%rdx
    55d5:	4c 89 9d 48 5e f1 ff 	mov    %r11,-0xea1b8(%rbp)
    55dc:	4c 89 de             	mov    %r11,%rsi
    55df:	4c 89 ef             	mov    %r13,%rdi
    55e2:	e8 9c 7f 00 00       	call   d583 <shake256>
    55e7:	48 8b 85 88 5e f1 ff 	mov    -0xea178(%rbp),%rax
    55ee:	44 8b 60 04          	mov    0x4(%rax),%r12d
    55f2:	44 8b 50 08          	mov    0x8(%rax),%r10d
    55f6:	44 89 95 50 5e f1 ff 	mov    %r10d,-0xea1b0(%rbp)
    55fd:	44 8b 48 5c          	mov    0x5c(%rax),%r9d
    5601:	44 89 8d 40 5e f1 ff 	mov    %r9d,-0xea1c0(%rbp)
    5608:	48 8d bd b0 5e f1 ff 	lea    -0xea150(%rbp),%rdi
    560f:	ba 60 39 00 00       	mov    $0x3960,%edx
    5614:	be 00 00 00 00       	mov    $0x0,%esi
    5619:	e8 e2 bb ff ff       	call   1200 <memset@plt>
    561e:	4c 63 d3             	movslq %ebx,%r10
    5621:	4c 03 ad 48 5e f1 ff 	add    -0xea1b8(%rbp),%r13
    5628:	4c 89 95 38 5e f1 ff 	mov    %r10,-0xea1c8(%rbp)
    562f:	4c 89 d6             	mov    %r10,%rsi
    5632:	4c 89 ef             	mov    %r13,%rdi
    5635:	e8 6d 32 00 00       	call   88a7 <randombytes>
    563a:	89 85 a8 5e f1 ff    	mov    %eax,-0xea158(%rbp)
    5640:	85 c0                	test   %eax,%eax
    5642:	74 0f                	je     5653 <mayo_sign_signature+0x3a2>
    5644:	c7 85 a8 5e f1 ff 01 	movl   $0x1,-0xea158(%rbp)
    564b:	00 00 00 
    564e:	e9 a4 fe ff ff       	jmp    54f7 <mayo_sign_signature+0x246>
    5653:	8b 8d 78 5e f1 ff    	mov    -0xea188(%rbp),%ecx
    5659:	8b 85 7c 5e f1 ff    	mov    -0xea184(%rbp),%eax
    565f:	29 c1                	sub    %eax,%ecx
    5661:	89 8d a0 5e f1 ff    	mov    %ecx,-0xea160(%rbp)
    5667:	0f af 85 ac 5e f1 ff 	imul   -0xea154(%rbp),%eax
    566e:	89 85 68 5e f1 ff    	mov    %eax,-0xea198(%rbp)
    5674:	8d 48 01             	lea    0x1(%rax),%ecx
    5677:	89 8d 80 5e f1 ff    	mov    %ecx,-0xea180(%rbp)
    567d:	44 2b a5 50 5e f1 ff 	sub    -0xea1b0(%rbp),%r12d
    5684:	41 8d 44 24 01       	lea    0x1(%r12),%eax
    5689:	44 0f af e0          	imul   %eax,%r12d
    568d:	44 89 e1             	mov    %r12d,%ecx
    5690:	c1 e9 1f             	shr    $0x1f,%ecx
    5693:	89 c8                	mov    %ecx,%eax
    5695:	44 01 e0             	add    %r12d,%eax
    5698:	d1 f8                	sar    $1,%eax
    569a:	0f af 85 40 5e f1 ff 	imul   -0xea1c0(%rbp),%eax
    56a1:	48 98                	cltq
    56a3:	48 8d 8c c5 10 98 f1 	lea    -0xe67f0(%rbp,%rax,8),%rcx
    56aa:	ff 
    56ab:	48 89 8d 50 5e f1 ff 	mov    %rcx,-0xea1b0(%rbp)
    56b2:	4c 63 8d 98 5e f1 ff 	movslq -0xea168(%rbp),%r9
    56b9:	48 8b 85 48 5e f1 ff 	mov    -0xea1b8(%rbp),%rax
    56c0:	48 03 85 38 5e f1 ff 	add    -0xea1c8(%rbp),%rax
    56c7:	4c 8d a5 30 72 ff ff 	lea    -0x8dd0(%rbp),%r12
    56ce:	48 89 85 40 5e f1 ff 	mov    %rax,-0xea1c0(%rbp)
    56d5:	49 8d 3c 04          	lea    (%r12,%rax,1),%rdi
    56d9:	4c 89 8d 48 5e f1 ff 	mov    %r9,-0xea1b8(%rbp)
    56e0:	4c 89 ca             	mov    %r9,%rdx
    56e3:	48 8b b5 58 5e f1 ff 	mov    -0xea1a8(%rbp),%rsi
    56ea:	e8 41 bb ff ff       	call   1230 <memcpy@plt>
    56ef:	44 01 fb             	add    %r15d,%ebx
    56f2:	44 8b bd 98 5e f1 ff 	mov    -0xea168(%rbp),%r15d
    56f9:	89 9d 98 5e f1 ff    	mov    %ebx,-0xea168(%rbp)
    56ff:	41 01 df             	add    %ebx,%r15d
    5702:	49 63 cf             	movslq %r15d,%rcx
    5705:	48 8d 9d 00 70 ff ff 	lea    -0x9000(%rbp),%rbx
    570c:	4c 89 e2             	mov    %r12,%rdx
    570f:	48 8b b5 38 5e f1 ff 	mov    -0xea1c8(%rbp),%rsi
    5716:	48 89 df             	mov    %rbx,%rdi
    5719:	e8 65 7e 00 00       	call   d583 <shake256>
    571e:	48 8b 95 38 5e f1 ff 	mov    -0xea1c8(%rbp),%rdx
    5725:	48 89 de             	mov    %rbx,%rsi
    5728:	4c 89 ef             	mov    %r13,%rdi
    572b:	e8 00 bb ff ff       	call   1230 <memcpy@plt>
    5730:	48 8b 9d 48 5e f1 ff 	mov    -0xea1b8(%rbp),%rbx
    5737:	48 03 9d 40 5e f1 ff 	add    -0xea1c0(%rbp),%rbx
    573e:	4d 8d 14 1c          	lea    (%r12,%rbx,1),%r10
    5742:	4c 89 95 48 5e f1 ff 	mov    %r10,-0xea1b8(%rbp)
    5749:	48 63 8d 98 5e f1 ff 	movslq -0xea168(%rbp),%rcx
    5750:	48 63 b5 90 5e f1 ff 	movslq -0xea170(%rbp),%rsi
    5757:	48 8d 9d 30 70 ff ff 	lea    -0x8fd0(%rbp),%rbx
    575e:	4c 89 e2             	mov    %r12,%rdx
    5761:	48 89 df             	mov    %rbx,%rdi
    5764:	e8 1a 7e 00 00       	call   d583 <shake256>
    5769:	48 8d b5 80 70 ff ff 	lea    -0x8f80(%rbp),%rsi
    5770:	44 89 f2             	mov    %r14d,%edx
    5773:	48 89 df             	mov    %rbx,%rdi
    5776:	e8 30 dd ff ff       	call   34ab <decode>
    577b:	8b 95 ac 5e f1 ff    	mov    -0xea154(%rbp),%edx
    5781:	0f af 95 70 5e f1 ff 	imul   -0xea190(%rbp),%edx
    5788:	8b 85 60 5e f1 ff    	mov    -0xea1a0(%rbp),%eax
    578e:	01 d0                	add    %edx,%eax
    5790:	48 98                	cltq
    5792:	48 89 85 60 5e f1 ff 	mov    %rax,-0xea1a0(%rbp)
    5799:	48 63 d2             	movslq %edx,%rdx
    579c:	48 8d 84 15 a0 73 ff 	lea    -0x8c60(%rbp,%rdx,1),%rax
    57a3:	ff 
    57a4:	48 89 85 58 5e f1 ff 	mov    %rax,-0xea1a8(%rbp)
    57ab:	44 8b 85 a8 5e f1 ff 	mov    -0xea158(%rbp),%r8d
    57b2:	44 89 85 90 5e f1 ff 	mov    %r8d,-0xea170(%rbp)
    57b9:	41 83 c7 01          	add    $0x1,%r15d
    57bd:	49 63 c7             	movslq %r15d,%rax
    57c0:	48 89 85 40 5e f1 ff 	mov    %rax,-0xea1c0(%rbp)
    57c7:	e9 ab 00 00 00       	jmp    5877 <mayo_sign_signature+0x5c6>
    57cc:	48 8d 9d d0 72 ff ff 	lea    -0x8d30(%rbp),%rbx
    57d3:	8b 95 68 5e f1 ff    	mov    -0xea198(%rbp),%edx
    57d9:	48 89 de             	mov    %rbx,%rsi
    57dc:	48 8b bd 58 5e f1 ff 	mov    -0xea1a8(%rbp),%rdi
    57e3:	e8 c3 dc ff ff       	call   34ab <decode>
    57e8:	48 8d 95 10 71 ff ff 	lea    -0x8ef0(%rbp),%rdx
    57ef:	48 8d b5 70 8c ff ff 	lea    -0x7390(%rbp),%rsi
    57f6:	48 83 ec 08          	sub    $0x8,%rsp
    57fa:	8b 85 80 5e f1 ff    	mov    -0xea180(%rbp),%eax
    5800:	50                   	push   %rax
    5801:	41 56                	push   %r14
    5803:	8b 85 7c 5e f1 ff    	mov    -0xea184(%rbp),%eax
    5809:	50                   	push   %rax
    580a:	44 8b 8d ac 5e f1 ff 	mov    -0xea154(%rbp),%r9d
    5811:	4c 8d 85 f0 7d ff ff 	lea    -0x8210(%rbp),%r8
    5818:	48 89 d9             	mov    %rbx,%rcx
    581b:	48 8b bd 88 5e f1 ff 	mov    -0xea178(%rbp),%rdi
    5822:	e8 8b 27 00 00       	call   7fb2 <sample_solution>
    5827:	48 83 c4 20          	add    $0x20,%rsp
    582b:	85 c0                	test   %eax,%eax
    582d:	0f 85 5e 01 00 00    	jne    5991 <mayo_sign_signature+0x6e0>
    5833:	48 8d bd b0 5e f1 ff 	lea    -0xea150(%rbp),%rdi
    583a:	ba 60 39 00 00       	mov    $0x3960,%edx
    583f:	be 00 00 00 00       	mov    $0x0,%esi
    5844:	e8 b7 b9 ff ff       	call   1200 <memset@plt>
    5849:	48 8d bd 70 8c ff ff 	lea    -0x7390(%rbp),%rdi
    5850:	ba 50 73 00 00       	mov    $0x7350,%edx
    5855:	be 00 00 00 00       	mov    $0x0,%esi
    585a:	e8 a1 b9 ff ff       	call   1200 <memset@plt>
    585f:	83 85 90 5e f1 ff 01 	addl   $0x1,-0xea170(%rbp)
    5866:	8b 85 90 5e f1 ff    	mov    -0xea170(%rbp),%eax
    586c:	3d 00 01 00 00       	cmp    $0x100,%eax
    5871:	0f 84 1a 01 00 00    	je     5991 <mayo_sign_signature+0x6e0>
    5877:	48 8b 85 48 5e f1 ff 	mov    -0xea1b8(%rbp),%rax
    587e:	0f b6 8d 90 5e f1 ff 	movzbl -0xea170(%rbp),%ecx
    5885:	88 08                	mov    %cl,(%rax)
    5887:	48 8d 95 30 72 ff ff 	lea    -0x8dd0(%rbp),%rdx
    588e:	48 8d bd a0 73 ff ff 	lea    -0x8c60(%rbp),%rdi
    5895:	48 8b 8d 40 5e f1 ff 	mov    -0xea1c0(%rbp),%rcx
    589c:	48 8b b5 60 5e f1 ff 	mov    -0xea1a0(%rbp),%rsi
    58a3:	e8 db 7c 00 00       	call   d583 <shake256>
    58a8:	83 bd ac 5e f1 ff 00 	cmpl   $0x0,-0xea154(%rbp)
    58af:	7e 4f                	jle    5900 <mayo_sign_signature+0x64f>
    58b1:	4c 63 bd 70 5e f1 ff 	movslq -0xea190(%rbp),%r15
    58b8:	4c 8d ad a0 73 ff ff 	lea    -0x8c60(%rbp),%r13
    58bf:	48 63 85 a0 5e f1 ff 	movslq -0xea160(%rbp),%rax
    58c6:	48 89 85 98 5e f1 ff 	mov    %rax,-0xea168(%rbp)
    58cd:	4c 8d a5 40 77 ff ff 	lea    -0x88c0(%rbp),%r12
    58d4:	8b 9d a8 5e f1 ff    	mov    -0xea158(%rbp),%ebx
    58da:	8b 95 a0 5e f1 ff    	mov    -0xea160(%rbp),%edx
    58e0:	4c 89 e6             	mov    %r12,%rsi
    58e3:	4c 89 ef             	mov    %r13,%rdi
    58e6:	e8 c0 db ff ff       	call   34ab <decode>
    58eb:	83 c3 01             	add    $0x1,%ebx
    58ee:	4d 01 fd             	add    %r15,%r13
    58f1:	4c 03 a5 98 5e f1 ff 	add    -0xea168(%rbp),%r12
    58f8:	39 9d ac 5e f1 ff    	cmp    %ebx,-0xea154(%rbp)
    58fe:	75 da                	jne    58da <mayo_sign_signature+0x629>
    5900:	48 8d 9d 70 8c ff ff 	lea    -0x7390(%rbp),%rbx
    5907:	4c 8d a5 b0 5e f1 ff 	lea    -0xea150(%rbp),%r12
    590e:	48 8d 8d 10 98 f1 ff 	lea    -0xe67f0(%rbp),%rcx
    5915:	48 8d b5 40 77 ff ff 	lea    -0x88c0(%rbp),%rsi
    591c:	49 89 d9             	mov    %rbx,%r9
    591f:	4d 89 e0             	mov    %r12,%r8
    5922:	48 8b 95 50 5e f1 ff 	mov    -0xea1b0(%rbp),%rdx
    5929:	4c 8b bd 88 5e f1 ff 	mov    -0xea178(%rbp),%r15
    5930:	4c 89 ff             	mov    %r15,%rdi
    5933:	e8 34 d8 ff ff       	call   316c <compute_M_and_VPV>
    5938:	48 8d 8d 10 71 ff ff 	lea    -0x8ef0(%rbp),%rcx
    593f:	48 8d 95 80 70 ff ff 	lea    -0x8f80(%rbp),%rdx
    5946:	48 89 de             	mov    %rbx,%rsi
    5949:	4c 89 ff             	mov    %r15,%rdi
    594c:	e8 9c dc ff ff       	call   35ed <compute_rhs>
    5951:	48 89 da             	mov    %rbx,%rdx
    5954:	4c 89 e6             	mov    %r12,%rsi
    5957:	4c 89 ff             	mov    %r15,%rdi
    595a:	e8 89 e6 ff ff       	call   3fe8 <compute_A>
    595f:	45 85 f6             	test   %r14d,%r14d
    5962:	0f 8e 64 fe ff ff    	jle    57cc <mayo_sign_signature+0x51b>
    5968:	48 63 8d 80 5e f1 ff 	movslq -0xea180(%rbp),%rcx
    596f:	48 8d 94 0d 70 8c ff 	lea    -0x7390(%rbp,%rcx,1),%rdx
    5976:	ff 
    5977:	8b 85 a8 5e f1 ff    	mov    -0xea158(%rbp),%eax
    597d:	83 c0 01             	add    $0x1,%eax
    5980:	c6 42 ff 00          	movb   $0x0,-0x1(%rdx)
    5984:	48 01 ca             	add    %rcx,%rdx
    5987:	44 39 f0             	cmp    %r14d,%eax
    598a:	75 f1                	jne    597d <mayo_sign_signature+0x6cc>
    598c:	e9 3b fe ff ff       	jmp    57cc <mayo_sign_signature+0x51b>
    5991:	83 bd ac 5e f1 ff 00 	cmpl   $0x0,-0xea154(%rbp)
    5998:	7f 55                	jg     59ef <mayo_sign_signature+0x73e>
    599a:	8b 95 78 5e f1 ff    	mov    -0xea188(%rbp),%edx
    59a0:	0f af 95 ac 5e f1 ff 	imul   -0xea154(%rbp),%edx
    59a7:	48 8d bd 30 85 ff ff 	lea    -0x7ad0(%rbp),%rdi
    59ae:	4c 8b b5 28 5e f1 ff 	mov    -0xea1d8(%rbp),%r14
    59b5:	4c 89 f6             	mov    %r14,%rsi
    59b8:	e8 9b db ff ff       	call   3558 <encode>
    59bd:	48 63 9d 34 5e f1 ff 	movslq -0xea1cc(%rbp),%rbx
    59c4:	48 89 df             	mov    %rbx,%rdi
    59c7:	48 8b 95 38 5e f1 ff 	mov    -0xea1c8(%rbp),%rdx
    59ce:	48 29 d7             	sub    %rdx,%rdi
    59d1:	4c 01 f7             	add    %r14,%rdi
    59d4:	48 8d b5 00 70 ff ff 	lea    -0x9000(%rbp),%rsi
    59db:	e8 50 b8 ff ff       	call   1230 <memcpy@plt>
    59e0:	48 8b 85 20 5e f1 ff 	mov    -0xea1e0(%rbp),%rax
    59e7:	48 89 18             	mov    %rbx,(%rax)
    59ea:	e9 08 fb ff ff       	jmp    54f7 <mayo_sign_signature+0x246>
    59ef:	48 63 85 7c 5e f1 ff 	movslq -0xea184(%rbp),%rax
    59f6:	48 89 85 60 5e f1 ff 	mov    %rax,-0xea1a0(%rbp)
    59fd:	48 8d 85 f0 7d ff ff 	lea    -0x8210(%rbp),%rax
    5a04:	48 89 85 90 5e f1 ff 	mov    %rax,-0xea170(%rbp)
    5a0b:	48 63 85 a0 5e f1 ff 	movslq -0xea160(%rbp),%rax
    5a12:	48 89 85 68 5e f1 ff 	mov    %rax,-0xea198(%rbp)
    5a19:	4c 8d b5 40 77 ff ff 	lea    -0x88c0(%rbp),%r14
    5a20:	48 63 85 78 5e f1 ff 	movslq -0xea188(%rbp),%rax
    5a27:	48 89 85 70 5e f1 ff 	mov    %rax,-0xea190(%rbp)
    5a2e:	4c 8d ad 30 85 ff ff 	lea    -0x7ad0(%rbp),%r13
    5a35:	8b 85 a8 5e f1 ff    	mov    -0xea158(%rbp),%eax
    5a3b:	89 85 98 5e f1 ff    	mov    %eax,-0xea168(%rbp)
    5a41:	4c 8d bd a0 71 ff ff 	lea    -0x8e60(%rbp),%r15
    5a48:	48 8b b5 90 5e f1 ff 	mov    -0xea170(%rbp),%rsi
    5a4f:	48 89 b5 80 5e f1 ff 	mov    %rsi,-0xea180(%rbp)
    5a56:	48 8d bd 88 66 ff ff 	lea    -0x9978(%rbp),%rdi
    5a5d:	41 b9 01 00 00 00    	mov    $0x1,%r9d
    5a63:	8b 9d a0 5e f1 ff    	mov    -0xea160(%rbp),%ebx
    5a69:	41 89 d8             	mov    %ebx,%r8d
    5a6c:	8b 8d 7c 5e f1 ff    	mov    -0xea184(%rbp),%ecx
    5a72:	4c 89 fa             	mov    %r15,%rdx
    5a75:	e8 3b c2 ff ff       	call   1cb5 <mat_mul>
    5a7a:	89 d8                	mov    %ebx,%eax
    5a7c:	85 db                	test   %ebx,%ebx
    5a7e:	0f 8e 03 0e 00 00    	jle    6887 <mayo_sign_signature+0x15d6>
    5a84:	bb 00 00 00 00       	mov    $0x0,%ebx
    5a89:	8d 48 ff             	lea    -0x1(%rax),%ecx
    5a8c:	48 89 8d 88 5e f1 ff 	mov    %rcx,-0xea178(%rbp)
    5a93:	83 e0 3f             	and    $0x3f,%eax
    5a96:	0f 84 51 08 00 00    	je     62ed <mayo_sign_signature+0x103c>
    5a9c:	48 83 f8 01          	cmp    $0x1,%rax
    5aa0:	0f 84 1f 08 00 00    	je     62c5 <mayo_sign_signature+0x1014>
    5aa6:	48 83 f8 02          	cmp    $0x2,%rax
    5aaa:	0f 84 fd 07 00 00    	je     62ad <mayo_sign_signature+0xffc>
    5ab0:	48 83 f8 03          	cmp    $0x3,%rax
    5ab4:	0f 84 db 07 00 00    	je     6295 <mayo_sign_signature+0xfe4>
    5aba:	48 83 f8 04          	cmp    $0x4,%rax
    5abe:	0f 84 b9 07 00 00    	je     627d <mayo_sign_signature+0xfcc>
    5ac4:	48 83 f8 05          	cmp    $0x5,%rax
    5ac8:	0f 84 97 07 00 00    	je     6265 <mayo_sign_signature+0xfb4>
    5ace:	48 83 f8 06          	cmp    $0x6,%rax
    5ad2:	0f 84 75 07 00 00    	je     624d <mayo_sign_signature+0xf9c>
    5ad8:	48 83 f8 07          	cmp    $0x7,%rax
    5adc:	0f 84 53 07 00 00    	je     6235 <mayo_sign_signature+0xf84>
    5ae2:	48 83 f8 08          	cmp    $0x8,%rax
    5ae6:	0f 84 31 07 00 00    	je     621d <mayo_sign_signature+0xf6c>
    5aec:	48 83 f8 09          	cmp    $0x9,%rax
    5af0:	0f 84 0f 07 00 00    	je     6205 <mayo_sign_signature+0xf54>
    5af6:	48 83 f8 0a          	cmp    $0xa,%rax
    5afa:	0f 84 ed 06 00 00    	je     61ed <mayo_sign_signature+0xf3c>
    5b00:	48 83 f8 0b          	cmp    $0xb,%rax
    5b04:	0f 84 cb 06 00 00    	je     61d5 <mayo_sign_signature+0xf24>
    5b0a:	48 83 f8 0c          	cmp    $0xc,%rax
    5b0e:	0f 84 a9 06 00 00    	je     61bd <mayo_sign_signature+0xf0c>
    5b14:	48 83 f8 0d          	cmp    $0xd,%rax
    5b18:	0f 84 87 06 00 00    	je     61a5 <mayo_sign_signature+0xef4>
    5b1e:	48 83 f8 0e          	cmp    $0xe,%rax
    5b22:	0f 84 65 06 00 00    	je     618d <mayo_sign_signature+0xedc>
    5b28:	48 83 f8 0f          	cmp    $0xf,%rax
    5b2c:	0f 84 43 06 00 00    	je     6175 <mayo_sign_signature+0xec4>
    5b32:	48 83 f8 10          	cmp    $0x10,%rax
    5b36:	0f 84 21 06 00 00    	je     615d <mayo_sign_signature+0xeac>
    5b3c:	48 83 f8 11          	cmp    $0x11,%rax
    5b40:	0f 84 ff 05 00 00    	je     6145 <mayo_sign_signature+0xe94>
    5b46:	48 83 f8 12          	cmp    $0x12,%rax
    5b4a:	0f 84 dd 05 00 00    	je     612d <mayo_sign_signature+0xe7c>
    5b50:	48 83 f8 13          	cmp    $0x13,%rax
    5b54:	0f 84 bb 05 00 00    	je     6115 <mayo_sign_signature+0xe64>
    5b5a:	48 83 f8 14          	cmp    $0x14,%rax
    5b5e:	0f 84 99 05 00 00    	je     60fd <mayo_sign_signature+0xe4c>
    5b64:	48 83 f8 15          	cmp    $0x15,%rax
    5b68:	0f 84 77 05 00 00    	je     60e5 <mayo_sign_signature+0xe34>
    5b6e:	48 83 f8 16          	cmp    $0x16,%rax
    5b72:	0f 84 55 05 00 00    	je     60cd <mayo_sign_signature+0xe1c>
    5b78:	48 83 f8 17          	cmp    $0x17,%rax
    5b7c:	0f 84 33 05 00 00    	je     60b5 <mayo_sign_signature+0xe04>
    5b82:	48 83 f8 18          	cmp    $0x18,%rax
    5b86:	0f 84 11 05 00 00    	je     609d <mayo_sign_signature+0xdec>
    5b8c:	48 83 f8 19          	cmp    $0x19,%rax
    5b90:	0f 84 ef 04 00 00    	je     6085 <mayo_sign_signature+0xdd4>
    5b96:	48 83 f8 1a          	cmp    $0x1a,%rax
    5b9a:	0f 84 cd 04 00 00    	je     606d <mayo_sign_signature+0xdbc>
    5ba0:	48 83 f8 1b          	cmp    $0x1b,%rax
    5ba4:	0f 84 ab 04 00 00    	je     6055 <mayo_sign_signature+0xda4>
    5baa:	48 83 f8 1c          	cmp    $0x1c,%rax
    5bae:	0f 84 89 04 00 00    	je     603d <mayo_sign_signature+0xd8c>
    5bb4:	48 83 f8 1d          	cmp    $0x1d,%rax
    5bb8:	0f 84 67 04 00 00    	je     6025 <mayo_sign_signature+0xd74>
    5bbe:	48 83 f8 1e          	cmp    $0x1e,%rax
    5bc2:	0f 84 45 04 00 00    	je     600d <mayo_sign_signature+0xd5c>
    5bc8:	48 83 f8 1f          	cmp    $0x1f,%rax
    5bcc:	0f 84 23 04 00 00    	je     5ff5 <mayo_sign_signature+0xd44>
    5bd2:	48 83 f8 20          	cmp    $0x20,%rax
    5bd6:	0f 84 01 04 00 00    	je     5fdd <mayo_sign_signature+0xd2c>
    5bdc:	48 83 f8 21          	cmp    $0x21,%rax
    5be0:	0f 84 df 03 00 00    	je     5fc5 <mayo_sign_signature+0xd14>
    5be6:	48 83 f8 22          	cmp    $0x22,%rax
    5bea:	0f 84 bd 03 00 00    	je     5fad <mayo_sign_signature+0xcfc>
    5bf0:	48 83 f8 23          	cmp    $0x23,%rax
    5bf4:	0f 84 9b 03 00 00    	je     5f95 <mayo_sign_signature+0xce4>
    5bfa:	48 83 f8 24          	cmp    $0x24,%rax
    5bfe:	0f 84 79 03 00 00    	je     5f7d <mayo_sign_signature+0xccc>
    5c04:	48 83 f8 25          	cmp    $0x25,%rax
    5c08:	0f 84 57 03 00 00    	je     5f65 <mayo_sign_signature+0xcb4>
    5c0e:	48 83 f8 26          	cmp    $0x26,%rax
    5c12:	0f 84 35 03 00 00    	je     5f4d <mayo_sign_signature+0xc9c>
    5c18:	48 83 f8 27          	cmp    $0x27,%rax
    5c1c:	0f 84 13 03 00 00    	je     5f35 <mayo_sign_signature+0xc84>
    5c22:	48 83 f8 28          	cmp    $0x28,%rax
    5c26:	0f 84 f1 02 00 00    	je     5f1d <mayo_sign_signature+0xc6c>
    5c2c:	48 83 f8 29          	cmp    $0x29,%rax
    5c30:	0f 84 cf 02 00 00    	je     5f05 <mayo_sign_signature+0xc54>
    5c36:	48 83 f8 2a          	cmp    $0x2a,%rax
    5c3a:	0f 84 ad 02 00 00    	je     5eed <mayo_sign_signature+0xc3c>
    5c40:	48 83 f8 2b          	cmp    $0x2b,%rax
    5c44:	0f 84 8b 02 00 00    	je     5ed5 <mayo_sign_signature+0xc24>
    5c4a:	48 83 f8 2c          	cmp    $0x2c,%rax
    5c4e:	0f 84 69 02 00 00    	je     5ebd <mayo_sign_signature+0xc0c>
    5c54:	48 83 f8 2d          	cmp    $0x2d,%rax
    5c58:	0f 84 47 02 00 00    	je     5ea5 <mayo_sign_signature+0xbf4>
    5c5e:	48 83 f8 2e          	cmp    $0x2e,%rax
    5c62:	0f 84 25 02 00 00    	je     5e8d <mayo_sign_signature+0xbdc>
    5c68:	48 83 f8 2f          	cmp    $0x2f,%rax
    5c6c:	0f 84 03 02 00 00    	je     5e75 <mayo_sign_signature+0xbc4>
    5c72:	48 83 f8 30          	cmp    $0x30,%rax
    5c76:	0f 84 e1 01 00 00    	je     5e5d <mayo_sign_signature+0xbac>
    5c7c:	48 83 f8 31          	cmp    $0x31,%rax
    5c80:	0f 84 bf 01 00 00    	je     5e45 <mayo_sign_signature+0xb94>
    5c86:	48 83 f8 32          	cmp    $0x32,%rax
    5c8a:	0f 84 9d 01 00 00    	je     5e2d <mayo_sign_signature+0xb7c>
    5c90:	48 83 f8 33          	cmp    $0x33,%rax
    5c94:	0f 84 7b 01 00 00    	je     5e15 <mayo_sign_signature+0xb64>
    5c9a:	48 83 f8 34          	cmp    $0x34,%rax
    5c9e:	0f 84 59 01 00 00    	je     5dfd <mayo_sign_signature+0xb4c>
    5ca4:	48 83 f8 35          	cmp    $0x35,%rax
    5ca8:	0f 84 37 01 00 00    	je     5de5 <mayo_sign_signature+0xb34>
    5cae:	48 83 f8 36          	cmp    $0x36,%rax
    5cb2:	0f 84 15 01 00 00    	je     5dcd <mayo_sign_signature+0xb1c>
    5cb8:	48 83 f8 37          	cmp    $0x37,%rax
    5cbc:	0f 84 f3 00 00 00    	je     5db5 <mayo_sign_signature+0xb04>
    5cc2:	48 83 f8 38          	cmp    $0x38,%rax
    5cc6:	0f 84 d1 00 00 00    	je     5d9d <mayo_sign_signature+0xaec>
    5ccc:	48 83 f8 39          	cmp    $0x39,%rax
    5cd0:	0f 84 af 00 00 00    	je     5d85 <mayo_sign_signature+0xad4>
    5cd6:	48 83 f8 3a          	cmp    $0x3a,%rax
    5cda:	0f 84 8d 00 00 00    	je     5d6d <mayo_sign_signature+0xabc>
    5ce0:	48 83 f8 3b          	cmp    $0x3b,%rax
    5ce4:	74 6f                	je     5d55 <mayo_sign_signature+0xaa4>
    5ce6:	48 83 f8 3c          	cmp    $0x3c,%rax
    5cea:	74 51                	je     5d3d <mayo_sign_signature+0xa8c>
    5cec:	48 83 f8 3d          	cmp    $0x3d,%rax
    5cf0:	74 33                	je     5d25 <mayo_sign_signature+0xa74>
    5cf2:	48 83 f8 3e          	cmp    $0x3e,%rax
    5cf6:	74 15                	je     5d0d <mayo_sign_signature+0xa5c>
    5cf8:	41 0f b6 37          	movzbl (%r15),%esi
    5cfc:	41 0f b6 3e          	movzbl (%r14),%edi
    5d00:	e8 1d bf ff ff       	call   1c22 <add_f>
    5d05:	41 88 45 00          	mov    %al,0x0(%r13)
    5d09:	48 83 c3 01          	add    $0x1,%rbx
    5d0d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5d12:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5d17:	e8 06 bf ff ff       	call   1c22 <add_f>
    5d1c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5d21:	48 83 c3 01          	add    $0x1,%rbx
    5d25:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5d2a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5d2f:	e8 ee be ff ff       	call   1c22 <add_f>
    5d34:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5d39:	48 83 c3 01          	add    $0x1,%rbx
    5d3d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5d42:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5d47:	e8 d6 be ff ff       	call   1c22 <add_f>
    5d4c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5d51:	48 83 c3 01          	add    $0x1,%rbx
    5d55:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5d5a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5d5f:	e8 be be ff ff       	call   1c22 <add_f>
    5d64:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5d69:	48 83 c3 01          	add    $0x1,%rbx
    5d6d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5d72:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5d77:	e8 a6 be ff ff       	call   1c22 <add_f>
    5d7c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5d81:	48 83 c3 01          	add    $0x1,%rbx
    5d85:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5d8a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5d8f:	e8 8e be ff ff       	call   1c22 <add_f>
    5d94:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5d99:	48 83 c3 01          	add    $0x1,%rbx
    5d9d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5da2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5da7:	e8 76 be ff ff       	call   1c22 <add_f>
    5dac:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5db1:	48 83 c3 01          	add    $0x1,%rbx
    5db5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5dba:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5dbf:	e8 5e be ff ff       	call   1c22 <add_f>
    5dc4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5dc9:	48 83 c3 01          	add    $0x1,%rbx
    5dcd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5dd2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5dd7:	e8 46 be ff ff       	call   1c22 <add_f>
    5ddc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5de1:	48 83 c3 01          	add    $0x1,%rbx
    5de5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5dea:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5def:	e8 2e be ff ff       	call   1c22 <add_f>
    5df4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5df9:	48 83 c3 01          	add    $0x1,%rbx
    5dfd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e02:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e07:	e8 16 be ff ff       	call   1c22 <add_f>
    5e0c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5e11:	48 83 c3 01          	add    $0x1,%rbx
    5e15:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e1a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e1f:	e8 fe bd ff ff       	call   1c22 <add_f>
    5e24:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5e29:	48 83 c3 01          	add    $0x1,%rbx
    5e2d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e32:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e37:	e8 e6 bd ff ff       	call   1c22 <add_f>
    5e3c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5e41:	48 83 c3 01          	add    $0x1,%rbx
    5e45:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e4a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e4f:	e8 ce bd ff ff       	call   1c22 <add_f>
    5e54:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5e59:	48 83 c3 01          	add    $0x1,%rbx
    5e5d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e62:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e67:	e8 b6 bd ff ff       	call   1c22 <add_f>
    5e6c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5e71:	48 83 c3 01          	add    $0x1,%rbx
    5e75:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e7a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e7f:	e8 9e bd ff ff       	call   1c22 <add_f>
    5e84:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5e89:	48 83 c3 01          	add    $0x1,%rbx
    5e8d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5e92:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5e97:	e8 86 bd ff ff       	call   1c22 <add_f>
    5e9c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5ea1:	48 83 c3 01          	add    $0x1,%rbx
    5ea5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5eaa:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5eaf:	e8 6e bd ff ff       	call   1c22 <add_f>
    5eb4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5eb9:	48 83 c3 01          	add    $0x1,%rbx
    5ebd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5ec2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5ec7:	e8 56 bd ff ff       	call   1c22 <add_f>
    5ecc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5ed1:	48 83 c3 01          	add    $0x1,%rbx
    5ed5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5eda:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5edf:	e8 3e bd ff ff       	call   1c22 <add_f>
    5ee4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5ee9:	48 83 c3 01          	add    $0x1,%rbx
    5eed:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5ef2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5ef7:	e8 26 bd ff ff       	call   1c22 <add_f>
    5efc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f01:	48 83 c3 01          	add    $0x1,%rbx
    5f05:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f0a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f0f:	e8 0e bd ff ff       	call   1c22 <add_f>
    5f14:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f19:	48 83 c3 01          	add    $0x1,%rbx
    5f1d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f22:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f27:	e8 f6 bc ff ff       	call   1c22 <add_f>
    5f2c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f31:	48 83 c3 01          	add    $0x1,%rbx
    5f35:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f3a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f3f:	e8 de bc ff ff       	call   1c22 <add_f>
    5f44:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f49:	48 83 c3 01          	add    $0x1,%rbx
    5f4d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f52:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f57:	e8 c6 bc ff ff       	call   1c22 <add_f>
    5f5c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f61:	48 83 c3 01          	add    $0x1,%rbx
    5f65:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f6a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f6f:	e8 ae bc ff ff       	call   1c22 <add_f>
    5f74:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f79:	48 83 c3 01          	add    $0x1,%rbx
    5f7d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f82:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f87:	e8 96 bc ff ff       	call   1c22 <add_f>
    5f8c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5f91:	48 83 c3 01          	add    $0x1,%rbx
    5f95:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5f9a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5f9f:	e8 7e bc ff ff       	call   1c22 <add_f>
    5fa4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5fa9:	48 83 c3 01          	add    $0x1,%rbx
    5fad:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5fb2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5fb7:	e8 66 bc ff ff       	call   1c22 <add_f>
    5fbc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5fc1:	48 83 c3 01          	add    $0x1,%rbx
    5fc5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5fca:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5fcf:	e8 4e bc ff ff       	call   1c22 <add_f>
    5fd4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5fd9:	48 83 c3 01          	add    $0x1,%rbx
    5fdd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5fe2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5fe7:	e8 36 bc ff ff       	call   1c22 <add_f>
    5fec:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    5ff1:	48 83 c3 01          	add    $0x1,%rbx
    5ff5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    5ffa:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    5fff:	e8 1e bc ff ff       	call   1c22 <add_f>
    6004:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6009:	48 83 c3 01          	add    $0x1,%rbx
    600d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6012:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6017:	e8 06 bc ff ff       	call   1c22 <add_f>
    601c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6021:	48 83 c3 01          	add    $0x1,%rbx
    6025:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    602a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    602f:	e8 ee bb ff ff       	call   1c22 <add_f>
    6034:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6039:	48 83 c3 01          	add    $0x1,%rbx
    603d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6042:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6047:	e8 d6 bb ff ff       	call   1c22 <add_f>
    604c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6051:	48 83 c3 01          	add    $0x1,%rbx
    6055:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    605a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    605f:	e8 be bb ff ff       	call   1c22 <add_f>
    6064:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6069:	48 83 c3 01          	add    $0x1,%rbx
    606d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6072:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6077:	e8 a6 bb ff ff       	call   1c22 <add_f>
    607c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6081:	48 83 c3 01          	add    $0x1,%rbx
    6085:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    608a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    608f:	e8 8e bb ff ff       	call   1c22 <add_f>
    6094:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6099:	48 83 c3 01          	add    $0x1,%rbx
    609d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    60a2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    60a7:	e8 76 bb ff ff       	call   1c22 <add_f>
    60ac:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    60b1:	48 83 c3 01          	add    $0x1,%rbx
    60b5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    60ba:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    60bf:	e8 5e bb ff ff       	call   1c22 <add_f>
    60c4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    60c9:	48 83 c3 01          	add    $0x1,%rbx
    60cd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    60d2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    60d7:	e8 46 bb ff ff       	call   1c22 <add_f>
    60dc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    60e1:	48 83 c3 01          	add    $0x1,%rbx
    60e5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    60ea:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    60ef:	e8 2e bb ff ff       	call   1c22 <add_f>
    60f4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    60f9:	48 83 c3 01          	add    $0x1,%rbx
    60fd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6102:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6107:	e8 16 bb ff ff       	call   1c22 <add_f>
    610c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6111:	48 83 c3 01          	add    $0x1,%rbx
    6115:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    611a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    611f:	e8 fe ba ff ff       	call   1c22 <add_f>
    6124:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6129:	48 83 c3 01          	add    $0x1,%rbx
    612d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6132:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6137:	e8 e6 ba ff ff       	call   1c22 <add_f>
    613c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6141:	48 83 c3 01          	add    $0x1,%rbx
    6145:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    614a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    614f:	e8 ce ba ff ff       	call   1c22 <add_f>
    6154:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6159:	48 83 c3 01          	add    $0x1,%rbx
    615d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6162:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6167:	e8 b6 ba ff ff       	call   1c22 <add_f>
    616c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6171:	48 83 c3 01          	add    $0x1,%rbx
    6175:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    617a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    617f:	e8 9e ba ff ff       	call   1c22 <add_f>
    6184:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6189:	48 83 c3 01          	add    $0x1,%rbx
    618d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6192:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6197:	e8 86 ba ff ff       	call   1c22 <add_f>
    619c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    61a1:	48 83 c3 01          	add    $0x1,%rbx
    61a5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    61aa:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    61af:	e8 6e ba ff ff       	call   1c22 <add_f>
    61b4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    61b9:	48 83 c3 01          	add    $0x1,%rbx
    61bd:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    61c2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    61c7:	e8 56 ba ff ff       	call   1c22 <add_f>
    61cc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    61d1:	48 83 c3 01          	add    $0x1,%rbx
    61d5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    61da:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    61df:	e8 3e ba ff ff       	call   1c22 <add_f>
    61e4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    61e9:	48 83 c3 01          	add    $0x1,%rbx
    61ed:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    61f2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    61f7:	e8 26 ba ff ff       	call   1c22 <add_f>
    61fc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6201:	48 83 c3 01          	add    $0x1,%rbx
    6205:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    620a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    620f:	e8 0e ba ff ff       	call   1c22 <add_f>
    6214:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6219:	48 83 c3 01          	add    $0x1,%rbx
    621d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6222:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6227:	e8 f6 b9 ff ff       	call   1c22 <add_f>
    622c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6231:	48 83 c3 01          	add    $0x1,%rbx
    6235:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    623a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    623f:	e8 de b9 ff ff       	call   1c22 <add_f>
    6244:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6249:	48 83 c3 01          	add    $0x1,%rbx
    624d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6252:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6257:	e8 c6 b9 ff ff       	call   1c22 <add_f>
    625c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6261:	48 83 c3 01          	add    $0x1,%rbx
    6265:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    626a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    626f:	e8 ae b9 ff ff       	call   1c22 <add_f>
    6274:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6279:	48 83 c3 01          	add    $0x1,%rbx
    627d:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    6282:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    6287:	e8 96 b9 ff ff       	call   1c22 <add_f>
    628c:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6291:	48 83 c3 01          	add    $0x1,%rbx
    6295:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    629a:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    629f:	e8 7e b9 ff ff       	call   1c22 <add_f>
    62a4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    62a9:	48 83 c3 01          	add    $0x1,%rbx
    62ad:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    62b2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    62b7:	e8 66 b9 ff ff       	call   1c22 <add_f>
    62bc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    62c1:	48 83 c3 01          	add    $0x1,%rbx
    62c5:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    62ca:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    62cf:	e8 4e b9 ff ff       	call   1c22 <add_f>
    62d4:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    62d9:	48 89 d8             	mov    %rbx,%rax
    62dc:	48 83 c3 01          	add    $0x1,%rbx
    62e0:	48 3b 85 88 5e f1 ff 	cmp    -0xea178(%rbp),%rax
    62e7:	0f 84 9a 05 00 00    	je     6887 <mayo_sign_signature+0x15d6>
    62ed:	42 0f b6 34 3b       	movzbl (%rbx,%r15,1),%esi
    62f2:	41 0f b6 3c 1e       	movzbl (%r14,%rbx,1),%edi
    62f7:	e8 26 b9 ff ff       	call   1c22 <add_f>
    62fc:	41 88 44 1d 00       	mov    %al,0x0(%r13,%rbx,1)
    6301:	4c 8d 63 01          	lea    0x1(%rbx),%r12
    6305:	43 0f b6 34 27       	movzbl (%r15,%r12,1),%esi
    630a:	43 0f b6 3c 26       	movzbl (%r14,%r12,1),%edi
    630f:	e8 0e b9 ff ff       	call   1c22 <add_f>
    6314:	43 88 44 25 00       	mov    %al,0x0(%r13,%r12,1)
    6319:	43 0f b6 74 27 01    	movzbl 0x1(%r15,%r12,1),%esi
    631f:	43 0f b6 7c 26 01    	movzbl 0x1(%r14,%r12,1),%edi
    6325:	e8 f8 b8 ff ff       	call   1c22 <add_f>
    632a:	43 88 44 25 01       	mov    %al,0x1(%r13,%r12,1)
    632f:	43 0f b6 74 27 02    	movzbl 0x2(%r15,%r12,1),%esi
    6335:	43 0f b6 7c 26 02    	movzbl 0x2(%r14,%r12,1),%edi
    633b:	e8 e2 b8 ff ff       	call   1c22 <add_f>
    6340:	43 88 44 25 02       	mov    %al,0x2(%r13,%r12,1)
    6345:	43 0f b6 74 27 03    	movzbl 0x3(%r15,%r12,1),%esi
    634b:	43 0f b6 7c 26 03    	movzbl 0x3(%r14,%r12,1),%edi
    6351:	e8 cc b8 ff ff       	call   1c22 <add_f>
    6356:	43 88 44 25 03       	mov    %al,0x3(%r13,%r12,1)
    635b:	43 0f b6 74 27 04    	movzbl 0x4(%r15,%r12,1),%esi
    6361:	43 0f b6 7c 26 04    	movzbl 0x4(%r14,%r12,1),%edi
    6367:	e8 b6 b8 ff ff       	call   1c22 <add_f>
    636c:	43 88 44 25 04       	mov    %al,0x4(%r13,%r12,1)
    6371:	43 0f b6 74 27 05    	movzbl 0x5(%r15,%r12,1),%esi
    6377:	43 0f b6 7c 26 05    	movzbl 0x5(%r14,%r12,1),%edi
    637d:	e8 a0 b8 ff ff       	call   1c22 <add_f>
    6382:	43 88 44 25 05       	mov    %al,0x5(%r13,%r12,1)
    6387:	43 0f b6 74 27 06    	movzbl 0x6(%r15,%r12,1),%esi
    638d:	43 0f b6 7c 26 06    	movzbl 0x6(%r14,%r12,1),%edi
    6393:	e8 8a b8 ff ff       	call   1c22 <add_f>
    6398:	43 88 44 25 06       	mov    %al,0x6(%r13,%r12,1)
    639d:	43 0f b6 74 27 07    	movzbl 0x7(%r15,%r12,1),%esi
    63a3:	43 0f b6 7c 26 07    	movzbl 0x7(%r14,%r12,1),%edi
    63a9:	e8 74 b8 ff ff       	call   1c22 <add_f>
    63ae:	43 88 44 25 07       	mov    %al,0x7(%r13,%r12,1)
    63b3:	43 0f b6 74 27 08    	movzbl 0x8(%r15,%r12,1),%esi
    63b9:	43 0f b6 7c 26 08    	movzbl 0x8(%r14,%r12,1),%edi
    63bf:	e8 5e b8 ff ff       	call   1c22 <add_f>
    63c4:	43 88 44 25 08       	mov    %al,0x8(%r13,%r12,1)
    63c9:	43 0f b6 74 27 09    	movzbl 0x9(%r15,%r12,1),%esi
    63cf:	43 0f b6 7c 26 09    	movzbl 0x9(%r14,%r12,1),%edi
    63d5:	e8 48 b8 ff ff       	call   1c22 <add_f>
    63da:	43 88 44 25 09       	mov    %al,0x9(%r13,%r12,1)
    63df:	43 0f b6 74 27 0a    	movzbl 0xa(%r15,%r12,1),%esi
    63e5:	43 0f b6 7c 26 0a    	movzbl 0xa(%r14,%r12,1),%edi
    63eb:	e8 32 b8 ff ff       	call   1c22 <add_f>
    63f0:	43 88 44 25 0a       	mov    %al,0xa(%r13,%r12,1)
    63f5:	43 0f b6 74 27 0b    	movzbl 0xb(%r15,%r12,1),%esi
    63fb:	43 0f b6 7c 26 0b    	movzbl 0xb(%r14,%r12,1),%edi
    6401:	e8 1c b8 ff ff       	call   1c22 <add_f>
    6406:	43 88 44 25 0b       	mov    %al,0xb(%r13,%r12,1)
    640b:	43 0f b6 74 27 0c    	movzbl 0xc(%r15,%r12,1),%esi
    6411:	43 0f b6 7c 26 0c    	movzbl 0xc(%r14,%r12,1),%edi
    6417:	e8 06 b8 ff ff       	call   1c22 <add_f>
    641c:	43 88 44 25 0c       	mov    %al,0xc(%r13,%r12,1)
    6421:	43 0f b6 74 27 0d    	movzbl 0xd(%r15,%r12,1),%esi
    6427:	43 0f b6 7c 26 0d    	movzbl 0xd(%r14,%r12,1),%edi
    642d:	e8 f0 b7 ff ff       	call   1c22 <add_f>
    6432:	43 88 44 25 0d       	mov    %al,0xd(%r13,%r12,1)
    6437:	43 0f b6 74 27 0e    	movzbl 0xe(%r15,%r12,1),%esi
    643d:	43 0f b6 7c 26 0e    	movzbl 0xe(%r14,%r12,1),%edi
    6443:	e8 da b7 ff ff       	call   1c22 <add_f>
    6448:	43 88 44 25 0e       	mov    %al,0xe(%r13,%r12,1)
    644d:	43 0f b6 74 27 0f    	movzbl 0xf(%r15,%r12,1),%esi
    6453:	43 0f b6 7c 26 0f    	movzbl 0xf(%r14,%r12,1),%edi
    6459:	e8 c4 b7 ff ff       	call   1c22 <add_f>
    645e:	43 88 44 25 0f       	mov    %al,0xf(%r13,%r12,1)
    6463:	43 0f b6 74 27 10    	movzbl 0x10(%r15,%r12,1),%esi
    6469:	43 0f b6 7c 26 10    	movzbl 0x10(%r14,%r12,1),%edi
    646f:	e8 ae b7 ff ff       	call   1c22 <add_f>
    6474:	43 88 44 25 10       	mov    %al,0x10(%r13,%r12,1)
    6479:	43 0f b6 74 27 11    	movzbl 0x11(%r15,%r12,1),%esi
    647f:	43 0f b6 7c 26 11    	movzbl 0x11(%r14,%r12,1),%edi
    6485:	e8 98 b7 ff ff       	call   1c22 <add_f>
    648a:	43 88 44 25 11       	mov    %al,0x11(%r13,%r12,1)
    648f:	43 0f b6 74 27 12    	movzbl 0x12(%r15,%r12,1),%esi
    6495:	43 0f b6 7c 26 12    	movzbl 0x12(%r14,%r12,1),%edi
    649b:	e8 82 b7 ff ff       	call   1c22 <add_f>
    64a0:	43 88 44 25 12       	mov    %al,0x12(%r13,%r12,1)
    64a5:	43 0f b6 74 27 13    	movzbl 0x13(%r15,%r12,1),%esi
    64ab:	43 0f b6 7c 26 13    	movzbl 0x13(%r14,%r12,1),%edi
    64b1:	e8 6c b7 ff ff       	call   1c22 <add_f>
    64b6:	43 88 44 25 13       	mov    %al,0x13(%r13,%r12,1)
    64bb:	43 0f b6 74 27 14    	movzbl 0x14(%r15,%r12,1),%esi
    64c1:	43 0f b6 7c 26 14    	movzbl 0x14(%r14,%r12,1),%edi
    64c7:	e8 56 b7 ff ff       	call   1c22 <add_f>
    64cc:	43 88 44 25 14       	mov    %al,0x14(%r13,%r12,1)
    64d1:	43 0f b6 74 27 15    	movzbl 0x15(%r15,%r12,1),%esi
    64d7:	43 0f b6 7c 26 15    	movzbl 0x15(%r14,%r12,1),%edi
    64dd:	e8 40 b7 ff ff       	call   1c22 <add_f>
    64e2:	43 88 44 25 15       	mov    %al,0x15(%r13,%r12,1)
    64e7:	43 0f b6 74 27 16    	movzbl 0x16(%r15,%r12,1),%esi
    64ed:	43 0f b6 7c 26 16    	movzbl 0x16(%r14,%r12,1),%edi
    64f3:	e8 2a b7 ff ff       	call   1c22 <add_f>
    64f8:	43 88 44 25 16       	mov    %al,0x16(%r13,%r12,1)
    64fd:	43 0f b6 74 27 17    	movzbl 0x17(%r15,%r12,1),%esi
    6503:	43 0f b6 7c 26 17    	movzbl 0x17(%r14,%r12,1),%edi
    6509:	e8 14 b7 ff ff       	call   1c22 <add_f>
    650e:	43 88 44 25 17       	mov    %al,0x17(%r13,%r12,1)
    6513:	43 0f b6 74 27 18    	movzbl 0x18(%r15,%r12,1),%esi
    6519:	43 0f b6 7c 26 18    	movzbl 0x18(%r14,%r12,1),%edi
    651f:	e8 fe b6 ff ff       	call   1c22 <add_f>
    6524:	43 88 44 25 18       	mov    %al,0x18(%r13,%r12,1)
    6529:	43 0f b6 74 27 19    	movzbl 0x19(%r15,%r12,1),%esi
    652f:	43 0f b6 7c 26 19    	movzbl 0x19(%r14,%r12,1),%edi
    6535:	e8 e8 b6 ff ff       	call   1c22 <add_f>
    653a:	43 88 44 25 19       	mov    %al,0x19(%r13,%r12,1)
    653f:	43 0f b6 74 27 1a    	movzbl 0x1a(%r15,%r12,1),%esi
    6545:	43 0f b6 7c 26 1a    	movzbl 0x1a(%r14,%r12,1),%edi
    654b:	e8 d2 b6 ff ff       	call   1c22 <add_f>
    6550:	43 88 44 25 1a       	mov    %al,0x1a(%r13,%r12,1)
    6555:	43 0f b6 74 27 1b    	movzbl 0x1b(%r15,%r12,1),%esi
    655b:	43 0f b6 7c 26 1b    	movzbl 0x1b(%r14,%r12,1),%edi
    6561:	e8 bc b6 ff ff       	call   1c22 <add_f>
    6566:	43 88 44 25 1b       	mov    %al,0x1b(%r13,%r12,1)
    656b:	43 0f b6 74 27 1c    	movzbl 0x1c(%r15,%r12,1),%esi
    6571:	43 0f b6 7c 26 1c    	movzbl 0x1c(%r14,%r12,1),%edi
    6577:	e8 a6 b6 ff ff       	call   1c22 <add_f>
    657c:	43 88 44 25 1c       	mov    %al,0x1c(%r13,%r12,1)
    6581:	43 0f b6 74 27 1d    	movzbl 0x1d(%r15,%r12,1),%esi
    6587:	43 0f b6 7c 26 1d    	movzbl 0x1d(%r14,%r12,1),%edi
    658d:	e8 90 b6 ff ff       	call   1c22 <add_f>
    6592:	43 88 44 25 1d       	mov    %al,0x1d(%r13,%r12,1)
    6597:	43 0f b6 74 27 1e    	movzbl 0x1e(%r15,%r12,1),%esi
    659d:	43 0f b6 7c 26 1e    	movzbl 0x1e(%r14,%r12,1),%edi
    65a3:	e8 7a b6 ff ff       	call   1c22 <add_f>
    65a8:	43 88 44 25 1e       	mov    %al,0x1e(%r13,%r12,1)
    65ad:	43 0f b6 74 27 1f    	movzbl 0x1f(%r15,%r12,1),%esi
    65b3:	43 0f b6 7c 26 1f    	movzbl 0x1f(%r14,%r12,1),%edi
    65b9:	e8 64 b6 ff ff       	call   1c22 <add_f>
    65be:	43 88 44 25 1f       	mov    %al,0x1f(%r13,%r12,1)
    65c3:	43 0f b6 74 27 20    	movzbl 0x20(%r15,%r12,1),%esi
    65c9:	43 0f b6 7c 26 20    	movzbl 0x20(%r14,%r12,1),%edi
    65cf:	e8 4e b6 ff ff       	call   1c22 <add_f>
    65d4:	43 88 44 25 20       	mov    %al,0x20(%r13,%r12,1)
    65d9:	43 0f b6 74 27 21    	movzbl 0x21(%r15,%r12,1),%esi
    65df:	43 0f b6 7c 26 21    	movzbl 0x21(%r14,%r12,1),%edi
    65e5:	e8 38 b6 ff ff       	call   1c22 <add_f>
    65ea:	43 88 44 25 21       	mov    %al,0x21(%r13,%r12,1)
    65ef:	43 0f b6 74 27 22    	movzbl 0x22(%r15,%r12,1),%esi
    65f5:	43 0f b6 7c 26 22    	movzbl 0x22(%r14,%r12,1),%edi
    65fb:	e8 22 b6 ff ff       	call   1c22 <add_f>
    6600:	43 88 44 25 22       	mov    %al,0x22(%r13,%r12,1)
    6605:	43 0f b6 74 27 23    	movzbl 0x23(%r15,%r12,1),%esi
    660b:	43 0f b6 7c 26 23    	movzbl 0x23(%r14,%r12,1),%edi
    6611:	e8 0c b6 ff ff       	call   1c22 <add_f>
    6616:	43 88 44 25 23       	mov    %al,0x23(%r13,%r12,1)
    661b:	43 0f b6 74 27 24    	movzbl 0x24(%r15,%r12,1),%esi
    6621:	43 0f b6 7c 26 24    	movzbl 0x24(%r14,%r12,1),%edi
    6627:	e8 f6 b5 ff ff       	call   1c22 <add_f>
    662c:	43 88 44 25 24       	mov    %al,0x24(%r13,%r12,1)
    6631:	43 0f b6 74 27 25    	movzbl 0x25(%r15,%r12,1),%esi
    6637:	43 0f b6 7c 26 25    	movzbl 0x25(%r14,%r12,1),%edi
    663d:	e8 e0 b5 ff ff       	call   1c22 <add_f>
    6642:	43 88 44 25 25       	mov    %al,0x25(%r13,%r12,1)
    6647:	43 0f b6 74 27 26    	movzbl 0x26(%r15,%r12,1),%esi
    664d:	43 0f b6 7c 26 26    	movzbl 0x26(%r14,%r12,1),%edi
    6653:	e8 ca b5 ff ff       	call   1c22 <add_f>
    6658:	43 88 44 25 26       	mov    %al,0x26(%r13,%r12,1)
    665d:	43 0f b6 74 27 27    	movzbl 0x27(%r15,%r12,1),%esi
    6663:	43 0f b6 7c 26 27    	movzbl 0x27(%r14,%r12,1),%edi
    6669:	e8 b4 b5 ff ff       	call   1c22 <add_f>
    666e:	43 88 44 25 27       	mov    %al,0x27(%r13,%r12,1)
    6673:	43 0f b6 74 27 28    	movzbl 0x28(%r15,%r12,1),%esi
    6679:	43 0f b6 7c 26 28    	movzbl 0x28(%r14,%r12,1),%edi
    667f:	e8 9e b5 ff ff       	call   1c22 <add_f>
    6684:	43 88 44 25 28       	mov    %al,0x28(%r13,%r12,1)
    6689:	43 0f b6 74 27 29    	movzbl 0x29(%r15,%r12,1),%esi
    668f:	43 0f b6 7c 26 29    	movzbl 0x29(%r14,%r12,1),%edi
    6695:	e8 88 b5 ff ff       	call   1c22 <add_f>
    669a:	43 88 44 25 29       	mov    %al,0x29(%r13,%r12,1)
    669f:	43 0f b6 74 27 2a    	movzbl 0x2a(%r15,%r12,1),%esi
    66a5:	43 0f b6 7c 26 2a    	movzbl 0x2a(%r14,%r12,1),%edi
    66ab:	e8 72 b5 ff ff       	call   1c22 <add_f>
    66b0:	43 88 44 25 2a       	mov    %al,0x2a(%r13,%r12,1)
    66b5:	43 0f b6 74 27 2b    	movzbl 0x2b(%r15,%r12,1),%esi
    66bb:	43 0f b6 7c 26 2b    	movzbl 0x2b(%r14,%r12,1),%edi
    66c1:	e8 5c b5 ff ff       	call   1c22 <add_f>
    66c6:	43 88 44 25 2b       	mov    %al,0x2b(%r13,%r12,1)
    66cb:	43 0f b6 74 27 2c    	movzbl 0x2c(%r15,%r12,1),%esi
    66d1:	43 0f b6 7c 26 2c    	movzbl 0x2c(%r14,%r12,1),%edi
    66d7:	e8 46 b5 ff ff       	call   1c22 <add_f>
    66dc:	43 88 44 25 2c       	mov    %al,0x2c(%r13,%r12,1)
    66e1:	43 0f b6 74 27 2d    	movzbl 0x2d(%r15,%r12,1),%esi
    66e7:	43 0f b6 7c 26 2d    	movzbl 0x2d(%r14,%r12,1),%edi
    66ed:	e8 30 b5 ff ff       	call   1c22 <add_f>
    66f2:	43 88 44 25 2d       	mov    %al,0x2d(%r13,%r12,1)
    66f7:	43 0f b6 74 27 2e    	movzbl 0x2e(%r15,%r12,1),%esi
    66fd:	43 0f b6 7c 26 2e    	movzbl 0x2e(%r14,%r12,1),%edi
    6703:	e8 1a b5 ff ff       	call   1c22 <add_f>
    6708:	43 88 44 25 2e       	mov    %al,0x2e(%r13,%r12,1)
    670d:	43 0f b6 74 27 2f    	movzbl 0x2f(%r15,%r12,1),%esi
    6713:	43 0f b6 7c 26 2f    	movzbl 0x2f(%r14,%r12,1),%edi
    6719:	e8 04 b5 ff ff       	call   1c22 <add_f>
    671e:	43 88 44 25 2f       	mov    %al,0x2f(%r13,%r12,1)
    6723:	43 0f b6 74 27 30    	movzbl 0x30(%r15,%r12,1),%esi
    6729:	43 0f b6 7c 26 30    	movzbl 0x30(%r14,%r12,1),%edi
    672f:	e8 ee b4 ff ff       	call   1c22 <add_f>
    6734:	43 88 44 25 30       	mov    %al,0x30(%r13,%r12,1)
    6739:	43 0f b6 74 27 31    	movzbl 0x31(%r15,%r12,1),%esi
    673f:	43 0f b6 7c 26 31    	movzbl 0x31(%r14,%r12,1),%edi
    6745:	e8 d8 b4 ff ff       	call   1c22 <add_f>
    674a:	43 88 44 25 31       	mov    %al,0x31(%r13,%r12,1)
    674f:	43 0f b6 74 27 32    	movzbl 0x32(%r15,%r12,1),%esi
    6755:	43 0f b6 7c 26 32    	movzbl 0x32(%r14,%r12,1),%edi
    675b:	e8 c2 b4 ff ff       	call   1c22 <add_f>
    6760:	43 88 44 25 32       	mov    %al,0x32(%r13,%r12,1)
    6765:	43 0f b6 74 27 33    	movzbl 0x33(%r15,%r12,1),%esi
    676b:	43 0f b6 7c 26 33    	movzbl 0x33(%r14,%r12,1),%edi
    6771:	e8 ac b4 ff ff       	call   1c22 <add_f>
    6776:	43 88 44 25 33       	mov    %al,0x33(%r13,%r12,1)
    677b:	43 0f b6 74 27 34    	movzbl 0x34(%r15,%r12,1),%esi
    6781:	43 0f b6 7c 26 34    	movzbl 0x34(%r14,%r12,1),%edi
    6787:	e8 96 b4 ff ff       	call   1c22 <add_f>
    678c:	43 88 44 25 34       	mov    %al,0x34(%r13,%r12,1)
    6791:	43 0f b6 74 27 35    	movzbl 0x35(%r15,%r12,1),%esi
    6797:	43 0f b6 7c 26 35    	movzbl 0x35(%r14,%r12,1),%edi
    679d:	e8 80 b4 ff ff       	call   1c22 <add_f>
    67a2:	43 88 44 25 35       	mov    %al,0x35(%r13,%r12,1)
    67a7:	43 0f b6 74 27 36    	movzbl 0x36(%r15,%r12,1),%esi
    67ad:	43 0f b6 7c 26 36    	movzbl 0x36(%r14,%r12,1),%edi
    67b3:	e8 6a b4 ff ff       	call   1c22 <add_f>
    67b8:	43 88 44 25 36       	mov    %al,0x36(%r13,%r12,1)
    67bd:	43 0f b6 74 27 37    	movzbl 0x37(%r15,%r12,1),%esi
    67c3:	43 0f b6 7c 26 37    	movzbl 0x37(%r14,%r12,1),%edi
    67c9:	e8 54 b4 ff ff       	call   1c22 <add_f>
    67ce:	43 88 44 25 37       	mov    %al,0x37(%r13,%r12,1)
    67d3:	43 0f b6 74 27 38    	movzbl 0x38(%r15,%r12,1),%esi
    67d9:	43 0f b6 7c 26 38    	movzbl 0x38(%r14,%r12,1),%edi
    67df:	e8 3e b4 ff ff       	call   1c22 <add_f>
    67e4:	43 88 44 25 38       	mov    %al,0x38(%r13,%r12,1)
    67e9:	43 0f b6 74 27 39    	movzbl 0x39(%r15,%r12,1),%esi
    67ef:	43 0f b6 7c 26 39    	movzbl 0x39(%r14,%r12,1),%edi
    67f5:	e8 28 b4 ff ff       	call   1c22 <add_f>
    67fa:	43 88 44 25 39       	mov    %al,0x39(%r13,%r12,1)
    67ff:	43 0f b6 74 27 3a    	movzbl 0x3a(%r15,%r12,1),%esi
    6805:	43 0f b6 7c 26 3a    	movzbl 0x3a(%r14,%r12,1),%edi
    680b:	e8 12 b4 ff ff       	call   1c22 <add_f>
    6810:	43 88 44 25 3a       	mov    %al,0x3a(%r13,%r12,1)
    6815:	43 0f b6 74 27 3b    	movzbl 0x3b(%r15,%r12,1),%esi
    681b:	43 0f b6 7c 26 3b    	movzbl 0x3b(%r14,%r12,1),%edi
    6821:	e8 fc b3 ff ff       	call   1c22 <add_f>
    6826:	43 88 44 25 3b       	mov    %al,0x3b(%r13,%r12,1)
    682b:	43 0f b6 74 27 3c    	movzbl 0x3c(%r15,%r12,1),%esi
    6831:	43 0f b6 7c 26 3c    	movzbl 0x3c(%r14,%r12,1),%edi
    6837:	e8 e6 b3 ff ff       	call   1c22 <add_f>
    683c:	43 88 44 25 3c       	mov    %al,0x3c(%r13,%r12,1)
    6841:	43 0f b6 74 27 3d    	movzbl 0x3d(%r15,%r12,1),%esi
    6847:	43 0f b6 7c 26 3d    	movzbl 0x3d(%r14,%r12,1),%edi
    684d:	e8 d0 b3 ff ff       	call   1c22 <add_f>
    6852:	43 88 44 25 3d       	mov    %al,0x3d(%r13,%r12,1)
    6857:	49 8d 5c 24 3e       	lea    0x3e(%r12),%rbx
    685c:	43 0f b6 74 27 3e    	movzbl 0x3e(%r15,%r12,1),%esi
    6862:	43 0f b6 7c 26 3e    	movzbl 0x3e(%r14,%r12,1),%edi
    6868:	e8 b5 b3 ff ff       	call   1c22 <add_f>
    686d:	43 88 44 25 3e       	mov    %al,0x3e(%r13,%r12,1)
    6872:	48 89 d8             	mov    %rbx,%rax
    6875:	49 8d 5c 24 3f       	lea    0x3f(%r12),%rbx
    687a:	48 3b 85 88 5e f1 ff 	cmp    -0xea178(%rbp),%rax
    6881:	0f 85 66 fa ff ff    	jne    62ed <mayo_sign_signature+0x103c>
    6887:	48 8b 9d 68 5e f1 ff 	mov    -0xea198(%rbp),%rbx
    688e:	49 8d 7c 1d 00       	lea    0x0(%r13,%rbx,1),%rdi
    6893:	4c 8b a5 60 5e f1 ff 	mov    -0xea1a0(%rbp),%r12
    689a:	4c 89 e2             	mov    %r12,%rdx
    689d:	48 8b b5 80 5e f1 ff 	mov    -0xea180(%rbp),%rsi
    68a4:	e8 87 a9 ff ff       	call   1230 <memcpy@plt>
    68a9:	83 85 98 5e f1 ff 01 	addl   $0x1,-0xea168(%rbp)
    68b0:	8b 85 98 5e f1 ff    	mov    -0xea168(%rbp),%eax
    68b6:	4c 01 a5 90 5e f1 ff 	add    %r12,-0xea170(%rbp)
    68bd:	49 01 de             	add    %rbx,%r14
    68c0:	4c 03 ad 70 5e f1 ff 	add    -0xea190(%rbp),%r13
    68c7:	39 85 ac 5e f1 ff    	cmp    %eax,-0xea154(%rbp)
    68cd:	0f 84 c7 f0 ff ff    	je     599a <mayo_sign_signature+0x6e9>
    68d3:	e9 70 f1 ff ff       	jmp    5a48 <mayo_sign_signature+0x797>
    68d8:	e8 f3 a8 ff ff       	call   11d0 <__stack_chk_fail@plt>

00000000000068dd <mayo_sign>:
    68dd:	f3 0f 1e fa          	endbr64
    68e1:	55                   	push   %rbp
    68e2:	48 89 e5             	mov    %rsp,%rbp
    68e5:	48 83 ec 50          	sub    $0x50,%rsp
    68e9:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    68ed:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    68f1:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    68f5:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    68f9:	4c 89 45 b8          	mov    %r8,-0x48(%rbp)
    68fd:	4c 89 4d b0          	mov    %r9,-0x50(%rbp)
    6901:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    6908:	00 00 
    690a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    690e:	31 c0                	xor    %eax,%eax
    6910:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    6917:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    691b:	8b 40 48             	mov    0x48(%rax),%eax
    691e:	89 45 ec             	mov    %eax,-0x14(%rbp)
    6921:	8b 45 ec             	mov    -0x14(%rbp),%eax
    6924:	48 98                	cltq
    6926:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    692a:	48 01 d0             	add    %rdx,%rax
    692d:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    6931:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
    6935:	48 89 ce             	mov    %rcx,%rsi
    6938:	48 89 c7             	mov    %rax,%rdi
    693b:	e8 10 a9 ff ff       	call   1250 <memmove@plt>
    6940:	8b 45 ec             	mov    -0x14(%rbp),%eax
    6943:	48 98                	cltq
    6945:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    6949:	48 01 c2             	add    %rax,%rdx
    694c:	4c 8b 45 b0          	mov    -0x50(%rbp),%r8
    6950:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
    6954:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    6958:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    695c:	48 8b 7d d8          	mov    -0x28(%rbp),%rdi
    6960:	4d 89 c1             	mov    %r8,%r9
    6963:	49 89 c8             	mov    %rcx,%r8
    6966:	48 89 d1             	mov    %rdx,%rcx
    6969:	48 89 c2             	mov    %rax,%rdx
    696c:	e8 40 e9 ff ff       	call   52b1 <mayo_sign_signature>
    6971:	89 45 e8             	mov    %eax,-0x18(%rbp)
    6974:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
    6978:	75 0e                	jne    6988 <mayo_sign+0xab>
    697a:	8b 45 ec             	mov    -0x14(%rbp),%eax
    697d:	48 98                	cltq
    697f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    6983:	48 39 d0             	cmp    %rdx,%rax
    6986:	74 1e                	je     69a6 <mayo_sign+0xc9>
    6988:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    698c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    6990:	48 01 c2             	add    %rax,%rdx
    6993:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6997:	be 00 00 00 00       	mov    $0x0,%esi
    699c:	48 89 c7             	mov    %rax,%rdi
    699f:	e8 5c a8 ff ff       	call   1200 <memset@plt>
    69a4:	eb 12                	jmp    69b8 <mayo_sign+0xdb>
    69a6:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    69aa:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    69ae:	48 01 c2             	add    %rax,%rdx
    69b1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69b5:	48 89 10             	mov    %rdx,(%rax)
    69b8:	8b 45 e8             	mov    -0x18(%rbp),%eax
    69bb:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    69bf:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    69c6:	00 00 
    69c8:	74 05                	je     69cf <mayo_sign+0xf2>
    69ca:	e8 01 a8 ff ff       	call   11d0 <__stack_chk_fail@plt>
    69cf:	c9                   	leave
    69d0:	c3                   	ret

00000000000069d1 <mayo_open>:
    69d1:	f3 0f 1e fa          	endbr64
    69d5:	55                   	push   %rbp
    69d6:	48 89 e5             	mov    %rsp,%rbp
    69d9:	48 83 ec 40          	sub    $0x40,%rsp
    69dd:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    69e1:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    69e5:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    69e9:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    69ed:	4c 89 45 c8          	mov    %r8,-0x38(%rbp)
    69f1:	4c 89 4d c0          	mov    %r9,-0x40(%rbp)
    69f5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    69f9:	8b 40 48             	mov    0x48(%rax),%eax
    69fc:	89 45 f8             	mov    %eax,-0x8(%rbp)
    69ff:	8b 45 f8             	mov    -0x8(%rbp),%eax
    6a02:	48 98                	cltq
    6a04:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    6a08:	73 07                	jae    6a11 <mayo_open+0x40>
    6a0a:	b8 01 00 00 00       	mov    $0x1,%eax
    6a0f:	eb 71                	jmp    6a82 <mayo_open+0xb1>
    6a11:	8b 45 f8             	mov    -0x8(%rbp),%eax
    6a14:	48 98                	cltq
    6a16:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6a1a:	48 29 c2             	sub    %rax,%rdx
    6a1d:	8b 45 f8             	mov    -0x8(%rbp),%eax
    6a20:	48 98                	cltq
    6a22:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    6a26:	48 8d 34 08          	lea    (%rax,%rcx,1),%rsi
    6a2a:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
    6a2e:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    6a32:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6a36:	49 89 f8             	mov    %rdi,%r8
    6a39:	48 89 c7             	mov    %rax,%rdi
    6a3c:	e8 e7 04 00 00       	call   6f28 <mayo_verify>
    6a41:	89 45 fc             	mov    %eax,-0x4(%rbp)
    6a44:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    6a48:	75 35                	jne    6a7f <mayo_open+0xae>
    6a4a:	8b 45 f8             	mov    -0x8(%rbp),%eax
    6a4d:	48 98                	cltq
    6a4f:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6a53:	48 29 c2             	sub    %rax,%rdx
    6a56:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6a5a:	48 89 10             	mov    %rdx,(%rax)
    6a5d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6a61:	48 8b 10             	mov    (%rax),%rdx
    6a64:	8b 45 f8             	mov    -0x8(%rbp),%eax
    6a67:	48 98                	cltq
    6a69:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    6a6d:	48 01 c1             	add    %rax,%rcx
    6a70:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6a74:	48 89 ce             	mov    %rcx,%rsi
    6a77:	48 89 c7             	mov    %rax,%rdi
    6a7a:	e8 d1 a7 ff ff       	call   1250 <memmove@plt>
    6a7f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    6a82:	c9                   	leave
    6a83:	c3                   	ret

0000000000006a84 <mayo_keypair_compact>:
    6a84:	f3 0f 1e fa          	endbr64
    6a88:	55                   	push   %rbp
    6a89:	48 89 e5             	mov    %rsp,%rbp
    6a8c:	4c 8d 9c 24 00 b0 f1 	lea    -0xe5000(%rsp),%r11
    6a93:	ff 
    6a94:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    6a9b:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    6aa0:	4c 39 dc             	cmp    %r11,%rsp
    6aa3:	75 ef                	jne    6a94 <mayo_keypair_compact+0x10>
    6aa5:	48 81 ec 40 08 00 00 	sub    $0x840,%rsp
    6aac:	48 89 bd d8 a7 f1 ff 	mov    %rdi,-0xe5828(%rbp)
    6ab3:	48 89 b5 d0 a7 f1 ff 	mov    %rsi,-0xe5830(%rbp)
    6aba:	48 89 95 c8 a7 f1 ff 	mov    %rdx,-0xe5838(%rbp)
    6ac1:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    6ac8:	00 00 
    6aca:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    6ace:	31 c0                	xor    %eax,%eax
    6ad0:	c7 85 e8 a7 f1 ff 00 	movl   $0x0,-0xe5818(%rbp)
    6ad7:	00 00 00 
    6ada:	48 8b 85 c8 a7 f1 ff 	mov    -0xe5838(%rbp),%rax
    6ae1:	48 89 85 10 a8 f1 ff 	mov    %rax,-0xe57f0(%rbp)
    6ae8:	48 8d 85 40 d3 f1 ff 	lea    -0xe2cc0(%rbp),%rax
    6aef:	ba 48 51 00 00       	mov    $0x5148,%edx
    6af4:	be 00 00 00 00       	mov    $0x0,%esi
    6af9:	48 89 c7             	mov    %rax,%rdi
    6afc:	e8 ff a6 ff ff       	call   1200 <memset@plt>
    6b01:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b08:	8b 40 5c             	mov    0x5c(%rax),%eax
    6b0b:	89 85 ec a7 f1 ff    	mov    %eax,-0xe5814(%rbp)
    6b11:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b18:	8b 00                	mov    (%rax),%eax
    6b1a:	89 85 f0 a7 f1 ff    	mov    %eax,-0xe5810(%rbp)
    6b20:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b27:	8b 50 04             	mov    0x4(%rax),%edx
    6b2a:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b31:	8b 40 08             	mov    0x8(%rax),%eax
    6b34:	29 c2                	sub    %eax,%edx
    6b36:	89 d0                	mov    %edx,%eax
    6b38:	89 85 f4 a7 f1 ff    	mov    %eax,-0xe580c(%rbp)
    6b3e:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b45:	8b 40 08             	mov    0x8(%rax),%eax
    6b48:	89 85 f8 a7 f1 ff    	mov    %eax,-0xe5808(%rbp)
    6b4e:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b55:	8b 40 24             	mov    0x24(%rax),%eax
    6b58:	89 85 fc a7 f1 ff    	mov    %eax,-0xe5804(%rbp)
    6b5e:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b65:	8b 50 04             	mov    0x4(%rax),%edx
    6b68:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b6f:	8b 40 08             	mov    0x8(%rax),%eax
    6b72:	29 c2                	sub    %eax,%edx
    6b74:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b7b:	8b 48 04             	mov    0x4(%rax),%ecx
    6b7e:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6b85:	8b 40 08             	mov    0x8(%rax),%eax
    6b88:	29 c1                	sub    %eax,%ecx
    6b8a:	89 c8                	mov    %ecx,%eax
    6b8c:	83 c0 01             	add    $0x1,%eax
    6b8f:	0f af c2             	imul   %edx,%eax
    6b92:	89 c2                	mov    %eax,%edx
    6b94:	c1 ea 1f             	shr    $0x1f,%edx
    6b97:	01 d0                	add    %edx,%eax
    6b99:	d1 f8                	sar    $1,%eax
    6b9b:	89 c2                	mov    %eax,%edx
    6b9d:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6ba4:	8b 40 5c             	mov    0x5c(%rax),%eax
    6ba7:	0f af c2             	imul   %edx,%eax
    6baa:	89 85 00 a8 f1 ff    	mov    %eax,-0xe5800(%rbp)
    6bb0:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6bb7:	8b 50 08             	mov    0x8(%rax),%edx
    6bba:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6bc1:	8b 40 08             	mov    0x8(%rax),%eax
    6bc4:	83 c0 01             	add    $0x1,%eax
    6bc7:	0f af c2             	imul   %edx,%eax
    6bca:	89 c2                	mov    %eax,%edx
    6bcc:	c1 ea 1f             	shr    $0x1f,%edx
    6bcf:	01 d0                	add    %edx,%eax
    6bd1:	d1 f8                	sar    $1,%eax
    6bd3:	89 c2                	mov    %eax,%edx
    6bd5:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6bdc:	8b 40 5c             	mov    0x5c(%rax),%eax
    6bdf:	0f af c2             	imul   %edx,%eax
    6be2:	89 85 04 a8 f1 ff    	mov    %eax,-0xe57fc(%rbp)
    6be8:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6bef:	8b 40 58             	mov    0x58(%rax),%eax
    6bf2:	89 85 08 a8 f1 ff    	mov    %eax,-0xe57f8(%rbp)
    6bf8:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6bff:	8b 40 50             	mov    0x50(%rax),%eax
    6c02:	89 85 0c a8 f1 ff    	mov    %eax,-0xe57f4(%rbp)
    6c08:	48 8d 85 90 24 f2 ff 	lea    -0xddb70(%rbp),%rax
    6c0f:	48 89 85 18 a8 f1 ff 	mov    %rax,-0xe57e8(%rbp)
    6c16:	8b 85 00 a8 f1 ff    	mov    -0xe5800(%rbp),%eax
    6c1c:	48 98                	cltq
    6c1e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6c25:	00 
    6c26:	48 8d 85 90 24 f2 ff 	lea    -0xddb70(%rbp),%rax
    6c2d:	48 01 d0             	add    %rdx,%rax
    6c30:	48 89 85 20 a8 f1 ff 	mov    %rax,-0xe57e0(%rbp)
    6c37:	8b 85 0c a8 f1 ff    	mov    -0xe57f4(%rbp),%eax
    6c3d:	48 98                	cltq
    6c3f:	48 8b 95 10 a8 f1 ff 	mov    -0xe57f0(%rbp),%rdx
    6c46:	48 89 c6             	mov    %rax,%rsi
    6c49:	48 89 d7             	mov    %rdx,%rdi
    6c4c:	e8 56 1c 00 00       	call   88a7 <randombytes>
    6c51:	85 c0                	test   %eax,%eax
    6c53:	74 0f                	je     6c64 <mayo_keypair_compact+0x1e0>
    6c55:	c7 85 e8 a7 f1 ff 01 	movl   $0x1,-0xe5818(%rbp)
    6c5c:	00 00 00 
    6c5f:	e9 44 01 00 00       	jmp    6da8 <mayo_keypair_compact+0x324>
    6c64:	8b 85 0c a8 f1 ff    	mov    -0xe57f4(%rbp),%eax
    6c6a:	48 63 d0             	movslq %eax,%rdx
    6c6d:	8b 8d 08 a8 f1 ff    	mov    -0xe57f8(%rbp),%ecx
    6c73:	8b 85 fc a7 f1 ff    	mov    -0xe5804(%rbp),%eax
    6c79:	01 c8                	add    %ecx,%eax
    6c7b:	48 63 f0             	movslq %eax,%rsi
    6c7e:	48 8b bd 10 a8 f1 ff 	mov    -0xe57f0(%rbp),%rdi
    6c85:	48 8d 85 10 f3 ff ff 	lea    -0xcf0(%rbp),%rax
    6c8c:	48 89 d1             	mov    %rdx,%rcx
    6c8f:	48 89 fa             	mov    %rdi,%rdx
    6c92:	48 89 c7             	mov    %rax,%rdi
    6c95:	e8 e9 68 00 00       	call   d583 <shake256>
    6c9a:	48 8d 85 10 f3 ff ff 	lea    -0xcf0(%rbp),%rax
    6ca1:	48 89 85 28 a8 f1 ff 	mov    %rax,-0xe57d8(%rbp)
    6ca8:	8b 85 f4 a7 f1 ff    	mov    -0xe580c(%rbp),%eax
    6cae:	0f af 85 f8 a7 f1 ff 	imul   -0xe5808(%rbp),%eax
    6cb5:	89 c2                	mov    %eax,%edx
    6cb7:	8b 85 08 a8 f1 ff    	mov    -0xe57f8(%rbp),%eax
    6cbd:	48 98                	cltq
    6cbf:	48 8d 8d 10 f3 ff ff 	lea    -0xcf0(%rbp),%rcx
    6cc6:	48 01 c1             	add    %rax,%rcx
    6cc9:	48 8d 85 80 f6 ff ff 	lea    -0x980(%rbp),%rax
    6cd0:	48 89 c6             	mov    %rax,%rsi
    6cd3:	48 89 cf             	mov    %rcx,%rdi
    6cd6:	e8 d0 c7 ff ff       	call   34ab <decode>
    6cdb:	48 8b 95 28 a8 f1 ff 	mov    -0xe57d8(%rbp),%rdx
    6ce2:	48 8d 85 90 24 f2 ff 	lea    -0xddb70(%rbp),%rax
    6ce9:	48 8b 8d d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rcx
    6cf0:	48 89 c6             	mov    %rax,%rsi
    6cf3:	48 89 cf             	mov    %rcx,%rdi
    6cf6:	e8 dc e0 ff ff       	call   4dd7 <expand_P1_P2>
    6cfb:	48 8d 8d 40 d3 f1 ff 	lea    -0xe2cc0(%rbp),%rcx
    6d02:	48 8d 85 80 f6 ff ff 	lea    -0x980(%rbp),%rax
    6d09:	48 8b 95 20 a8 f1 ff 	mov    -0xe57e0(%rbp),%rdx
    6d10:	48 8b b5 18 a8 f1 ff 	mov    -0xe57e8(%rbp),%rsi
    6d17:	48 8b bd d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rdi
    6d1e:	49 89 c8             	mov    %rcx,%r8
    6d21:	48 89 c1             	mov    %rax,%rcx
    6d24:	e8 b8 c5 ff ff       	call   32e1 <compute_P3>
    6d29:	8b 85 08 a8 f1 ff    	mov    -0xe57f8(%rbp),%eax
    6d2f:	48 98                	cltq
    6d31:	48 8b b5 28 a8 f1 ff 	mov    -0xe57d8(%rbp),%rsi
    6d38:	48 8b 8d d0 a7 f1 ff 	mov    -0xe5830(%rbp),%rcx
    6d3f:	48 89 c2             	mov    %rax,%rdx
    6d42:	48 89 cf             	mov    %rcx,%rdi
    6d45:	e8 e6 a4 ff ff       	call   1230 <memcpy@plt>
    6d4a:	8b 8d f8 a7 f1 ff    	mov    -0xe5808(%rbp),%ecx
    6d50:	48 8d 95 30 a8 f1 ff 	lea    -0xe57d0(%rbp),%rdx
    6d57:	48 8d 85 40 d3 f1 ff 	lea    -0xe2cc0(%rbp),%rax
    6d5e:	48 8b bd d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rdi
    6d65:	48 89 c6             	mov    %rax,%rsi
    6d68:	e8 46 11 00 00       	call   7eb3 <m_upper>
    6d6d:	8b 85 04 a8 f1 ff    	mov    -0xe57fc(%rbp),%eax
    6d73:	99                   	cltd
    6d74:	f7 bd ec a7 f1 ff    	idivl  -0xe5814(%rbp)
    6d7a:	89 c7                	mov    %eax,%edi
    6d7c:	8b 85 08 a8 f1 ff    	mov    -0xe57f8(%rbp),%eax
    6d82:	48 98                	cltq
    6d84:	48 8b 95 d0 a7 f1 ff 	mov    -0xe5830(%rbp),%rdx
    6d8b:	48 8d 34 10          	lea    (%rax,%rdx,1),%rsi
    6d8f:	8b 95 f0 a7 f1 ff    	mov    -0xe5810(%rbp),%edx
    6d95:	48 8d 85 30 a8 f1 ff 	lea    -0xe57d0(%rbp),%rax
    6d9c:	89 d1                	mov    %edx,%ecx
    6d9e:	89 fa                	mov    %edi,%edx
    6da0:	48 89 c7             	mov    %rax,%rdi
    6da3:	e8 95 df ff ff       	call   4d3d <pack_m_vecs>
    6da8:	48 8d 85 80 f6 ff ff 	lea    -0x980(%rbp),%rax
    6daf:	be 6e 09 00 00       	mov    $0x96e,%esi
    6db4:	48 89 c7             	mov    %rax,%rdi
    6db7:	e8 35 71 00 00       	call   def1 <mayo_secure_clear>
    6dbc:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6dc3:	8b 50 04             	mov    0x4(%rax),%edx
    6dc6:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6dcd:	8b 40 08             	mov    0x8(%rax),%eax
    6dd0:	29 c2                	sub    %eax,%edx
    6dd2:	48 8b 85 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rax
    6dd9:	8b 40 08             	mov    0x8(%rax),%eax
    6ddc:	0f af c2             	imul   %edx,%eax
    6ddf:	48 8b 95 d8 a7 f1 ff 	mov    -0xe5828(%rbp),%rdx
    6de6:	8b 52 5c             	mov    0x5c(%rdx),%edx
    6de9:	0f af c2             	imul   %edx,%eax
    6dec:	48 98                	cltq
    6dee:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6df5:	00 
    6df6:	48 8b 85 20 a8 f1 ff 	mov    -0xe57e0(%rbp),%rax
    6dfd:	48 89 d6             	mov    %rdx,%rsi
    6e00:	48 89 c7             	mov    %rax,%rdi
    6e03:	e8 e9 70 00 00       	call   def1 <mayo_secure_clear>
    6e08:	48 8d 85 40 d3 f1 ff 	lea    -0xe2cc0(%rbp),%rax
    6e0f:	be 48 51 00 00       	mov    $0x5148,%esi
    6e14:	48 89 c7             	mov    %rax,%rdi
    6e17:	e8 d5 70 00 00       	call   def1 <mayo_secure_clear>
    6e1c:	8b 85 e8 a7 f1 ff    	mov    -0xe5818(%rbp),%eax
    6e22:	48 8b 75 f8          	mov    -0x8(%rbp),%rsi
    6e26:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
    6e2d:	00 00 
    6e2f:	74 05                	je     6e36 <mayo_keypair_compact+0x3b2>
    6e31:	e8 9a a3 ff ff       	call   11d0 <__stack_chk_fail@plt>
    6e36:	c9                   	leave
    6e37:	c3                   	ret

0000000000006e38 <mayo_expand_pk>:
    6e38:	f3 0f 1e fa          	endbr64
    6e3c:	55                   	push   %rbp
    6e3d:	48 89 e5             	mov    %rsp,%rbp
    6e40:	48 83 ec 20          	sub    $0x20,%rsp
    6e44:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    6e48:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    6e4c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    6e50:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    6e54:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    6e58:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6e5c:	48 89 ce             	mov    %rcx,%rsi
    6e5f:	48 89 c7             	mov    %rax,%rdi
    6e62:	e8 70 df ff ff       	call   4dd7 <expand_P1_P2>
    6e67:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6e6b:	8b 10                	mov    (%rax),%edx
    6e6d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6e71:	8b 48 08             	mov    0x8(%rax),%ecx
    6e74:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6e78:	8b 40 08             	mov    0x8(%rax),%eax
    6e7b:	83 c0 01             	add    $0x1,%eax
    6e7e:	0f af c1             	imul   %ecx,%eax
    6e81:	89 c1                	mov    %eax,%ecx
    6e83:	c1 e9 1f             	shr    $0x1f,%ecx
    6e86:	01 c8                	add    %ecx,%eax
    6e88:	d1 f8                	sar    $1,%eax
    6e8a:	89 c7                	mov    %eax,%edi
    6e8c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6e90:	8b 48 04             	mov    0x4(%rax),%ecx
    6e93:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6e97:	8b 40 08             	mov    0x8(%rax),%eax
    6e9a:	29 c1                	sub    %eax,%ecx
    6e9c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ea0:	8b 70 04             	mov    0x4(%rax),%esi
    6ea3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ea7:	8b 40 08             	mov    0x8(%rax),%eax
    6eaa:	29 c6                	sub    %eax,%esi
    6eac:	89 f0                	mov    %esi,%eax
    6eae:	83 c0 01             	add    $0x1,%eax
    6eb1:	0f af c1             	imul   %ecx,%eax
    6eb4:	89 c1                	mov    %eax,%ecx
    6eb6:	c1 e9 1f             	shr    $0x1f,%ecx
    6eb9:	01 c8                	add    %ecx,%eax
    6ebb:	d1 f8                	sar    $1,%eax
    6ebd:	89 c1                	mov    %eax,%ecx
    6ebf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ec3:	8b 40 5c             	mov    0x5c(%rax),%eax
    6ec6:	0f af c1             	imul   %ecx,%eax
    6ec9:	48 63 c8             	movslq %eax,%rcx
    6ecc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ed0:	8b 70 04             	mov    0x4(%rax),%esi
    6ed3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ed7:	8b 40 08             	mov    0x8(%rax),%eax
    6eda:	29 c6                	sub    %eax,%esi
    6edc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ee0:	8b 40 08             	mov    0x8(%rax),%eax
    6ee3:	0f af c6             	imul   %esi,%eax
    6ee6:	48 8b 75 f8          	mov    -0x8(%rbp),%rsi
    6eea:	8b 76 5c             	mov    0x5c(%rsi),%esi
    6eed:	0f af c6             	imul   %esi,%eax
    6ef0:	48 98                	cltq
    6ef2:	48 01 c8             	add    %rcx,%rax
    6ef5:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    6efc:	00 
    6efd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6f01:	48 8d 34 01          	lea    (%rcx,%rax,1),%rsi
    6f05:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6f09:	8b 40 58             	mov    0x58(%rax),%eax
    6f0c:	48 98                	cltq
    6f0e:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    6f12:	48 01 c8             	add    %rcx,%rax
    6f15:	89 d1                	mov    %edx,%ecx
    6f17:	89 fa                	mov    %edi,%edx
    6f19:	48 89 c7             	mov    %rax,%rdi
    6f1c:	e8 f8 dc ff ff       	call   4c19 <unpack_m_vecs>
    6f21:	b8 00 00 00 00       	mov    $0x0,%eax
    6f26:	c9                   	leave
    6f27:	c3                   	ret

0000000000006f28 <mayo_verify>:
    6f28:	f3 0f 1e fa          	endbr64
    6f2c:	55                   	push   %rbp
    6f2d:	48 89 e5             	mov    %rsp,%rbp
    6f30:	4c 8d 9c 24 00 00 f2 	lea    -0xe0000(%rsp),%r11
    6f37:	ff 
    6f38:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    6f3f:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    6f44:	4c 39 dc             	cmp    %r11,%rsp
    6f47:	75 ef                	jne    6f38 <mayo_verify+0x10>
    6f49:	48 81 ec a0 03 00 00 	sub    $0x3a0,%rsp
    6f50:	48 89 bd 88 fc f1 ff 	mov    %rdi,-0xe0378(%rbp)
    6f57:	48 89 b5 80 fc f1 ff 	mov    %rsi,-0xe0380(%rbp)
    6f5e:	48 89 95 78 fc f1 ff 	mov    %rdx,-0xe0388(%rbp)
    6f65:	48 89 8d 70 fc f1 ff 	mov    %rcx,-0xe0390(%rbp)
    6f6c:	4c 89 85 68 fc f1 ff 	mov    %r8,-0xe0398(%rbp)
    6f73:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    6f7a:	00 00 
    6f7c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    6f80:	31 c0                	xor    %eax,%eax
    6f82:	48 c7 85 a0 f7 ff ff 	movq   $0x0,-0x860(%rbp)
    6f89:	00 00 00 00 
    6f8d:	48 c7 85 a8 f7 ff ff 	movq   $0x0,-0x858(%rbp)
    6f94:	00 00 00 00 
    6f98:	48 8d 95 b0 f7 ff ff 	lea    -0x850(%rbp),%rdx
    6f9f:	b8 00 00 00 00       	mov    $0x0,%eax
    6fa4:	b9 21 00 00 00       	mov    $0x21,%ecx
    6fa9:	48 89 d7             	mov    %rdx,%rdi
    6fac:	f3 48 ab             	rep stos %rax,(%rdi)
    6faf:	48 89 fa             	mov    %rdi,%rdx
    6fb2:	89 02                	mov    %eax,(%rdx)
    6fb4:	48 83 c2 04          	add    $0x4,%rdx
    6fb8:	48 8d 85 d0 fc f1 ff 	lea    -0xe0330(%rbp),%rax
    6fbf:	ba 80 f9 0d 00       	mov    $0xdf980,%edx
    6fc4:	be 00 00 00 00       	mov    $0x0,%esi
    6fc9:	48 89 c7             	mov    %rax,%rdi
    6fcc:	e8 2f a2 ff ff       	call   1200 <memset@plt>
    6fd1:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    6fd8:	8b 00                	mov    (%rax),%eax
    6fda:	89 85 98 fc f1 ff    	mov    %eax,-0xe0368(%rbp)
    6fe0:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    6fe7:	8b 40 04             	mov    0x4(%rax),%eax
    6fea:	89 85 9c fc f1 ff    	mov    %eax,-0xe0364(%rbp)
    6ff0:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    6ff7:	8b 40 0c             	mov    0xc(%rax),%eax
    6ffa:	89 85 a0 fc f1 ff    	mov    %eax,-0xe0360(%rbp)
    7000:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    7007:	8b 40 20             	mov    0x20(%rax),%eax
    700a:	89 85 a4 fc f1 ff    	mov    %eax,-0xe035c(%rbp)
    7010:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    7017:	8b 40 48             	mov    0x48(%rax),%eax
    701a:	89 85 a8 fc f1 ff    	mov    %eax,-0xe0358(%rbp)
    7020:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    7027:	8b 40 54             	mov    0x54(%rax),%eax
    702a:	89 85 ac fc f1 ff    	mov    %eax,-0xe0354(%rbp)
    7030:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    7037:	8b 40 4c             	mov    0x4c(%rax),%eax
    703a:	89 85 b0 fc f1 ff    	mov    %eax,-0xe0350(%rbp)
    7040:	48 8d 85 d0 fc f1 ff 	lea    -0xe0330(%rbp),%rax
    7047:	48 8b b5 68 fc f1 ff 	mov    -0xe0398(%rbp),%rsi
    704e:	48 8b 8d 88 fc f1 ff 	mov    -0xe0378(%rbp),%rcx
    7055:	48 89 c2             	mov    %rax,%rdx
    7058:	48 89 cf             	mov    %rcx,%rdi
    705b:	e8 d8 fd ff ff       	call   6e38 <mayo_expand_pk>
    7060:	89 85 b4 fc f1 ff    	mov    %eax,-0xe034c(%rbp)
    7066:	83 bd b4 fc f1 ff 00 	cmpl   $0x0,-0xe034c(%rbp)
    706d:	74 0a                	je     7079 <mayo_verify+0x151>
    706f:	b8 01 00 00 00       	mov    $0x1,%eax
    7074:	e9 0a 02 00 00       	jmp    7283 <mayo_verify+0x35b>
    7079:	48 8d 85 d0 fc f1 ff 	lea    -0xe0330(%rbp),%rax
    7080:	48 89 85 b8 fc f1 ff 	mov    %rax,-0xe0348(%rbp)
    7087:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    708e:	8b 50 04             	mov    0x4(%rax),%edx
    7091:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    7098:	8b 40 08             	mov    0x8(%rax),%eax
    709b:	29 c2                	sub    %eax,%edx
    709d:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    70a4:	8b 48 04             	mov    0x4(%rax),%ecx
    70a7:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    70ae:	8b 40 08             	mov    0x8(%rax),%eax
    70b1:	29 c1                	sub    %eax,%ecx
    70b3:	89 c8                	mov    %ecx,%eax
    70b5:	83 c0 01             	add    $0x1,%eax
    70b8:	0f af c2             	imul   %edx,%eax
    70bb:	89 c2                	mov    %eax,%edx
    70bd:	c1 ea 1f             	shr    $0x1f,%edx
    70c0:	01 d0                	add    %edx,%eax
    70c2:	d1 f8                	sar    $1,%eax
    70c4:	89 c2                	mov    %eax,%edx
    70c6:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    70cd:	8b 40 5c             	mov    0x5c(%rax),%eax
    70d0:	0f af c2             	imul   %edx,%eax
    70d3:	48 98                	cltq
    70d5:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    70dc:	00 
    70dd:	48 8b 85 b8 fc f1 ff 	mov    -0xe0348(%rbp),%rax
    70e4:	48 01 d0             	add    %rdx,%rax
    70e7:	48 89 85 c0 fc f1 ff 	mov    %rax,-0xe0340(%rbp)
    70ee:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    70f5:	8b 50 04             	mov    0x4(%rax),%edx
    70f8:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    70ff:	8b 40 08             	mov    0x8(%rax),%eax
    7102:	29 c2                	sub    %eax,%edx
    7104:	48 8b 85 88 fc f1 ff 	mov    -0xe0378(%rbp),%rax
    710b:	8b 40 08             	mov    0x8(%rax),%eax
    710e:	0f af c2             	imul   %edx,%eax
    7111:	48 8b 95 88 fc f1 ff 	mov    -0xe0378(%rbp),%rdx
    7118:	8b 52 5c             	mov    0x5c(%rdx),%edx
    711b:	0f af c2             	imul   %edx,%eax
    711e:	48 98                	cltq
    7120:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7127:	00 
    7128:	48 8b 85 c0 fc f1 ff 	mov    -0xe0340(%rbp),%rax
    712f:	48 01 d0             	add    %rdx,%rax
    7132:	48 89 85 c8 fc f1 ff 	mov    %rax,-0xe0338(%rbp)
    7139:	8b 85 ac fc f1 ff    	mov    -0xe0354(%rbp),%eax
    713f:	48 63 f0             	movslq %eax,%rsi
    7142:	48 8b 8d 78 fc f1 ff 	mov    -0xe0388(%rbp),%rcx
    7149:	48 8b 95 80 fc f1 ff 	mov    -0xe0380(%rbp),%rdx
    7150:	48 8d 85 a0 f6 ff ff 	lea    -0x960(%rbp),%rax
    7157:	48 89 c7             	mov    %rax,%rdi
    715a:	e8 24 64 00 00       	call   d583 <shake256>
    715f:	8b 85 b0 fc f1 ff    	mov    -0xe0350(%rbp),%eax
    7165:	48 98                	cltq
    7167:	8b 95 a8 fc f1 ff    	mov    -0xe0358(%rbp),%edx
    716d:	48 63 ca             	movslq %edx,%rcx
    7170:	8b 95 b0 fc f1 ff    	mov    -0xe0350(%rbp),%edx
    7176:	48 63 d2             	movslq %edx,%rdx
    7179:	48 29 d1             	sub    %rdx,%rcx
    717c:	48 8b 95 70 fc f1 ff 	mov    -0xe0390(%rbp),%rdx
    7183:	48 8d 34 11          	lea    (%rcx,%rdx,1),%rsi
    7187:	8b 95 ac fc f1 ff    	mov    -0xe0354(%rbp),%edx
    718d:	48 63 d2             	movslq %edx,%rdx
    7190:	48 8d 8d a0 f6 ff ff 	lea    -0x960(%rbp),%rcx
    7197:	48 01 d1             	add    %rdx,%rcx
    719a:	48 89 c2             	mov    %rax,%rdx
    719d:	48 89 cf             	mov    %rcx,%rdi
    71a0:	e8 8b a0 ff ff       	call   1230 <memcpy@plt>
    71a5:	8b 95 ac fc f1 ff    	mov    -0xe0354(%rbp),%edx
    71ab:	8b 85 b0 fc f1 ff    	mov    -0xe0350(%rbp),%eax
    71b1:	01 d0                	add    %edx,%eax
    71b3:	48 63 c8             	movslq %eax,%rcx
    71b6:	8b 85 a4 fc f1 ff    	mov    -0xe035c(%rbp),%eax
    71bc:	48 63 f0             	movslq %eax,%rsi
    71bf:	48 8d 95 a0 f6 ff ff 	lea    -0x960(%rbp),%rdx
    71c6:	48 8d 85 50 f6 ff ff 	lea    -0x9b0(%rbp),%rax
    71cd:	48 89 c7             	mov    %rax,%rdi
    71d0:	e8 ae 63 00 00       	call   d583 <shake256>
    71d5:	8b 95 98 fc f1 ff    	mov    -0xe0368(%rbp),%edx
    71db:	48 8d 8d 10 f7 ff ff 	lea    -0x8f0(%rbp),%rcx
    71e2:	48 8d 85 50 f6 ff ff 	lea    -0x9b0(%rbp),%rax
    71e9:	48 89 ce             	mov    %rcx,%rsi
    71ec:	48 89 c7             	mov    %rax,%rdi
    71ef:	e8 b7 c2 ff ff       	call   34ab <decode>
    71f4:	8b 85 a0 fc f1 ff    	mov    -0xe0360(%rbp),%eax
    71fa:	0f af 85 9c fc f1 ff 	imul   -0xe0364(%rbp),%eax
    7201:	89 c2                	mov    %eax,%edx
    7203:	48 8d 85 c0 f8 ff ff 	lea    -0x740(%rbp),%rax
    720a:	48 8b 8d 70 fc f1 ff 	mov    -0xe0390(%rbp),%rcx
    7211:	48 89 c6             	mov    %rax,%rsi
    7214:	48 89 cf             	mov    %rcx,%rdi
    7217:	e8 8f c2 ff ff       	call   34ab <decode>
    721c:	48 8d b5 a0 f7 ff ff 	lea    -0x860(%rbp),%rsi
    7223:	4c 8b 85 c8 fc f1 ff 	mov    -0xe0338(%rbp),%r8
    722a:	48 8b 8d c0 fc f1 ff 	mov    -0xe0340(%rbp),%rcx
    7231:	48 8b 95 b8 fc f1 ff 	mov    -0xe0348(%rbp),%rdx
    7238:	48 8d 85 c0 f8 ff ff 	lea    -0x740(%rbp),%rax
    723f:	48 8b bd 88 fc f1 ff 	mov    -0xe0378(%rbp),%rdi
    7246:	49 89 f1             	mov    %rsi,%r9
    7249:	48 89 c6             	mov    %rax,%rsi
    724c:	e8 58 dc ff ff       	call   4ea9 <eval_public_map>
    7251:	8b 85 98 fc f1 ff    	mov    -0xe0368(%rbp),%eax
    7257:	48 63 d0             	movslq %eax,%rdx
    725a:	48 8d 8d 10 f7 ff ff 	lea    -0x8f0(%rbp),%rcx
    7261:	48 8d 85 a0 f7 ff ff 	lea    -0x860(%rbp),%rax
    7268:	48 89 ce             	mov    %rcx,%rsi
    726b:	48 89 c7             	mov    %rax,%rdi
    726e:	e8 9d 9f ff ff       	call   1210 <memcmp@plt>
    7273:	85 c0                	test   %eax,%eax
    7275:	75 07                	jne    727e <mayo_verify+0x356>
    7277:	b8 00 00 00 00       	mov    $0x0,%eax
    727c:	eb 05                	jmp    7283 <mayo_verify+0x35b>
    727e:	b8 01 00 00 00       	mov    $0x1,%eax
    7283:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
    7287:	64 48 33 3c 25 28 00 	xor    %fs:0x28,%rdi
    728e:	00 00 
    7290:	74 05                	je     7297 <mayo_verify+0x36f>
    7292:	e8 39 9f ff ff       	call   11d0 <__stack_chk_fail@plt>
    7297:	c9                   	leave
    7298:	c3                   	ret

0000000000007299 <ct_64_is_greater_than>:
    7299:	55                   	push   %rbp
    729a:	48 89 e5             	mov    %rsp,%rbp
    729d:	89 7d ec             	mov    %edi,-0x14(%rbp)
    72a0:	89 75 e8             	mov    %esi,-0x18(%rbp)
    72a3:	8b 45 e8             	mov    -0x18(%rbp),%eax
    72a6:	48 63 d0             	movslq %eax,%rdx
    72a9:	8b 45 ec             	mov    -0x14(%rbp),%eax
    72ac:	48 98                	cltq
    72ae:	48 29 c2             	sub    %rax,%rdx
    72b1:	48 89 d0             	mov    %rdx,%rax
    72b4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    72b8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    72bc:	48 c1 f8 3f          	sar    $0x3f,%rax
    72c0:	5d                   	pop    %rbp
    72c1:	c3                   	ret

00000000000072c2 <ct_compare_64>:
    72c2:	55                   	push   %rbp
    72c3:	48 89 e5             	mov    %rsp,%rbp
    72c6:	89 7d fc             	mov    %edi,-0x4(%rbp)
    72c9:	89 75 f8             	mov    %esi,-0x8(%rbp)
    72cc:	8b 45 fc             	mov    -0x4(%rbp),%eax
    72cf:	33 45 f8             	xor    -0x8(%rbp),%eax
    72d2:	48 98                	cltq
    72d4:	48 f7 d8             	neg    %rax
    72d7:	48 c1 f8 3f          	sar    $0x3f,%rax
    72db:	5d                   	pop    %rbp
    72dc:	c3                   	ret

00000000000072dd <ct_compare_8>:
    72dd:	55                   	push   %rbp
    72de:	48 89 e5             	mov    %rsp,%rbp
    72e1:	89 fa                	mov    %edi,%edx
    72e3:	89 f0                	mov    %esi,%eax
    72e5:	88 55 fc             	mov    %dl,-0x4(%rbp)
    72e8:	88 45 f8             	mov    %al,-0x8(%rbp)
    72eb:	0f b6 45 fc          	movzbl -0x4(%rbp),%eax
    72ef:	32 45 f8             	xor    -0x8(%rbp),%al
    72f2:	0f b6 c0             	movzbl %al,%eax
    72f5:	f7 d8                	neg    %eax
    72f7:	c1 f8 1f             	sar    $0x1f,%eax
    72fa:	5d                   	pop    %rbp
    72fb:	c3                   	ret

00000000000072fc <mul_f>:
    72fc:	55                   	push   %rbp
    72fd:	48 89 e5             	mov    %rsp,%rbp
    7300:	89 fa                	mov    %edi,%edx
    7302:	89 f0                	mov    %esi,%eax
    7304:	88 55 ec             	mov    %dl,-0x14(%rbp)
    7307:	88 45 e8             	mov    %al,-0x18(%rbp)
    730a:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    730e:	83 e0 01             	and    $0x1,%eax
    7311:	89 c2                	mov    %eax,%edx
    7313:	0f b6 45 e8          	movzbl -0x18(%rbp),%eax
    7317:	0f af c2             	imul   %edx,%eax
    731a:	88 45 fd             	mov    %al,-0x3(%rbp)
    731d:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    7321:	83 e0 02             	and    $0x2,%eax
    7324:	f6 65 e8             	mulb   -0x18(%rbp)
    7327:	89 c2                	mov    %eax,%edx
    7329:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    732d:	31 d0                	xor    %edx,%eax
    732f:	88 45 fd             	mov    %al,-0x3(%rbp)
    7332:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    7336:	83 e0 04             	and    $0x4,%eax
    7339:	f6 65 e8             	mulb   -0x18(%rbp)
    733c:	89 c2                	mov    %eax,%edx
    733e:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    7342:	31 d0                	xor    %edx,%eax
    7344:	88 45 fd             	mov    %al,-0x3(%rbp)
    7347:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    734b:	83 e0 08             	and    $0x8,%eax
    734e:	f6 65 e8             	mulb   -0x18(%rbp)
    7351:	89 c2                	mov    %eax,%edx
    7353:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    7357:	31 d0                	xor    %edx,%eax
    7359:	88 45 fd             	mov    %al,-0x3(%rbp)
    735c:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    7360:	83 e0 f0             	and    $0xfffffff0,%eax
    7363:	88 45 fe             	mov    %al,-0x2(%rbp)
    7366:	0f b6 45 fe          	movzbl -0x2(%rbp),%eax
    736a:	c0 e8 04             	shr    $0x4,%al
    736d:	32 45 fd             	xor    -0x3(%rbp),%al
    7370:	89 c2                	mov    %eax,%edx
    7372:	0f b6 45 fe          	movzbl -0x2(%rbp),%eax
    7376:	c0 e8 03             	shr    $0x3,%al
    7379:	31 d0                	xor    %edx,%eax
    737b:	83 e0 0f             	and    $0xf,%eax
    737e:	88 45 ff             	mov    %al,-0x1(%rbp)
    7381:	0f b6 45 ff          	movzbl -0x1(%rbp),%eax
    7385:	5d                   	pop    %rbp
    7386:	c3                   	ret

0000000000007387 <mul_fx8>:
    7387:	55                   	push   %rbp
    7388:	48 89 e5             	mov    %rsp,%rbp
    738b:	89 f8                	mov    %edi,%eax
    738d:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    7391:	88 45 dc             	mov    %al,-0x24(%rbp)
    7394:	0f b6 45 dc          	movzbl -0x24(%rbp),%eax
    7398:	83 e0 01             	and    $0x1,%eax
    739b:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    739f:	48 0f af c2          	imul   %rdx,%rax
    73a3:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    73a7:	0f b6 45 dc          	movzbl -0x24(%rbp),%eax
    73ab:	83 e0 02             	and    $0x2,%eax
    73ae:	48 0f af 45 d0       	imul   -0x30(%rbp),%rax
    73b3:	48 31 45 e8          	xor    %rax,-0x18(%rbp)
    73b7:	0f b6 45 dc          	movzbl -0x24(%rbp),%eax
    73bb:	83 e0 04             	and    $0x4,%eax
    73be:	48 0f af 45 d0       	imul   -0x30(%rbp),%rax
    73c3:	48 31 45 e8          	xor    %rax,-0x18(%rbp)
    73c7:	0f b6 45 dc          	movzbl -0x24(%rbp),%eax
    73cb:	83 e0 08             	and    $0x8,%eax
    73ce:	48 0f af 45 d0       	imul   -0x30(%rbp),%rax
    73d3:	48 31 45 e8          	xor    %rax,-0x18(%rbp)
    73d7:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    73de:	f0 f0 f0 
    73e1:	48 23 45 e8          	and    -0x18(%rbp),%rax
    73e5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    73e9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    73ed:	48 c1 e8 04          	shr    $0x4,%rax
    73f1:	48 33 45 e8          	xor    -0x18(%rbp),%rax
    73f5:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    73f9:	48 c1 ea 03          	shr    $0x3,%rdx
    73fd:	48 31 c2             	xor    %rax,%rdx
    7400:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    7407:	0f 0f 0f 
    740a:	48 21 d0             	and    %rdx,%rax
    740d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    7411:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7415:	5d                   	pop    %rbp
    7416:	c3                   	ret

0000000000007417 <add_f>:
    7417:	55                   	push   %rbp
    7418:	48 89 e5             	mov    %rsp,%rbp
    741b:	89 fa                	mov    %edi,%edx
    741d:	89 f0                	mov    %esi,%eax
    741f:	88 55 fc             	mov    %dl,-0x4(%rbp)
    7422:	88 45 f8             	mov    %al,-0x8(%rbp)
    7425:	0f b6 45 fc          	movzbl -0x4(%rbp),%eax
    7429:	32 45 f8             	xor    -0x8(%rbp),%al
    742c:	5d                   	pop    %rbp
    742d:	c3                   	ret

000000000000742e <sub_f>:
    742e:	55                   	push   %rbp
    742f:	48 89 e5             	mov    %rsp,%rbp
    7432:	89 fa                	mov    %edi,%edx
    7434:	89 f0                	mov    %esi,%eax
    7436:	88 55 fc             	mov    %dl,-0x4(%rbp)
    7439:	88 45 f8             	mov    %al,-0x8(%rbp)
    743c:	0f b6 45 fc          	movzbl -0x4(%rbp),%eax
    7440:	32 45 f8             	xor    -0x8(%rbp),%al
    7443:	5d                   	pop    %rbp
    7444:	c3                   	ret

0000000000007445 <inverse_f>:
    7445:	55                   	push   %rbp
    7446:	48 89 e5             	mov    %rsp,%rbp
    7449:	48 83 ec 18          	sub    $0x18,%rsp
    744d:	89 f8                	mov    %edi,%eax
    744f:	88 45 ec             	mov    %al,-0x14(%rbp)
    7452:	0f b6 55 ec          	movzbl -0x14(%rbp),%edx
    7456:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    745a:	89 d6                	mov    %edx,%esi
    745c:	89 c7                	mov    %eax,%edi
    745e:	e8 99 fe ff ff       	call   72fc <mul_f>
    7463:	88 45 fb             	mov    %al,-0x5(%rbp)
    7466:	0f b6 55 fb          	movzbl -0x5(%rbp),%edx
    746a:	0f b6 45 fb          	movzbl -0x5(%rbp),%eax
    746e:	89 d6                	mov    %edx,%esi
    7470:	89 c7                	mov    %eax,%edi
    7472:	e8 85 fe ff ff       	call   72fc <mul_f>
    7477:	88 45 fc             	mov    %al,-0x4(%rbp)
    747a:	0f b6 55 fc          	movzbl -0x4(%rbp),%edx
    747e:	0f b6 45 fc          	movzbl -0x4(%rbp),%eax
    7482:	89 d6                	mov    %edx,%esi
    7484:	89 c7                	mov    %eax,%edi
    7486:	e8 71 fe ff ff       	call   72fc <mul_f>
    748b:	88 45 fd             	mov    %al,-0x3(%rbp)
    748e:	0f b6 55 fc          	movzbl -0x4(%rbp),%edx
    7492:	0f b6 45 fb          	movzbl -0x5(%rbp),%eax
    7496:	89 d6                	mov    %edx,%esi
    7498:	89 c7                	mov    %eax,%edi
    749a:	e8 5d fe ff ff       	call   72fc <mul_f>
    749f:	88 45 fe             	mov    %al,-0x2(%rbp)
    74a2:	0f b6 55 fe          	movzbl -0x2(%rbp),%edx
    74a6:	0f b6 45 fd          	movzbl -0x3(%rbp),%eax
    74aa:	89 d6                	mov    %edx,%esi
    74ac:	89 c7                	mov    %eax,%edi
    74ae:	e8 49 fe ff ff       	call   72fc <mul_f>
    74b3:	88 45 ff             	mov    %al,-0x1(%rbp)
    74b6:	0f b6 45 ff          	movzbl -0x1(%rbp),%eax
    74ba:	c9                   	leave
    74bb:	c3                   	ret

00000000000074bc <lincomb>:
    74bc:	55                   	push   %rbp
    74bd:	48 89 e5             	mov    %rsp,%rbp
    74c0:	53                   	push   %rbx
    74c1:	48 83 ec 28          	sub    $0x28,%rsp
    74c5:	48 89 7d e0          	mov    %rdi,-0x20(%rbp)
    74c9:	48 89 75 d8          	mov    %rsi,-0x28(%rbp)
    74cd:	89 55 d4             	mov    %edx,-0x2c(%rbp)
    74d0:	89 4d d0             	mov    %ecx,-0x30(%rbp)
    74d3:	c6 45 f3 00          	movb   $0x0,-0xd(%rbp)
    74d7:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    74de:	eb 45                	jmp    7525 <lincomb+0x69>
    74e0:	0f b6 5d f3          	movzbl -0xd(%rbp),%ebx
    74e4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    74e8:	0f b6 00             	movzbl (%rax),%eax
    74eb:	0f b6 d0             	movzbl %al,%edx
    74ee:	8b 45 f4             	mov    -0xc(%rbp),%eax
    74f1:	48 98                	cltq
    74f3:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    74f7:	48 01 c8             	add    %rcx,%rax
    74fa:	0f b6 00             	movzbl (%rax),%eax
    74fd:	0f b6 c0             	movzbl %al,%eax
    7500:	89 d6                	mov    %edx,%esi
    7502:	89 c7                	mov    %eax,%edi
    7504:	e8 f3 fd ff ff       	call   72fc <mul_f>
    7509:	0f b6 c0             	movzbl %al,%eax
    750c:	89 de                	mov    %ebx,%esi
    750e:	89 c7                	mov    %eax,%edi
    7510:	e8 02 ff ff ff       	call   7417 <add_f>
    7515:	88 45 f3             	mov    %al,-0xd(%rbp)
    7518:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    751c:	8b 45 d0             	mov    -0x30(%rbp),%eax
    751f:	48 98                	cltq
    7521:	48 01 45 d8          	add    %rax,-0x28(%rbp)
    7525:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7528:	3b 45 d4             	cmp    -0x2c(%rbp),%eax
    752b:	7c b3                	jl     74e0 <lincomb+0x24>
    752d:	0f b6 45 f3          	movzbl -0xd(%rbp),%eax
    7531:	48 83 c4 28          	add    $0x28,%rsp
    7535:	5b                   	pop    %rbx
    7536:	5d                   	pop    %rbp
    7537:	c3                   	ret

0000000000007538 <mat_mul>:
    7538:	55                   	push   %rbp
    7539:	48 89 e5             	mov    %rsp,%rbp
    753c:	48 83 ec 38          	sub    $0x38,%rsp
    7540:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    7544:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    7548:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    754c:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
    754f:	44 89 45 d0          	mov    %r8d,-0x30(%rbp)
    7553:	44 89 4d cc          	mov    %r9d,-0x34(%rbp)
    7557:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    755e:	eb 4c                	jmp    75ac <mat_mul+0x74>
    7560:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    7567:	eb 2e                	jmp    7597 <mat_mul+0x5f>
    7569:	8b 45 fc             	mov    -0x4(%rbp),%eax
    756c:	48 98                	cltq
    756e:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    7572:	48 8d 34 10          	lea    (%rax,%rdx,1),%rsi
    7576:	8b 4d cc             	mov    -0x34(%rbp),%ecx
    7579:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    757c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    7580:	48 89 c7             	mov    %rax,%rdi
    7583:	e8 34 ff ff ff       	call   74bc <lincomb>
    7588:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    758c:	88 02                	mov    %al,(%rdx)
    758e:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    7592:	48 83 45 d8 01       	addq   $0x1,-0x28(%rbp)
    7597:	8b 45 fc             	mov    -0x4(%rbp),%eax
    759a:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    759d:	7c ca                	jl     7569 <mat_mul+0x31>
    759f:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    75a3:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    75a6:	48 98                	cltq
    75a8:	48 01 45 e8          	add    %rax,-0x18(%rbp)
    75ac:	8b 45 f8             	mov    -0x8(%rbp),%eax
    75af:	3b 45 d0             	cmp    -0x30(%rbp),%eax
    75b2:	7c ac                	jl     7560 <mat_mul+0x28>
    75b4:	90                   	nop
    75b5:	90                   	nop
    75b6:	c9                   	leave
    75b7:	c3                   	ret

00000000000075b8 <mul_table>:
    75b8:	55                   	push   %rbp
    75b9:	48 89 e5             	mov    %rsp,%rbp
    75bc:	89 f8                	mov    %edi,%eax
    75be:	88 45 ec             	mov    %al,-0x14(%rbp)
    75c1:	0f b6 45 ec          	movzbl -0x14(%rbp),%eax
    75c5:	69 c0 01 02 04 08    	imul   $0x8040201,%eax,%eax
    75cb:	89 45 f4             	mov    %eax,-0xc(%rbp)
    75ce:	c7 45 f8 f0 f0 f0 f0 	movl   $0xf0f0f0f0,-0x8(%rbp)
    75d5:	8b 45 f4             	mov    -0xc(%rbp),%eax
    75d8:	23 45 f8             	and    -0x8(%rbp),%eax
    75db:	89 45 fc             	mov    %eax,-0x4(%rbp)
    75de:	8b 45 fc             	mov    -0x4(%rbp),%eax
    75e1:	c1 e8 04             	shr    $0x4,%eax
    75e4:	33 45 f4             	xor    -0xc(%rbp),%eax
    75e7:	8b 55 fc             	mov    -0x4(%rbp),%edx
    75ea:	c1 ea 03             	shr    $0x3,%edx
    75ed:	31 d0                	xor    %edx,%eax
    75ef:	5d                   	pop    %rbp
    75f0:	c3                   	ret

00000000000075f1 <m_vec_copy>:
    75f1:	55                   	push   %rbp
    75f2:	48 89 e5             	mov    %rsp,%rbp
    75f5:	89 7d ec             	mov    %edi,-0x14(%rbp)
    75f8:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    75fc:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    7600:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    7607:	eb 32                	jmp    763b <m_vec_copy+0x4a>
    7609:	8b 45 fc             	mov    -0x4(%rbp),%eax
    760c:	48 98                	cltq
    760e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7615:	00 
    7616:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    761a:	48 01 c2             	add    %rax,%rdx
    761d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7620:	48 98                	cltq
    7622:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    7629:	00 
    762a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    762e:	48 01 c8             	add    %rcx,%rax
    7631:	48 8b 12             	mov    (%rdx),%rdx
    7634:	48 89 10             	mov    %rdx,(%rax)
    7637:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    763b:	8b 45 fc             	mov    -0x4(%rbp),%eax
    763e:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    7641:	7c c6                	jl     7609 <m_vec_copy+0x18>
    7643:	90                   	nop
    7644:	90                   	nop
    7645:	5d                   	pop    %rbp
    7646:	c3                   	ret

0000000000007647 <m_vec_add>:
    7647:	55                   	push   %rbp
    7648:	48 89 e5             	mov    %rsp,%rbp
    764b:	89 7d ec             	mov    %edi,-0x14(%rbp)
    764e:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    7652:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    7656:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    765d:	eb 4c                	jmp    76ab <m_vec_add+0x64>
    765f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7662:	48 98                	cltq
    7664:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    766b:	00 
    766c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    7670:	48 01 d0             	add    %rdx,%rax
    7673:	48 8b 08             	mov    (%rax),%rcx
    7676:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7679:	48 98                	cltq
    767b:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7682:	00 
    7683:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7687:	48 01 d0             	add    %rdx,%rax
    768a:	48 8b 10             	mov    (%rax),%rdx
    768d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7690:	48 98                	cltq
    7692:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    7699:	00 
    769a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    769e:	48 01 f0             	add    %rsi,%rax
    76a1:	48 31 ca             	xor    %rcx,%rdx
    76a4:	48 89 10             	mov    %rdx,(%rax)
    76a7:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    76ab:	8b 45 fc             	mov    -0x4(%rbp),%eax
    76ae:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    76b1:	7c ac                	jl     765f <m_vec_add+0x18>
    76b3:	90                   	nop
    76b4:	90                   	nop
    76b5:	5d                   	pop    %rbp
    76b6:	c3                   	ret

00000000000076b7 <vec_mul_add_u64>:
    76b7:	55                   	push   %rbp
    76b8:	48 89 e5             	mov    %rsp,%rbp
    76bb:	48 83 ec 28          	sub    $0x28,%rsp
    76bf:	89 7d ec             	mov    %edi,-0x14(%rbp)
    76c2:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    76c6:	89 d0                	mov    %edx,%eax
    76c8:	48 89 4d d8          	mov    %rcx,-0x28(%rbp)
    76cc:	88 45 e8             	mov    %al,-0x18(%rbp)
    76cf:	0f b6 45 e8          	movzbl -0x18(%rbp),%eax
    76d3:	89 c7                	mov    %eax,%edi
    76d5:	e8 de fe ff ff       	call   75b8 <mul_table>
    76da:	89 45 f4             	mov    %eax,-0xc(%rbp)
    76dd:	48 b8 11 11 11 11 11 	movabs $0x1111111111111111,%rax
    76e4:	11 11 11 
    76e7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    76eb:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    76f2:	e9 ef 00 00 00       	jmp    77e6 <vec_mul_add_u64+0x12f>
    76f7:	8b 45 f0             	mov    -0x10(%rbp),%eax
    76fa:	48 98                	cltq
    76fc:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7703:	00 
    7704:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    7708:	48 01 d0             	add    %rdx,%rax
    770b:	48 8b 08             	mov    (%rax),%rcx
    770e:	8b 45 f0             	mov    -0x10(%rbp),%eax
    7711:	48 98                	cltq
    7713:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    771a:	00 
    771b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    771f:	48 01 d0             	add    %rdx,%rax
    7722:	48 8b 00             	mov    (%rax),%rax
    7725:	48 23 45 f8          	and    -0x8(%rbp),%rax
    7729:	48 89 c2             	mov    %rax,%rdx
    772c:	8b 45 f4             	mov    -0xc(%rbp),%eax
    772f:	0f b6 c0             	movzbl %al,%eax
    7732:	48 0f af d0          	imul   %rax,%rdx
    7736:	8b 45 f0             	mov    -0x10(%rbp),%eax
    7739:	48 98                	cltq
    773b:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    7742:	00 
    7743:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7747:	48 01 f0             	add    %rsi,%rax
    774a:	48 8b 00             	mov    (%rax),%rax
    774d:	48 d1 e8             	shr    $1,%rax
    7750:	48 23 45 f8          	and    -0x8(%rbp),%rax
    7754:	8b 75 f4             	mov    -0xc(%rbp),%esi
    7757:	c1 ee 08             	shr    $0x8,%esi
    775a:	89 f6                	mov    %esi,%esi
    775c:	83 e6 0f             	and    $0xf,%esi
    775f:	48 0f af c6          	imul   %rsi,%rax
    7763:	48 31 c2             	xor    %rax,%rdx
    7766:	8b 45 f0             	mov    -0x10(%rbp),%eax
    7769:	48 98                	cltq
    776b:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    7772:	00 
    7773:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7777:	48 01 f0             	add    %rsi,%rax
    777a:	48 8b 00             	mov    (%rax),%rax
    777d:	48 c1 e8 02          	shr    $0x2,%rax
    7781:	48 23 45 f8          	and    -0x8(%rbp),%rax
    7785:	8b 75 f4             	mov    -0xc(%rbp),%esi
    7788:	c1 ee 10             	shr    $0x10,%esi
    778b:	89 f6                	mov    %esi,%esi
    778d:	83 e6 0f             	and    $0xf,%esi
    7790:	48 0f af c6          	imul   %rsi,%rax
    7794:	48 31 c2             	xor    %rax,%rdx
    7797:	8b 45 f0             	mov    -0x10(%rbp),%eax
    779a:	48 98                	cltq
    779c:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    77a3:	00 
    77a4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    77a8:	48 01 f0             	add    %rsi,%rax
    77ab:	48 8b 00             	mov    (%rax),%rax
    77ae:	48 c1 e8 03          	shr    $0x3,%rax
    77b2:	48 23 45 f8          	and    -0x8(%rbp),%rax
    77b6:	8b 75 f4             	mov    -0xc(%rbp),%esi
    77b9:	c1 ee 18             	shr    $0x18,%esi
    77bc:	89 f6                	mov    %esi,%esi
    77be:	83 e6 0f             	and    $0xf,%esi
    77c1:	48 0f af c6          	imul   %rsi,%rax
    77c5:	48 31 c2             	xor    %rax,%rdx
    77c8:	8b 45 f0             	mov    -0x10(%rbp),%eax
    77cb:	48 98                	cltq
    77cd:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    77d4:	00 
    77d5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    77d9:	48 01 f0             	add    %rsi,%rax
    77dc:	48 31 ca             	xor    %rcx,%rdx
    77df:	48 89 10             	mov    %rdx,(%rax)
    77e2:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    77e6:	8b 45 f0             	mov    -0x10(%rbp),%eax
    77e9:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    77ec:	0f 8c 05 ff ff ff    	jl     76f7 <vec_mul_add_u64+0x40>
    77f2:	90                   	nop
    77f3:	90                   	nop
    77f4:	c9                   	leave
    77f5:	c3                   	ret

00000000000077f6 <m_extract_element>:
    77f6:	55                   	push   %rbp
    77f7:	48 89 e5             	mov    %rsp,%rbp
    77fa:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    77fe:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    7801:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    7804:	8d 50 0f             	lea    0xf(%rax),%edx
    7807:	85 c0                	test   %eax,%eax
    7809:	0f 48 c2             	cmovs  %edx,%eax
    780c:	c1 f8 04             	sar    $0x4,%eax
    780f:	89 45 f8             	mov    %eax,-0x8(%rbp)
    7812:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    7815:	89 d0                	mov    %edx,%eax
    7817:	c1 f8 1f             	sar    $0x1f,%eax
    781a:	c1 e8 1c             	shr    $0x1c,%eax
    781d:	01 c2                	add    %eax,%edx
    781f:	83 e2 0f             	and    $0xf,%edx
    7822:	29 c2                	sub    %eax,%edx
    7824:	89 d0                	mov    %edx,%eax
    7826:	89 45 fc             	mov    %eax,-0x4(%rbp)
    7829:	8b 45 f8             	mov    -0x8(%rbp),%eax
    782c:	48 98                	cltq
    782e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7835:	00 
    7836:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    783a:	48 01 d0             	add    %rdx,%rax
    783d:	48 8b 10             	mov    (%rax),%rdx
    7840:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7843:	c1 e0 02             	shl    $0x2,%eax
    7846:	89 c1                	mov    %eax,%ecx
    7848:	48 d3 ea             	shr    %cl,%rdx
    784b:	48 89 d0             	mov    %rdx,%rax
    784e:	83 e0 0f             	and    $0xf,%eax
    7851:	5d                   	pop    %rbp
    7852:	c3                   	ret

0000000000007853 <ef_pack_m_vec>:
    7853:	55                   	push   %rbp
    7854:	48 89 e5             	mov    %rsp,%rbp
    7857:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    785b:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    785f:	89 55 dc             	mov    %edx,-0x24(%rbp)
    7862:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7866:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    786a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    7871:	eb 49                	jmp    78bc <ef_pack_m_vec+0x69>
    7873:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7876:	48 98                	cltq
    7878:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    787c:	48 01 d0             	add    %rdx,%rax
    787f:	0f b6 00             	movzbl (%rax),%eax
    7882:	89 c1                	mov    %eax,%ecx
    7884:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7887:	48 98                	cltq
    7889:	48 8d 50 01          	lea    0x1(%rax),%rdx
    788d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    7891:	48 01 d0             	add    %rdx,%rax
    7894:	0f b6 00             	movzbl (%rax),%eax
    7897:	0f b6 c0             	movzbl %al,%eax
    789a:	c1 e0 04             	shl    $0x4,%eax
    789d:	09 c1                	or     %eax,%ecx
    789f:	8b 45 f4             	mov    -0xc(%rbp),%eax
    78a2:	89 c2                	mov    %eax,%edx
    78a4:	c1 ea 1f             	shr    $0x1f,%edx
    78a7:	01 d0                	add    %edx,%eax
    78a9:	d1 f8                	sar    $1,%eax
    78ab:	48 98                	cltq
    78ad:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    78b1:	48 01 d0             	add    %rdx,%rax
    78b4:	89 ca                	mov    %ecx,%edx
    78b6:	88 10                	mov    %dl,(%rax)
    78b8:	83 45 f4 02          	addl   $0x2,-0xc(%rbp)
    78bc:	8b 45 f4             	mov    -0xc(%rbp),%eax
    78bf:	83 c0 01             	add    $0x1,%eax
    78c2:	39 45 dc             	cmp    %eax,-0x24(%rbp)
    78c5:	7f ac                	jg     7873 <ef_pack_m_vec+0x20>
    78c7:	8b 55 dc             	mov    -0x24(%rbp),%edx
    78ca:	89 d0                	mov    %edx,%eax
    78cc:	c1 f8 1f             	sar    $0x1f,%eax
    78cf:	c1 e8 1f             	shr    $0x1f,%eax
    78d2:	01 c2                	add    %eax,%edx
    78d4:	83 e2 01             	and    $0x1,%edx
    78d7:	29 c2                	sub    %eax,%edx
    78d9:	89 d0                	mov    %edx,%eax
    78db:	83 f8 01             	cmp    $0x1,%eax
    78de:	75 27                	jne    7907 <ef_pack_m_vec+0xb4>
    78e0:	8b 45 f4             	mov    -0xc(%rbp),%eax
    78e3:	48 98                	cltq
    78e5:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    78e9:	48 8d 0c 10          	lea    (%rax,%rdx,1),%rcx
    78ed:	8b 45 f4             	mov    -0xc(%rbp),%eax
    78f0:	89 c2                	mov    %eax,%edx
    78f2:	c1 ea 1f             	shr    $0x1f,%edx
    78f5:	01 d0                	add    %edx,%eax
    78f7:	d1 f8                	sar    $1,%eax
    78f9:	48 98                	cltq
    78fb:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    78ff:	48 01 c2             	add    %rax,%rdx
    7902:	0f b6 01             	movzbl (%rcx),%eax
    7905:	88 02                	mov    %al,(%rdx)
    7907:	90                   	nop
    7908:	5d                   	pop    %rbp
    7909:	c3                   	ret

000000000000790a <ef_unpack_m_vec>:
    790a:	55                   	push   %rbp
    790b:	48 89 e5             	mov    %rsp,%rbp
    790e:	89 7d ec             	mov    %edi,-0x14(%rbp)
    7911:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    7915:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    7919:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    791d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    7921:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    7928:	eb 5c                	jmp    7986 <ef_unpack_m_vec+0x7c>
    792a:	8b 45 f4             	mov    -0xc(%rbp),%eax
    792d:	89 c2                	mov    %eax,%edx
    792f:	c1 ea 1f             	shr    $0x1f,%edx
    7932:	01 d0                	add    %edx,%eax
    7934:	d1 f8                	sar    $1,%eax
    7936:	48 98                	cltq
    7938:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    793c:	48 01 d0             	add    %rdx,%rax
    793f:	0f b6 00             	movzbl (%rax),%eax
    7942:	8b 55 f4             	mov    -0xc(%rbp),%edx
    7945:	48 63 d2             	movslq %edx,%rdx
    7948:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    794c:	48 01 ca             	add    %rcx,%rdx
    794f:	83 e0 0f             	and    $0xf,%eax
    7952:	88 02                	mov    %al,(%rdx)
    7954:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7957:	89 c2                	mov    %eax,%edx
    7959:	c1 ea 1f             	shr    $0x1f,%edx
    795c:	01 d0                	add    %edx,%eax
    795e:	d1 f8                	sar    $1,%eax
    7960:	48 98                	cltq
    7962:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    7966:	48 01 d0             	add    %rdx,%rax
    7969:	0f b6 00             	movzbl (%rax),%eax
    796c:	8b 55 f4             	mov    -0xc(%rbp),%edx
    796f:	48 63 d2             	movslq %edx,%rdx
    7972:	48 8d 4a 01          	lea    0x1(%rdx),%rcx
    7976:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    797a:	48 01 ca             	add    %rcx,%rdx
    797d:	c0 e8 04             	shr    $0x4,%al
    7980:	88 02                	mov    %al,(%rdx)
    7982:	83 45 f4 02          	addl   $0x2,-0xc(%rbp)
    7986:	8b 45 ec             	mov    -0x14(%rbp),%eax
    7989:	c1 e0 04             	shl    $0x4,%eax
    798c:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    798f:	7c 99                	jl     792a <ef_unpack_m_vec+0x20>
    7991:	90                   	nop
    7992:	90                   	nop
    7993:	5d                   	pop    %rbp
    7994:	c3                   	ret

0000000000007995 <EF>:
    7995:	55                   	push   %rbp
    7996:	48 89 e5             	mov    %rsp,%rbp
    7999:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
    799d:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    79a4:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    79a9:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    79b0:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    79b5:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    79bc:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    79c1:	48 81 ec 20 0c 00 00 	sub    $0xc20,%rsp
    79c8:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
    79cd:	89 74 24 04          	mov    %esi,0x4(%rsp)
    79d1:	89 14 24             	mov    %edx,(%rsp)
    79d4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    79db:	00 00 
    79dd:	48 89 84 24 18 3c 00 	mov    %rax,0x3c18(%rsp)
    79e4:	00 
    79e5:	31 c0                	xor    %eax,%eax
    79e7:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    79ee:	00 
    79ef:	ba b0 39 00 00       	mov    $0x39b0,%edx
    79f4:	be 00 00 00 00       	mov    $0x0,%esi
    79f9:	48 89 c7             	mov    %rax,%rdi
    79fc:	e8 ff 97 ff ff       	call   1200 <memset@plt>
    7a01:	8b 04 24             	mov    (%rsp),%eax
    7a04:	83 c0 0f             	add    $0xf,%eax
    7a07:	8d 50 0f             	lea    0xf(%rax),%edx
    7a0a:	85 c0                	test   %eax,%eax
    7a0c:	0f 48 c2             	cmovs  %edx,%eax
    7a0f:	c1 f8 04             	sar    $0x4,%eax
    7a12:	89 44 24 4c          	mov    %eax,0x4c(%rsp)
    7a16:	c7 44 24 20 00 00 00 	movl   $0x0,0x20(%rsp)
    7a1d:	00 
    7a1e:	eb 44                	jmp    7a64 <EF+0xcf>
    7a20:	8b 44 24 20          	mov    0x20(%rsp),%eax
    7a24:	0f af 44 24 4c       	imul   0x4c(%rsp),%eax
    7a29:	48 98                	cltq
    7a2b:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7a32:	00 
    7a33:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    7a3a:	00 
    7a3b:	48 8d 0c 10          	lea    (%rax,%rdx,1),%rcx
    7a3f:	8b 44 24 20          	mov    0x20(%rsp),%eax
    7a43:	0f af 04 24          	imul   (%rsp),%eax
    7a47:	48 98                	cltq
    7a49:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
    7a4e:	48 01 d0             	add    %rdx,%rax
    7a51:	8b 14 24             	mov    (%rsp),%edx
    7a54:	48 89 ce             	mov    %rcx,%rsi
    7a57:	48 89 c7             	mov    %rax,%rdi
    7a5a:	e8 f4 fd ff ff       	call   7853 <ef_pack_m_vec>
    7a5f:	83 44 24 20 01       	addl   $0x1,0x20(%rsp)
    7a64:	8b 44 24 20          	mov    0x20(%rsp),%eax
    7a68:	3b 44 24 04          	cmp    0x4(%rsp),%eax
    7a6c:	7c b2                	jl     7a20 <EF+0x8b>
    7a6e:	c7 44 24 24 00 00 00 	movl   $0x0,0x24(%rsp)
    7a75:	00 
    7a76:	c7 44 24 28 00 00 00 	movl   $0x0,0x28(%rsp)
    7a7d:	00 
    7a7e:	e9 22 03 00 00       	jmp    7da5 <EF+0x410>
    7a83:	8b 54 24 28          	mov    0x28(%rsp),%edx
    7a87:	8b 44 24 04          	mov    0x4(%rsp),%eax
    7a8b:	01 d0                	add    %edx,%eax
    7a8d:	2b 04 24             	sub    (%rsp),%eax
    7a90:	ba 00 00 00 00       	mov    $0x0,%edx
    7a95:	85 c0                	test   %eax,%eax
    7a97:	0f 48 c2             	cmovs  %edx,%eax
    7a9a:	89 44 24 50          	mov    %eax,0x50(%rsp)
    7a9e:	8b 44 24 04          	mov    0x4(%rsp),%eax
    7aa2:	3b 44 24 28          	cmp    0x28(%rsp),%eax
    7aa6:	7f 09                	jg     7ab1 <EF+0x11c>
    7aa8:	8b 44 24 04          	mov    0x4(%rsp),%eax
    7aac:	83 e8 01             	sub    $0x1,%eax
    7aaf:	eb 04                	jmp    7ab5 <EF+0x120>
    7ab1:	8b 44 24 28          	mov    0x28(%rsp),%eax
    7ab5:	89 44 24 54          	mov    %eax,0x54(%rsp)
    7ab9:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%rsp)
    7ac0:	00 
    7ac1:	eb 29                	jmp    7aec <EF+0x157>
    7ac3:	8b 44 24 2c          	mov    0x2c(%rsp),%eax
    7ac7:	48 98                	cltq
    7ac9:	48 c7 84 c4 80 00 00 	movq   $0x0,0x80(%rsp,%rax,8)
    7ad0:	00 00 00 00 00 
    7ad5:	8b 44 24 2c          	mov    0x2c(%rsp),%eax
    7ad9:	48 98                	cltq
    7adb:	48 c7 84 c4 00 01 00 	movq   $0x0,0x100(%rsp,%rax,8)
    7ae2:	00 00 00 00 00 
    7ae7:	83 44 24 2c 01       	addl   $0x1,0x2c(%rsp)
    7aec:	8b 44 24 2c          	mov    0x2c(%rsp),%eax
    7af0:	3b 44 24 4c          	cmp    0x4c(%rsp),%eax
    7af4:	7c cd                	jl     7ac3 <EF+0x12e>
    7af6:	c6 44 24 1c 00       	movb   $0x0,0x1c(%rsp)
    7afb:	48 c7 44 24 58 ff ff 	movq   $0xffffffffffffffff,0x58(%rsp)
    7b02:	ff ff 
    7b04:	8b 44 24 50          	mov    0x50(%rsp),%eax
    7b08:	89 44 24 30          	mov    %eax,0x30(%rsp)
    7b0c:	e9 d0 00 00 00       	jmp    7be1 <EF+0x24c>
    7b11:	8b 54 24 24          	mov    0x24(%rsp),%edx
    7b15:	8b 44 24 30          	mov    0x30(%rsp),%eax
    7b19:	89 d6                	mov    %edx,%esi
    7b1b:	89 c7                	mov    %eax,%edi
    7b1d:	e8 a0 f7 ff ff       	call   72c2 <ct_compare_64>
    7b22:	48 f7 d0             	not    %rax
    7b25:	48 89 44 24 70       	mov    %rax,0x70(%rsp)
    7b2a:	8b 54 24 24          	mov    0x24(%rsp),%edx
    7b2e:	8b 44 24 30          	mov    0x30(%rsp),%eax
    7b32:	89 d6                	mov    %edx,%esi
    7b34:	89 c7                	mov    %eax,%edi
    7b36:	e8 5e f7 ff ff       	call   7299 <ct_64_is_greater_than>
    7b3b:	48 89 44 24 78       	mov    %rax,0x78(%rsp)
    7b40:	c7 44 24 34 00 00 00 	movl   $0x0,0x34(%rsp)
    7b47:	00 
    7b48:	eb 55                	jmp    7b9f <EF+0x20a>
    7b4a:	8b 44 24 34          	mov    0x34(%rsp),%eax
    7b4e:	48 98                	cltq
    7b50:	48 8b 8c c4 80 00 00 	mov    0x80(%rsp,%rax,8),%rcx
    7b57:	00 
    7b58:	48 8b 44 24 78       	mov    0x78(%rsp),%rax
    7b5d:	48 23 44 24 58       	and    0x58(%rsp),%rax
    7b62:	48 0b 44 24 70       	or     0x70(%rsp),%rax
    7b67:	48 89 c2             	mov    %rax,%rdx
    7b6a:	8b 44 24 30          	mov    0x30(%rsp),%eax
    7b6e:	0f af 44 24 4c       	imul   0x4c(%rsp),%eax
    7b73:	8b 74 24 34          	mov    0x34(%rsp),%esi
    7b77:	01 f0                	add    %esi,%eax
    7b79:	48 98                	cltq
    7b7b:	48 8b 84 c4 80 01 00 	mov    0x180(%rsp,%rax,8),%rax
    7b82:	00 
    7b83:	48 21 d0             	and    %rdx,%rax
    7b86:	48 31 c1             	xor    %rax,%rcx
    7b89:	48 89 ca             	mov    %rcx,%rdx
    7b8c:	8b 44 24 34          	mov    0x34(%rsp),%eax
    7b90:	48 98                	cltq
    7b92:	48 89 94 c4 80 00 00 	mov    %rdx,0x80(%rsp,%rax,8)
    7b99:	00 
    7b9a:	83 44 24 34 01       	addl   $0x1,0x34(%rsp)
    7b9f:	8b 44 24 34          	mov    0x34(%rsp),%eax
    7ba3:	3b 44 24 4c          	cmp    0x4c(%rsp),%eax
    7ba7:	7c a1                	jl     7b4a <EF+0x1b5>
    7ba9:	8b 54 24 28          	mov    0x28(%rsp),%edx
    7bad:	48 8d 84 24 80 00 00 	lea    0x80(%rsp),%rax
    7bb4:	00 
    7bb5:	89 d6                	mov    %edx,%esi
    7bb7:	48 89 c7             	mov    %rax,%rdi
    7bba:	e8 37 fc ff ff       	call   77f6 <m_extract_element>
    7bbf:	88 44 24 1c          	mov    %al,0x1c(%rsp)
    7bc3:	0f b6 44 24 1c       	movzbl 0x1c(%rsp),%eax
    7bc8:	be 00 00 00 00       	mov    $0x0,%esi
    7bcd:	89 c7                	mov    %eax,%edi
    7bcf:	e8 ee f6 ff ff       	call   72c2 <ct_compare_64>
    7bd4:	48 f7 d0             	not    %rax
    7bd7:	48 89 44 24 58       	mov    %rax,0x58(%rsp)
    7bdc:	83 44 24 30 01       	addl   $0x1,0x30(%rsp)
    7be1:	8b 44 24 54          	mov    0x54(%rsp),%eax
    7be5:	83 c0 20             	add    $0x20,%eax
    7be8:	39 44 24 04          	cmp    %eax,0x4(%rsp)
    7bec:	7f 09                	jg     7bf7 <EF+0x262>
    7bee:	8b 44 24 04          	mov    0x4(%rsp),%eax
    7bf2:	83 e8 01             	sub    $0x1,%eax
    7bf5:	eb 07                	jmp    7bfe <EF+0x269>
    7bf7:	8b 44 24 54          	mov    0x54(%rsp),%eax
    7bfb:	83 c0 20             	add    $0x20,%eax
    7bfe:	3b 44 24 30          	cmp    0x30(%rsp),%eax
    7c02:	0f 8d 09 ff ff ff    	jge    7b11 <EF+0x17c>
    7c08:	0f b6 44 24 1c       	movzbl 0x1c(%rsp),%eax
    7c0d:	89 c7                	mov    %eax,%edi
    7c0f:	e8 31 f8 ff ff       	call   7445 <inverse_f>
    7c14:	88 44 24 1d          	mov    %al,0x1d(%rsp)
    7c18:	0f b6 54 24 1d       	movzbl 0x1d(%rsp),%edx
    7c1d:	48 8d 8c 24 00 01 00 	lea    0x100(%rsp),%rcx
    7c24:	00 
    7c25:	48 8d 84 24 80 00 00 	lea    0x80(%rsp),%rax
    7c2c:	00 
    7c2d:	8b 7c 24 4c          	mov    0x4c(%rsp),%edi
    7c31:	48 89 c6             	mov    %rax,%rsi
    7c34:	e8 7e fa ff ff       	call   76b7 <vec_mul_add_u64>
    7c39:	8b 44 24 50          	mov    0x50(%rsp),%eax
    7c3d:	89 44 24 38          	mov    %eax,0x38(%rsp)
    7c41:	e9 9a 00 00 00       	jmp    7ce0 <EF+0x34b>
    7c46:	8b 54 24 24          	mov    0x24(%rsp),%edx
    7c4a:	8b 44 24 38          	mov    0x38(%rsp),%eax
    7c4e:	89 d6                	mov    %edx,%esi
    7c50:	89 c7                	mov    %eax,%edi
    7c52:	e8 6b f6 ff ff       	call   72c2 <ct_compare_64>
    7c57:	48 0b 44 24 58       	or     0x58(%rsp),%rax
    7c5c:	48 f7 d0             	not    %rax
    7c5f:	48 89 44 24 60       	mov    %rax,0x60(%rsp)
    7c64:	48 8b 44 24 60       	mov    0x60(%rsp),%rax
    7c69:	48 f7 d0             	not    %rax
    7c6c:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
    7c71:	c7 44 24 3c 00 00 00 	movl   $0x0,0x3c(%rsp)
    7c78:	00 
    7c79:	eb 56                	jmp    7cd1 <EF+0x33c>
    7c7b:	8b 44 24 38          	mov    0x38(%rsp),%eax
    7c7f:	0f af 44 24 4c       	imul   0x4c(%rsp),%eax
    7c84:	8b 54 24 3c          	mov    0x3c(%rsp),%edx
    7c88:	01 d0                	add    %edx,%eax
    7c8a:	48 98                	cltq
    7c8c:	48 8b 84 c4 80 01 00 	mov    0x180(%rsp,%rax,8),%rax
    7c93:	00 
    7c94:	48 23 44 24 68       	and    0x68(%rsp),%rax
    7c99:	48 89 c2             	mov    %rax,%rdx
    7c9c:	8b 44 24 3c          	mov    0x3c(%rsp),%eax
    7ca0:	48 98                	cltq
    7ca2:	48 8b 84 c4 00 01 00 	mov    0x100(%rsp,%rax,8),%rax
    7ca9:	00 
    7caa:	48 23 44 24 60       	and    0x60(%rsp),%rax
    7caf:	8b 4c 24 38          	mov    0x38(%rsp),%ecx
    7cb3:	0f af 4c 24 4c       	imul   0x4c(%rsp),%ecx
    7cb8:	8b 74 24 3c          	mov    0x3c(%rsp),%esi
    7cbc:	01 f1                	add    %esi,%ecx
    7cbe:	48 01 c2             	add    %rax,%rdx
    7cc1:	48 63 c1             	movslq %ecx,%rax
    7cc4:	48 89 94 c4 80 01 00 	mov    %rdx,0x180(%rsp,%rax,8)
    7ccb:	00 
    7ccc:	83 44 24 3c 01       	addl   $0x1,0x3c(%rsp)
    7cd1:	8b 44 24 3c          	mov    0x3c(%rsp),%eax
    7cd5:	3b 44 24 4c          	cmp    0x4c(%rsp),%eax
    7cd9:	7c a0                	jl     7c7b <EF+0x2e6>
    7cdb:	83 44 24 38 01       	addl   $0x1,0x38(%rsp)
    7ce0:	8b 44 24 38          	mov    0x38(%rsp),%eax
    7ce4:	3b 44 24 54          	cmp    0x54(%rsp),%eax
    7ce8:	0f 8e 58 ff ff ff    	jle    7c46 <EF+0x2b1>
    7cee:	8b 44 24 50          	mov    0x50(%rsp),%eax
    7cf2:	89 44 24 40          	mov    %eax,0x40(%rsp)
    7cf6:	e9 83 00 00 00       	jmp    7d7e <EF+0x3e9>
    7cfb:	8b 44 24 40          	mov    0x40(%rsp),%eax
    7cff:	3b 44 24 24          	cmp    0x24(%rsp),%eax
    7d03:	0f 9f c0             	setg   %al
    7d06:	88 44 24 1e          	mov    %al,0x1e(%rsp)
    7d0a:	8b 44 24 40          	mov    0x40(%rsp),%eax
    7d0e:	0f af 44 24 4c       	imul   0x4c(%rsp),%eax
    7d13:	48 98                	cltq
    7d15:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7d1c:	00 
    7d1d:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    7d24:	00 
    7d25:	48 01 d0             	add    %rdx,%rax
    7d28:	8b 54 24 28          	mov    0x28(%rsp),%edx
    7d2c:	89 d6                	mov    %edx,%esi
    7d2e:	48 89 c7             	mov    %rax,%rdi
    7d31:	e8 c0 fa ff ff       	call   77f6 <m_extract_element>
    7d36:	88 44 24 1f          	mov    %al,0x1f(%rsp)
    7d3a:	8b 44 24 40          	mov    0x40(%rsp),%eax
    7d3e:	0f af 44 24 4c       	imul   0x4c(%rsp),%eax
    7d43:	48 98                	cltq
    7d45:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7d4c:	00 
    7d4d:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    7d54:	00 
    7d55:	48 8d 0c 10          	lea    (%rax,%rdx,1),%rcx
    7d59:	0f b6 44 24 1e       	movzbl 0x1e(%rsp),%eax
    7d5e:	f6 64 24 1f          	mulb   0x1f(%rsp)
    7d62:	0f b6 d0             	movzbl %al,%edx
    7d65:	48 8d 84 24 00 01 00 	lea    0x100(%rsp),%rax
    7d6c:	00 
    7d6d:	8b 7c 24 4c          	mov    0x4c(%rsp),%edi
    7d71:	48 89 c6             	mov    %rax,%rsi
    7d74:	e8 3e f9 ff ff       	call   76b7 <vec_mul_add_u64>
    7d79:	83 44 24 40 01       	addl   $0x1,0x40(%rsp)
    7d7e:	8b 44 24 40          	mov    0x40(%rsp),%eax
    7d82:	3b 44 24 04          	cmp    0x4(%rsp),%eax
    7d86:	0f 8c 6f ff ff ff    	jl     7cfb <EF+0x366>
    7d8c:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    7d91:	89 c2                	mov    %eax,%edx
    7d93:	8b 44 24 24          	mov    0x24(%rsp),%eax
    7d97:	01 d0                	add    %edx,%eax
    7d99:	83 c0 01             	add    $0x1,%eax
    7d9c:	89 44 24 24          	mov    %eax,0x24(%rsp)
    7da0:	83 44 24 28 01       	addl   $0x1,0x28(%rsp)
    7da5:	8b 44 24 28          	mov    0x28(%rsp),%eax
    7da9:	3b 04 24             	cmp    (%rsp),%eax
    7dac:	0f 8c d1 fc ff ff    	jl     7a83 <EF+0xee>
    7db2:	c7 44 24 44 00 00 00 	movl   $0x0,0x44(%rsp)
    7db9:	00 
    7dba:	eb 7a                	jmp    7e36 <EF+0x4a1>
    7dbc:	8b 44 24 44          	mov    0x44(%rsp),%eax
    7dc0:	0f af 44 24 4c       	imul   0x4c(%rsp),%eax
    7dc5:	48 98                	cltq
    7dc7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7dce:	00 
    7dcf:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    7dd6:	00 
    7dd7:	48 8d 34 10          	lea    (%rax,%rdx,1),%rsi
    7ddb:	48 8d 84 24 30 3b 00 	lea    0x3b30(%rsp),%rax
    7de2:	00 
    7de3:	8b 4c 24 4c          	mov    0x4c(%rsp),%ecx
    7de7:	48 89 c2             	mov    %rax,%rdx
    7dea:	89 cf                	mov    %ecx,%edi
    7dec:	e8 19 fb ff ff       	call   790a <ef_unpack_m_vec>
    7df1:	c7 44 24 48 00 00 00 	movl   $0x0,0x48(%rsp)
    7df8:	00 
    7df9:	eb 2d                	jmp    7e28 <EF+0x493>
    7dfb:	8b 44 24 44          	mov    0x44(%rsp),%eax
    7dff:	0f af 04 24          	imul   (%rsp),%eax
    7e03:	8b 54 24 48          	mov    0x48(%rsp),%edx
    7e07:	01 d0                	add    %edx,%eax
    7e09:	48 98                	cltq
    7e0b:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
    7e10:	48 01 c2             	add    %rax,%rdx
    7e13:	8b 44 24 48          	mov    0x48(%rsp),%eax
    7e17:	48 98                	cltq
    7e19:	0f b6 84 04 30 3b 00 	movzbl 0x3b30(%rsp,%rax,1),%eax
    7e20:	00 
    7e21:	88 02                	mov    %al,(%rdx)
    7e23:	83 44 24 48 01       	addl   $0x1,0x48(%rsp)
    7e28:	8b 44 24 48          	mov    0x48(%rsp),%eax
    7e2c:	3b 04 24             	cmp    (%rsp),%eax
    7e2f:	7c ca                	jl     7dfb <EF+0x466>
    7e31:	83 44 24 44 01       	addl   $0x1,0x44(%rsp)
    7e36:	8b 44 24 44          	mov    0x44(%rsp),%eax
    7e3a:	3b 44 24 04          	cmp    0x4(%rsp),%eax
    7e3e:	0f 8c 78 ff ff ff    	jl     7dbc <EF+0x427>
    7e44:	48 8d 84 24 30 3b 00 	lea    0x3b30(%rsp),%rax
    7e4b:	00 
    7e4c:	be dc 00 00 00       	mov    $0xdc,%esi
    7e51:	48 89 c7             	mov    %rax,%rdi
    7e54:	e8 98 60 00 00       	call   def1 <mayo_secure_clear>
    7e59:	48 8d 84 24 80 00 00 	lea    0x80(%rsp),%rax
    7e60:	00 
    7e61:	be 68 00 00 00       	mov    $0x68,%esi
    7e66:	48 89 c7             	mov    %rax,%rdi
    7e69:	e8 83 60 00 00       	call   def1 <mayo_secure_clear>
    7e6e:	48 8d 84 24 00 01 00 	lea    0x100(%rsp),%rax
    7e75:	00 
    7e76:	be 68 00 00 00       	mov    $0x68,%esi
    7e7b:	48 89 c7             	mov    %rax,%rdi
    7e7e:	e8 6e 60 00 00       	call   def1 <mayo_secure_clear>
    7e83:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    7e8a:	00 
    7e8b:	be b0 39 00 00       	mov    $0x39b0,%esi
    7e90:	48 89 c7             	mov    %rax,%rdi
    7e93:	e8 59 60 00 00       	call   def1 <mayo_secure_clear>
    7e98:	90                   	nop
    7e99:	48 8b 84 24 18 3c 00 	mov    0x3c18(%rsp),%rax
    7ea0:	00 
    7ea1:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    7ea8:	00 00 
    7eaa:	74 05                	je     7eb1 <EF+0x51c>
    7eac:	e8 1f 93 ff ff       	call   11d0 <__stack_chk_fail@plt>
    7eb1:	c9                   	leave
    7eb2:	c3                   	ret

0000000000007eb3 <m_upper>:
    7eb3:	f3 0f 1e fa          	endbr64
    7eb7:	55                   	push   %rbp
    7eb8:	48 89 e5             	mov    %rsp,%rbp
    7ebb:	48 83 ec 30          	sub    $0x30,%rsp
    7ebf:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    7ec3:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    7ec7:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    7ecb:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
    7ece:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    7ed2:	8b 40 5c             	mov    0x5c(%rax),%eax
    7ed5:	89 45 fc             	mov    %eax,-0x4(%rbp)
    7ed8:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    7edf:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    7ee6:	e9 b7 00 00 00       	jmp    7fa2 <m_upper+0xef>
    7eeb:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7eee:	89 45 f8             	mov    %eax,-0x8(%rbp)
    7ef1:	e9 9c 00 00 00       	jmp    7f92 <m_upper+0xdf>
    7ef6:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7ef9:	0f af 45 f0          	imul   -0x10(%rbp),%eax
    7efd:	48 98                	cltq
    7eff:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7f06:	00 
    7f07:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    7f0b:	48 01 c2             	add    %rax,%rdx
    7f0e:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7f11:	0f af 45 d4          	imul   -0x2c(%rbp),%eax
    7f15:	8b 4d f8             	mov    -0x8(%rbp),%ecx
    7f18:	01 c8                	add    %ecx,%eax
    7f1a:	0f af 45 fc          	imul   -0x4(%rbp),%eax
    7f1e:	48 98                	cltq
    7f20:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    7f27:	00 
    7f28:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7f2c:	48 01 c1             	add    %rax,%rcx
    7f2f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7f32:	48 89 ce             	mov    %rcx,%rsi
    7f35:	89 c7                	mov    %eax,%edi
    7f37:	e8 b5 f6 ff ff       	call   75f1 <m_vec_copy>
    7f3c:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7f3f:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    7f42:	74 46                	je     7f8a <m_upper+0xd7>
    7f44:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7f47:	0f af 45 f0          	imul   -0x10(%rbp),%eax
    7f4b:	48 98                	cltq
    7f4d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7f54:	00 
    7f55:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    7f59:	48 01 c2             	add    %rax,%rdx
    7f5c:	8b 45 f8             	mov    -0x8(%rbp),%eax
    7f5f:	0f af 45 d4          	imul   -0x2c(%rbp),%eax
    7f63:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    7f66:	01 c8                	add    %ecx,%eax
    7f68:	0f af 45 fc          	imul   -0x4(%rbp),%eax
    7f6c:	48 98                	cltq
    7f6e:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    7f75:	00 
    7f76:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7f7a:	48 01 c1             	add    %rax,%rcx
    7f7d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    7f80:	48 89 ce             	mov    %rcx,%rsi
    7f83:	89 c7                	mov    %eax,%edi
    7f85:	e8 bd f6 ff ff       	call   7647 <m_vec_add>
    7f8a:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    7f8e:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    7f92:	8b 45 f8             	mov    -0x8(%rbp),%eax
    7f95:	3b 45 d4             	cmp    -0x2c(%rbp),%eax
    7f98:	0f 8c 58 ff ff ff    	jl     7ef6 <m_upper+0x43>
    7f9e:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    7fa2:	8b 45 f4             	mov    -0xc(%rbp),%eax
    7fa5:	3b 45 d4             	cmp    -0x2c(%rbp),%eax
    7fa8:	0f 8c 3d ff ff ff    	jl     7eeb <m_upper+0x38>
    7fae:	90                   	nop
    7faf:	90                   	nop
    7fb0:	c9                   	leave
    7fb1:	c3                   	ret

0000000000007fb2 <sample_solution>:
    7fb2:	f3 0f 1e fa          	endbr64
    7fb6:	55                   	push   %rbp
    7fb7:	48 89 e5             	mov    %rsp,%rbp
    7fba:	53                   	push   %rbx
    7fbb:	48 81 ec 08 01 00 00 	sub    $0x108,%rsp
    7fc2:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
    7fc9:	48 89 b5 10 ff ff ff 	mov    %rsi,-0xf0(%rbp)
    7fd0:	48 89 95 08 ff ff ff 	mov    %rdx,-0xf8(%rbp)
    7fd7:	48 89 8d 00 ff ff ff 	mov    %rcx,-0x100(%rbp)
    7fde:	4c 89 85 f8 fe ff ff 	mov    %r8,-0x108(%rbp)
    7fe5:	44 89 8d f4 fe ff ff 	mov    %r9d,-0x10c(%rbp)
    7fec:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    7ff3:	00 00 
    7ff5:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    7ff9:	31 c0                	xor    %eax,%eax
    7ffb:	c7 85 28 ff ff ff 00 	movl   $0x0,-0xd8(%rbp)
    8002:	00 00 00 
    8005:	eb 31                	jmp    8038 <sample_solution+0x86>
    8007:	8b 85 28 ff ff ff    	mov    -0xd8(%rbp),%eax
    800d:	48 98                	cltq
    800f:	48 8b 95 00 ff ff ff 	mov    -0x100(%rbp),%rdx
    8016:	48 01 d0             	add    %rdx,%rax
    8019:	8b 95 28 ff ff ff    	mov    -0xd8(%rbp),%edx
    801f:	48 63 d2             	movslq %edx,%rdx
    8022:	48 8b 8d f8 fe ff ff 	mov    -0x108(%rbp),%rcx
    8029:	48 01 ca             	add    %rcx,%rdx
    802c:	0f b6 00             	movzbl (%rax),%eax
    802f:	88 02                	mov    %al,(%rdx)
    8031:	83 85 28 ff ff ff 01 	addl   $0x1,-0xd8(%rbp)
    8038:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    803e:	0f af 45 10          	imul   0x10(%rbp),%eax
    8042:	39 85 28 ff ff ff    	cmp    %eax,-0xd8(%rbp)
    8048:	7c bd                	jl     8007 <sample_solution+0x55>
    804a:	c7 85 2c ff ff ff 00 	movl   $0x0,-0xd4(%rbp)
    8051:	00 00 00 
    8054:	eb 38                	jmp    808e <sample_solution+0xdc>
    8056:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    805c:	0f af 45 10          	imul   0x10(%rbp),%eax
    8060:	89 c2                	mov    %eax,%edx
    8062:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    8068:	0f af 45 10          	imul   0x10(%rbp),%eax
    806c:	83 c0 01             	add    $0x1,%eax
    806f:	0f af 85 2c ff ff ff 	imul   -0xd4(%rbp),%eax
    8076:	01 d0                	add    %edx,%eax
    8078:	48 98                	cltq
    807a:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    8081:	48 01 d0             	add    %rdx,%rax
    8084:	c6 00 00             	movb   $0x0,(%rax)
    8087:	83 85 2c ff ff ff 01 	addl   $0x1,-0xd4(%rbp)
    808e:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8094:	3b 45 18             	cmp    0x18(%rbp),%eax
    8097:	7c bd                	jl     8056 <sample_solution+0xa4>
    8099:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    809f:	0f af 45 10          	imul   0x10(%rbp),%eax
    80a3:	8d 50 01             	lea    0x1(%rax),%edx
    80a6:	8b 4d 18             	mov    0x18(%rbp),%ecx
    80a9:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    80b0:	48 8b b5 00 ff ff ff 	mov    -0x100(%rbp),%rsi
    80b7:	48 8b bd 10 ff ff ff 	mov    -0xf0(%rbp),%rdi
    80be:	41 b9 01 00 00 00    	mov    $0x1,%r9d
    80c4:	41 89 c8             	mov    %ecx,%r8d
    80c7:	89 d1                	mov    %edx,%ecx
    80c9:	48 89 c2             	mov    %rax,%rdx
    80cc:	e8 67 f4 ff ff       	call   7538 <mat_mul>
    80d1:	c7 85 30 ff ff ff 00 	movl   $0x0,-0xd0(%rbp)
    80d8:	00 00 00 
    80db:	eb 6d                	jmp    814a <sample_solution+0x198>
    80dd:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    80e3:	48 98                	cltq
    80e5:	0f b6 84 05 50 ff ff 	movzbl -0xb0(%rbp,%rax,1),%eax
    80ec:	ff 
    80ed:	0f b6 d0             	movzbl %al,%edx
    80f0:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    80f6:	48 98                	cltq
    80f8:	48 8b 8d 08 ff ff ff 	mov    -0xf8(%rbp),%rcx
    80ff:	48 01 c8             	add    %rcx,%rax
    8102:	0f b6 00             	movzbl (%rax),%eax
    8105:	0f b6 c0             	movzbl %al,%eax
    8108:	8b 8d f4 fe ff ff    	mov    -0x10c(%rbp),%ecx
    810e:	89 ce                	mov    %ecx,%esi
    8110:	0f af 75 10          	imul   0x10(%rbp),%esi
    8114:	8b 8d f4 fe ff ff    	mov    -0x10c(%rbp),%ecx
    811a:	0f af 4d 10          	imul   0x10(%rbp),%ecx
    811e:	83 c1 01             	add    $0x1,%ecx
    8121:	0f af 8d 30 ff ff ff 	imul   -0xd0(%rbp),%ecx
    8128:	01 f1                	add    %esi,%ecx
    812a:	48 63 c9             	movslq %ecx,%rcx
    812d:	48 8b b5 10 ff ff ff 	mov    -0xf0(%rbp),%rsi
    8134:	48 8d 1c 31          	lea    (%rcx,%rsi,1),%rbx
    8138:	89 d6                	mov    %edx,%esi
    813a:	89 c7                	mov    %eax,%edi
    813c:	e8 ed f2 ff ff       	call   742e <sub_f>
    8141:	88 03                	mov    %al,(%rbx)
    8143:	83 85 30 ff ff ff 01 	addl   $0x1,-0xd0(%rbp)
    814a:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8150:	3b 45 18             	cmp    0x18(%rbp),%eax
    8153:	7c 88                	jl     80dd <sample_solution+0x12b>
    8155:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    815b:	0f af 45 10          	imul   0x10(%rbp),%eax
    815f:	8d 50 01             	lea    0x1(%rax),%edx
    8162:	8b 4d 18             	mov    0x18(%rbp),%ecx
    8165:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    816c:	89 ce                	mov    %ecx,%esi
    816e:	48 89 c7             	mov    %rax,%rdi
    8171:	e8 1f f8 ff ff       	call   7995 <EF>
    8176:	c6 85 25 ff ff ff 00 	movb   $0x0,-0xdb(%rbp)
    817d:	c7 85 34 ff ff ff 00 	movl   $0x0,-0xcc(%rbp)
    8184:	00 00 00 
    8187:	eb 2e                	jmp    81b7 <sample_solution+0x205>
    8189:	8b 45 18             	mov    0x18(%rbp),%eax
    818c:	83 e8 01             	sub    $0x1,%eax
    818f:	0f af 45 20          	imul   0x20(%rbp),%eax
    8193:	8b 95 34 ff ff ff    	mov    -0xcc(%rbp),%edx
    8199:	01 d0                	add    %edx,%eax
    819b:	48 98                	cltq
    819d:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    81a4:	48 01 d0             	add    %rdx,%rax
    81a7:	0f b6 00             	movzbl (%rax),%eax
    81aa:	08 85 25 ff ff ff    	or     %al,-0xdb(%rbp)
    81b0:	83 85 34 ff ff ff 01 	addl   $0x1,-0xcc(%rbp)
    81b7:	8b 45 20             	mov    0x20(%rbp),%eax
    81ba:	83 e8 01             	sub    $0x1,%eax
    81bd:	39 85 34 ff ff ff    	cmp    %eax,-0xcc(%rbp)
    81c3:	7c c4                	jl     8189 <sample_solution+0x1d7>
    81c5:	80 bd 25 ff ff ff 00 	cmpb   $0x0,-0xdb(%rbp)
    81cc:	75 0a                	jne    81d8 <sample_solution+0x226>
    81ce:	b8 00 00 00 00       	mov    $0x0,%eax
    81d3:	e9 cf 05 00 00       	jmp    87a7 <sample_solution+0x7f5>
    81d8:	8b 45 18             	mov    0x18(%rbp),%eax
    81db:	83 e8 01             	sub    $0x1,%eax
    81de:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
    81e4:	e9 ac 05 00 00       	jmp    8795 <sample_solution+0x7e3>
    81e9:	c6 85 24 ff ff ff 00 	movb   $0x0,-0xdc(%rbp)
    81f0:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    81f6:	0f af 45 10          	imul   0x10(%rbp),%eax
    81fa:	89 c1                	mov    %eax,%ecx
    81fc:	8b 45 18             	mov    0x18(%rbp),%eax
    81ff:	2b 85 38 ff ff ff    	sub    -0xc8(%rbp),%eax
    8205:	89 c3                	mov    %eax,%ebx
    8207:	b8 20 00 00 00       	mov    $0x20,%eax
    820c:	99                   	cltd
    820d:	f7 fb                	idiv   %ebx
    820f:	89 c2                	mov    %eax,%edx
    8211:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    8217:	01 d0                	add    %edx,%eax
    8219:	39 c1                	cmp    %eax,%ecx
    821b:	0f 4e c1             	cmovle %ecx,%eax
    821e:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
    8224:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    822a:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    8230:	e9 47 05 00 00       	jmp    877c <sample_solution+0x7ca>
    8235:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    823b:	0f af 45 20          	imul   0x20(%rbp),%eax
    823f:	8b 95 3c ff ff ff    	mov    -0xc4(%rbp),%edx
    8245:	01 d0                	add    %edx,%eax
    8247:	48 98                	cltq
    8249:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    8250:	48 01 d0             	add    %rdx,%rax
    8253:	0f b6 00             	movzbl (%rax),%eax
    8256:	0f b6 c0             	movzbl %al,%eax
    8259:	be 00 00 00 00       	mov    $0x0,%esi
    825e:	89 c7                	mov    %eax,%edi
    8260:	e8 78 f0 ff ff       	call   72dd <ct_compare_8>
    8265:	89 c2                	mov    %eax,%edx
    8267:	0f b6 85 24 ff ff ff 	movzbl -0xdc(%rbp),%eax
    826e:	f7 d0                	not    %eax
    8270:	21 d0                	and    %edx,%eax
    8272:	88 85 26 ff ff ff    	mov    %al,-0xda(%rbp)
    8278:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    827e:	0f af 45 20          	imul   0x20(%rbp),%eax
    8282:	8b 55 20             	mov    0x20(%rbp),%edx
    8285:	01 d0                	add    %edx,%eax
    8287:	48 98                	cltq
    8289:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    828d:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8294:	48 01 d0             	add    %rdx,%rax
    8297:	0f b6 00             	movzbl (%rax),%eax
    829a:	22 85 26 ff ff ff    	and    -0xda(%rbp),%al
    82a0:	88 85 27 ff ff ff    	mov    %al,-0xd9(%rbp)
    82a6:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    82ac:	48 98                	cltq
    82ae:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    82b5:	48 01 d0             	add    %rdx,%rax
    82b8:	0f b6 00             	movzbl (%rax),%eax
    82bb:	8b 95 3c ff ff ff    	mov    -0xc4(%rbp),%edx
    82c1:	48 63 d2             	movslq %edx,%rdx
    82c4:	48 8b 8d f8 fe ff ff 	mov    -0x108(%rbp),%rcx
    82cb:	48 01 ca             	add    %rcx,%rdx
    82ce:	32 85 27 ff ff ff    	xor    -0xd9(%rbp),%al
    82d4:	88 02                	mov    %al,(%rdx)
    82d6:	c7 85 40 ff ff ff 00 	movl   $0x0,-0xc0(%rbp)
    82dd:	00 00 00 
    82e0:	e9 71 04 00 00       	jmp    8756 <sample_solution+0x7a4>
    82e5:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    82eb:	0f af 45 20          	imul   0x20(%rbp),%eax
    82ef:	8b 95 3c ff ff ff    	mov    -0xc4(%rbp),%edx
    82f5:	01 d0                	add    %edx,%eax
    82f7:	48 98                	cltq
    82f9:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    8300:	48 01 d0             	add    %rdx,%rax
    8303:	0f b6 00             	movzbl (%rax),%eax
    8306:	0f b6 d0             	movzbl %al,%edx
    8309:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    830f:	83 c0 01             	add    $0x1,%eax
    8312:	0f af 45 20          	imul   0x20(%rbp),%eax
    8316:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    831c:	01 c8                	add    %ecx,%eax
    831e:	48 98                	cltq
    8320:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    8327:	48 01 c8             	add    %rcx,%rax
    832a:	0f b6 00             	movzbl (%rax),%eax
    832d:	0f b6 c0             	movzbl %al,%eax
    8330:	48 c1 e0 08          	shl    $0x8,%rax
    8334:	48 31 c2             	xor    %rax,%rdx
    8337:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    833d:	83 c0 02             	add    $0x2,%eax
    8340:	0f af 45 20          	imul   0x20(%rbp),%eax
    8344:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    834a:	01 c8                	add    %ecx,%eax
    834c:	48 98                	cltq
    834e:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    8355:	48 01 c8             	add    %rcx,%rax
    8358:	0f b6 00             	movzbl (%rax),%eax
    835b:	0f b6 c0             	movzbl %al,%eax
    835e:	48 c1 e0 10          	shl    $0x10,%rax
    8362:	48 31 c2             	xor    %rax,%rdx
    8365:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    836b:	83 c0 03             	add    $0x3,%eax
    836e:	0f af 45 20          	imul   0x20(%rbp),%eax
    8372:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    8378:	01 c8                	add    %ecx,%eax
    837a:	48 98                	cltq
    837c:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    8383:	48 01 c8             	add    %rcx,%rax
    8386:	0f b6 00             	movzbl (%rax),%eax
    8389:	0f b6 c0             	movzbl %al,%eax
    838c:	48 c1 e0 18          	shl    $0x18,%rax
    8390:	48 31 c2             	xor    %rax,%rdx
    8393:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8399:	83 c0 04             	add    $0x4,%eax
    839c:	0f af 45 20          	imul   0x20(%rbp),%eax
    83a0:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    83a6:	01 c8                	add    %ecx,%eax
    83a8:	48 98                	cltq
    83aa:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    83b1:	48 01 c8             	add    %rcx,%rax
    83b4:	0f b6 00             	movzbl (%rax),%eax
    83b7:	0f b6 c0             	movzbl %al,%eax
    83ba:	48 c1 e0 20          	shl    $0x20,%rax
    83be:	48 31 c2             	xor    %rax,%rdx
    83c1:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    83c7:	83 c0 05             	add    $0x5,%eax
    83ca:	0f af 45 20          	imul   0x20(%rbp),%eax
    83ce:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    83d4:	01 c8                	add    %ecx,%eax
    83d6:	48 98                	cltq
    83d8:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    83df:	48 01 c8             	add    %rcx,%rax
    83e2:	0f b6 00             	movzbl (%rax),%eax
    83e5:	0f b6 c0             	movzbl %al,%eax
    83e8:	48 c1 e0 28          	shl    $0x28,%rax
    83ec:	48 31 c2             	xor    %rax,%rdx
    83ef:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    83f5:	83 c0 06             	add    $0x6,%eax
    83f8:	0f af 45 20          	imul   0x20(%rbp),%eax
    83fc:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    8402:	01 c8                	add    %ecx,%eax
    8404:	48 98                	cltq
    8406:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    840d:	48 01 c8             	add    %rcx,%rax
    8410:	0f b6 00             	movzbl (%rax),%eax
    8413:	0f b6 c0             	movzbl %al,%eax
    8416:	48 c1 e0 30          	shl    $0x30,%rax
    841a:	48 31 c2             	xor    %rax,%rdx
    841d:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8423:	83 c0 07             	add    $0x7,%eax
    8426:	0f af 45 20          	imul   0x20(%rbp),%eax
    842a:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    8430:	01 c8                	add    %ecx,%eax
    8432:	48 98                	cltq
    8434:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    843b:	48 01 c8             	add    %rcx,%rax
    843e:	0f b6 00             	movzbl (%rax),%eax
    8441:	0f b6 c0             	movzbl %al,%eax
    8444:	48 c1 e0 38          	shl    $0x38,%rax
    8448:	48 31 d0             	xor    %rdx,%rax
    844b:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    8452:	0f b6 85 27 ff ff ff 	movzbl -0xd9(%rbp),%eax
    8459:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    8460:	48 89 d6             	mov    %rdx,%rsi
    8463:	89 c7                	mov    %eax,%edi
    8465:	e8 1d ef ff ff       	call   7387 <mul_fx8>
    846a:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    8471:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8477:	0f af 45 20          	imul   0x20(%rbp),%eax
    847b:	8b 55 20             	mov    0x20(%rbp),%edx
    847e:	01 d0                	add    %edx,%eax
    8480:	48 98                	cltq
    8482:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8486:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    848d:	48 01 d0             	add    %rdx,%rax
    8490:	0f b6 08             	movzbl (%rax),%ecx
    8493:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    849a:	83 e0 0f             	and    $0xf,%eax
    849d:	89 c6                	mov    %eax,%esi
    849f:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    84a5:	0f af 45 20          	imul   0x20(%rbp),%eax
    84a9:	8b 55 20             	mov    0x20(%rbp),%edx
    84ac:	01 d0                	add    %edx,%eax
    84ae:	48 98                	cltq
    84b0:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    84b4:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    84bb:	48 01 d0             	add    %rdx,%rax
    84be:	31 f1                	xor    %esi,%ecx
    84c0:	89 ca                	mov    %ecx,%edx
    84c2:	88 10                	mov    %dl,(%rax)
    84c4:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    84ca:	83 c0 01             	add    $0x1,%eax
    84cd:	0f af 45 20          	imul   0x20(%rbp),%eax
    84d1:	8b 55 20             	mov    0x20(%rbp),%edx
    84d4:	01 d0                	add    %edx,%eax
    84d6:	48 98                	cltq
    84d8:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    84dc:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    84e3:	48 01 d0             	add    %rdx,%rax
    84e6:	0f b6 08             	movzbl (%rax),%ecx
    84e9:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    84f0:	48 c1 e8 08          	shr    $0x8,%rax
    84f4:	83 e0 0f             	and    $0xf,%eax
    84f7:	89 c6                	mov    %eax,%esi
    84f9:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    84ff:	83 c0 01             	add    $0x1,%eax
    8502:	0f af 45 20          	imul   0x20(%rbp),%eax
    8506:	8b 55 20             	mov    0x20(%rbp),%edx
    8509:	01 d0                	add    %edx,%eax
    850b:	48 98                	cltq
    850d:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8511:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8518:	48 01 d0             	add    %rdx,%rax
    851b:	31 f1                	xor    %esi,%ecx
    851d:	89 ca                	mov    %ecx,%edx
    851f:	88 10                	mov    %dl,(%rax)
    8521:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8527:	83 c0 02             	add    $0x2,%eax
    852a:	0f af 45 20          	imul   0x20(%rbp),%eax
    852e:	8b 55 20             	mov    0x20(%rbp),%edx
    8531:	01 d0                	add    %edx,%eax
    8533:	48 98                	cltq
    8535:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8539:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8540:	48 01 d0             	add    %rdx,%rax
    8543:	0f b6 08             	movzbl (%rax),%ecx
    8546:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    854d:	48 c1 e8 10          	shr    $0x10,%rax
    8551:	83 e0 0f             	and    $0xf,%eax
    8554:	89 c6                	mov    %eax,%esi
    8556:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    855c:	83 c0 02             	add    $0x2,%eax
    855f:	0f af 45 20          	imul   0x20(%rbp),%eax
    8563:	8b 55 20             	mov    0x20(%rbp),%edx
    8566:	01 d0                	add    %edx,%eax
    8568:	48 98                	cltq
    856a:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    856e:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8575:	48 01 d0             	add    %rdx,%rax
    8578:	31 f1                	xor    %esi,%ecx
    857a:	89 ca                	mov    %ecx,%edx
    857c:	88 10                	mov    %dl,(%rax)
    857e:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8584:	83 c0 03             	add    $0x3,%eax
    8587:	0f af 45 20          	imul   0x20(%rbp),%eax
    858b:	8b 55 20             	mov    0x20(%rbp),%edx
    858e:	01 d0                	add    %edx,%eax
    8590:	48 98                	cltq
    8592:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8596:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    859d:	48 01 d0             	add    %rdx,%rax
    85a0:	0f b6 08             	movzbl (%rax),%ecx
    85a3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    85aa:	48 c1 e8 18          	shr    $0x18,%rax
    85ae:	83 e0 0f             	and    $0xf,%eax
    85b1:	89 c6                	mov    %eax,%esi
    85b3:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    85b9:	83 c0 03             	add    $0x3,%eax
    85bc:	0f af 45 20          	imul   0x20(%rbp),%eax
    85c0:	8b 55 20             	mov    0x20(%rbp),%edx
    85c3:	01 d0                	add    %edx,%eax
    85c5:	48 98                	cltq
    85c7:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    85cb:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    85d2:	48 01 d0             	add    %rdx,%rax
    85d5:	31 f1                	xor    %esi,%ecx
    85d7:	89 ca                	mov    %ecx,%edx
    85d9:	88 10                	mov    %dl,(%rax)
    85db:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    85e1:	83 c0 04             	add    $0x4,%eax
    85e4:	0f af 45 20          	imul   0x20(%rbp),%eax
    85e8:	8b 55 20             	mov    0x20(%rbp),%edx
    85eb:	01 d0                	add    %edx,%eax
    85ed:	48 98                	cltq
    85ef:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    85f3:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    85fa:	48 01 d0             	add    %rdx,%rax
    85fd:	0f b6 08             	movzbl (%rax),%ecx
    8600:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    8607:	48 c1 e8 20          	shr    $0x20,%rax
    860b:	83 e0 0f             	and    $0xf,%eax
    860e:	89 c6                	mov    %eax,%esi
    8610:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8616:	83 c0 04             	add    $0x4,%eax
    8619:	0f af 45 20          	imul   0x20(%rbp),%eax
    861d:	8b 55 20             	mov    0x20(%rbp),%edx
    8620:	01 d0                	add    %edx,%eax
    8622:	48 98                	cltq
    8624:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8628:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    862f:	48 01 d0             	add    %rdx,%rax
    8632:	31 f1                	xor    %esi,%ecx
    8634:	89 ca                	mov    %ecx,%edx
    8636:	88 10                	mov    %dl,(%rax)
    8638:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    863e:	83 c0 05             	add    $0x5,%eax
    8641:	0f af 45 20          	imul   0x20(%rbp),%eax
    8645:	8b 55 20             	mov    0x20(%rbp),%edx
    8648:	01 d0                	add    %edx,%eax
    864a:	48 98                	cltq
    864c:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8650:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8657:	48 01 d0             	add    %rdx,%rax
    865a:	0f b6 08             	movzbl (%rax),%ecx
    865d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    8664:	48 c1 e8 28          	shr    $0x28,%rax
    8668:	83 e0 0f             	and    $0xf,%eax
    866b:	89 c6                	mov    %eax,%esi
    866d:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    8673:	83 c0 05             	add    $0x5,%eax
    8676:	0f af 45 20          	imul   0x20(%rbp),%eax
    867a:	8b 55 20             	mov    0x20(%rbp),%edx
    867d:	01 d0                	add    %edx,%eax
    867f:	48 98                	cltq
    8681:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8685:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    868c:	48 01 d0             	add    %rdx,%rax
    868f:	31 f1                	xor    %esi,%ecx
    8691:	89 ca                	mov    %ecx,%edx
    8693:	88 10                	mov    %dl,(%rax)
    8695:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    869b:	83 c0 06             	add    $0x6,%eax
    869e:	0f af 45 20          	imul   0x20(%rbp),%eax
    86a2:	8b 55 20             	mov    0x20(%rbp),%edx
    86a5:	01 d0                	add    %edx,%eax
    86a7:	48 98                	cltq
    86a9:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    86ad:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    86b4:	48 01 d0             	add    %rdx,%rax
    86b7:	0f b6 08             	movzbl (%rax),%ecx
    86ba:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    86c1:	48 c1 e8 30          	shr    $0x30,%rax
    86c5:	83 e0 0f             	and    $0xf,%eax
    86c8:	89 c6                	mov    %eax,%esi
    86ca:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    86d0:	83 c0 06             	add    $0x6,%eax
    86d3:	0f af 45 20          	imul   0x20(%rbp),%eax
    86d7:	8b 55 20             	mov    0x20(%rbp),%edx
    86da:	01 d0                	add    %edx,%eax
    86dc:	48 98                	cltq
    86de:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    86e2:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    86e9:	48 01 d0             	add    %rdx,%rax
    86ec:	31 f1                	xor    %esi,%ecx
    86ee:	89 ca                	mov    %ecx,%edx
    86f0:	88 10                	mov    %dl,(%rax)
    86f2:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    86f8:	83 c0 07             	add    $0x7,%eax
    86fb:	0f af 45 20          	imul   0x20(%rbp),%eax
    86ff:	8b 55 20             	mov    0x20(%rbp),%edx
    8702:	01 d0                	add    %edx,%eax
    8704:	48 98                	cltq
    8706:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    870a:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8711:	48 01 d0             	add    %rdx,%rax
    8714:	0f b6 08             	movzbl (%rax),%ecx
    8717:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    871e:	48 c1 e8 38          	shr    $0x38,%rax
    8722:	83 e0 0f             	and    $0xf,%eax
    8725:	89 c6                	mov    %eax,%esi
    8727:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    872d:	83 c0 07             	add    $0x7,%eax
    8730:	0f af 45 20          	imul   0x20(%rbp),%eax
    8734:	8b 55 20             	mov    0x20(%rbp),%edx
    8737:	01 d0                	add    %edx,%eax
    8739:	48 98                	cltq
    873b:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    873f:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    8746:	48 01 d0             	add    %rdx,%rax
    8749:	31 f1                	xor    %esi,%ecx
    874b:	89 ca                	mov    %ecx,%edx
    874d:	88 10                	mov    %dl,(%rax)
    874f:	83 85 40 ff ff ff 08 	addl   $0x8,-0xc0(%rbp)
    8756:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    875c:	3b 85 38 ff ff ff    	cmp    -0xc8(%rbp),%eax
    8762:	0f 8c 7d fb ff ff    	jl     82e5 <sample_solution+0x333>
    8768:	0f b6 85 26 ff ff ff 	movzbl -0xda(%rbp),%eax
    876f:	08 85 24 ff ff ff    	or     %al,-0xdc(%rbp)
    8775:	83 85 3c ff ff ff 01 	addl   $0x1,-0xc4(%rbp)
    877c:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    8782:	3b 85 44 ff ff ff    	cmp    -0xbc(%rbp),%eax
    8788:	0f 8e a7 fa ff ff    	jle    8235 <sample_solution+0x283>
    878e:	83 ad 38 ff ff ff 01 	subl   $0x1,-0xc8(%rbp)
    8795:	83 bd 38 ff ff ff 00 	cmpl   $0x0,-0xc8(%rbp)
    879c:	0f 89 47 fa ff ff    	jns    81e9 <sample_solution+0x237>
    87a2:	b8 01 00 00 00       	mov    $0x1,%eax
    87a7:	48 8b 5d e8          	mov    -0x18(%rbp),%rbx
    87ab:	64 48 33 1c 25 28 00 	xor    %fs:0x28,%rbx
    87b2:	00 00 
    87b4:	74 05                	je     87bb <sample_solution+0x809>
    87b6:	e8 15 8a ff ff       	call   11d0 <__stack_chk_fail@plt>
    87bb:	48 81 c4 08 01 00 00 	add    $0x108,%rsp
    87c2:	5b                   	pop    %rbx
    87c3:	5d                   	pop    %rbp
    87c4:	c3                   	ret

00000000000087c5 <randombytes_linux_randombytes_getrandom>:
    87c5:	f3 0f 1e fa          	endbr64
    87c9:	55                   	push   %rbp
    87ca:	48 89 e5             	mov    %rsp,%rbp
    87cd:	48 83 ec 30          	sub    $0x30,%rsp
    87d1:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    87d5:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    87d9:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    87e0:	00 
    87e1:	eb 67                	jmp    884a <randombytes_linux_randombytes_getrandom+0x85>
    87e3:	b8 ff ff ff 01       	mov    $0x1ffffff,%eax
    87e8:	48 81 7d d0 ff ff ff 	cmpq   $0x1ffffff,-0x30(%rbp)
    87ef:	01 
    87f0:	48 0f 46 45 d0       	cmovbe -0x30(%rbp),%rax
    87f5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    87f9:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    87fd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8801:	48 01 d0             	add    %rdx,%rax
    8804:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    8808:	ba 00 00 00 00       	mov    $0x0,%edx
    880d:	48 89 ce             	mov    %rcx,%rsi
    8810:	48 89 c7             	mov    %rax,%rdi
    8813:	e8 78 8a ff ff       	call   1290 <getrandom@plt>
    8818:	89 45 ec             	mov    %eax,-0x14(%rbp)
    881b:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    881f:	75 0c                	jne    882d <randombytes_linux_randombytes_getrandom+0x68>
    8821:	e8 6a 89 ff ff       	call   1190 <__errno_location@plt>
    8826:	8b 00                	mov    (%rax),%eax
    8828:	83 f8 04             	cmp    $0x4,%eax
    882b:	74 cc                	je     87f9 <randombytes_linux_randombytes_getrandom+0x34>
    882d:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    8831:	79 05                	jns    8838 <randombytes_linux_randombytes_getrandom+0x73>
    8833:	8b 45 ec             	mov    -0x14(%rbp),%eax
    8836:	eb 44                	jmp    887c <randombytes_linux_randombytes_getrandom+0xb7>
    8838:	8b 45 ec             	mov    -0x14(%rbp),%eax
    883b:	48 98                	cltq
    883d:	48 01 45 f0          	add    %rax,-0x10(%rbp)
    8841:	8b 45 ec             	mov    -0x14(%rbp),%eax
    8844:	48 98                	cltq
    8846:	48 29 45 d0          	sub    %rax,-0x30(%rbp)
    884a:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    884f:	75 92                	jne    87e3 <randombytes_linux_randombytes_getrandom+0x1e>
    8851:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    8856:	74 1f                	je     8877 <randombytes_linux_randombytes_getrandom+0xb2>
    8858:	48 8d 0d 21 59 00 00 	lea    0x5921(%rip),%rcx        # e180 <__PRETTY_FUNCTION__.4755>
    885f:	ba a5 00 00 00       	mov    $0xa5,%edx
    8864:	48 8d 35 b5 58 00 00 	lea    0x58b5(%rip),%rsi        # e120 <f_tail_142+0x34>
    886b:	48 8d 3d eb 58 00 00 	lea    0x58eb(%rip),%rdi        # e15d <f_tail_142+0x71>
    8872:	e8 79 89 ff ff       	call   11f0 <__assert_fail@plt>
    8877:	b8 00 00 00 00       	mov    $0x0,%eax
    887c:	c9                   	leave
    887d:	c3                   	ret

000000000000887e <randombytes_select>:
    887e:	f3 0f 1e fa          	endbr64
    8882:	55                   	push   %rbp
    8883:	48 89 e5             	mov    %rsp,%rbp
    8886:	48 83 ec 10          	sub    $0x10,%rsp
    888a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    888e:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    8892:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    8896:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    889a:	48 89 d6             	mov    %rdx,%rsi
    889d:	48 89 c7             	mov    %rax,%rdi
    88a0:	e8 20 ff ff ff       	call   87c5 <randombytes_linux_randombytes_getrandom>
    88a5:	c9                   	leave
    88a6:	c3                   	ret

00000000000088a7 <randombytes>:
    88a7:	f3 0f 1e fa          	endbr64
    88ab:	55                   	push   %rbp
    88ac:	48 89 e5             	mov    %rsp,%rbp
    88af:	48 83 ec 20          	sub    $0x20,%rsp
    88b3:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    88b7:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    88bb:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    88bf:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    88c3:	48 89 d6             	mov    %rdx,%rsi
    88c6:	48 89 c7             	mov    %rax,%rdi
    88c9:	e8 b0 ff ff ff       	call   887e <randombytes_select>
    88ce:	89 45 fc             	mov    %eax,-0x4(%rbp)
    88d1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    88d4:	c9                   	leave
    88d5:	c3                   	ret

00000000000088d6 <randombytes_init>:
    88d6:	f3 0f 1e fa          	endbr64
    88da:	55                   	push   %rbp
    88db:	48 89 e5             	mov    %rsp,%rbp
    88de:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    88e2:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    88e6:	89 55 ec             	mov    %edx,-0x14(%rbp)
    88e9:	90                   	nop
    88ea:	5d                   	pop    %rbp
    88eb:	c3                   	ret

00000000000088ec <br_dec32le>:
    88ec:	55                   	push   %rbp
    88ed:	48 89 e5             	mov    %rsp,%rbp
    88f0:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    88f4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    88f8:	0f b6 00             	movzbl (%rax),%eax
    88fb:	0f b6 d0             	movzbl %al,%edx
    88fe:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    8902:	48 83 c0 01          	add    $0x1,%rax
    8906:	0f b6 00             	movzbl (%rax),%eax
    8909:	0f b6 c0             	movzbl %al,%eax
    890c:	c1 e0 08             	shl    $0x8,%eax
    890f:	09 c2                	or     %eax,%edx
    8911:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    8915:	48 83 c0 02          	add    $0x2,%rax
    8919:	0f b6 00             	movzbl (%rax),%eax
    891c:	0f b6 c0             	movzbl %al,%eax
    891f:	c1 e0 10             	shl    $0x10,%eax
    8922:	09 c2                	or     %eax,%edx
    8924:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    8928:	48 83 c0 03          	add    $0x3,%rax
    892c:	0f b6 00             	movzbl (%rax),%eax
    892f:	0f b6 c0             	movzbl %al,%eax
    8932:	c1 e0 18             	shl    $0x18,%eax
    8935:	09 d0                	or     %edx,%eax
    8937:	5d                   	pop    %rbp
    8938:	c3                   	ret

0000000000008939 <br_range_dec32le>:
    8939:	f3 0f 1e fa          	endbr64
    893d:	55                   	push   %rbp
    893e:	48 89 e5             	mov    %rsp,%rbp
    8941:	53                   	push   %rbx
    8942:	48 83 ec 18          	sub    $0x18,%rsp
    8946:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
    894a:	48 89 75 e8          	mov    %rsi,-0x18(%rbp)
    894e:	48 89 55 e0          	mov    %rdx,-0x20(%rbp)
    8952:	eb 1f                	jmp    8973 <br_range_dec32le+0x3a>
    8954:	48 8b 5d f0          	mov    -0x10(%rbp),%rbx
    8958:	48 8d 43 04          	lea    0x4(%rbx),%rax
    895c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    8960:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8964:	48 89 c7             	mov    %rax,%rdi
    8967:	e8 80 ff ff ff       	call   88ec <br_dec32le>
    896c:	89 03                	mov    %eax,(%rbx)
    896e:	48 83 45 e0 04       	addq   $0x4,-0x20(%rbp)
    8973:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8977:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    897b:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    897f:	48 85 c0             	test   %rax,%rax
    8982:	75 d0                	jne    8954 <br_range_dec32le+0x1b>
    8984:	90                   	nop
    8985:	90                   	nop
    8986:	48 83 c4 18          	add    $0x18,%rsp
    898a:	5b                   	pop    %rbx
    898b:	5d                   	pop    %rbp
    898c:	c3                   	ret

000000000000898d <br_swap32>:
    898d:	55                   	push   %rbp
    898e:	48 89 e5             	mov    %rsp,%rbp
    8991:	89 7d fc             	mov    %edi,-0x4(%rbp)
    8994:	8b 45 fc             	mov    -0x4(%rbp),%eax
    8997:	c1 e0 08             	shl    $0x8,%eax
    899a:	25 00 ff 00 ff       	and    $0xff00ff00,%eax
    899f:	89 c2                	mov    %eax,%edx
    89a1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    89a4:	c1 e8 08             	shr    $0x8,%eax
    89a7:	25 ff 00 ff 00       	and    $0xff00ff,%eax
    89ac:	09 d0                	or     %edx,%eax
    89ae:	89 45 fc             	mov    %eax,-0x4(%rbp)
    89b1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    89b4:	c1 c0 10             	rol    $0x10,%eax
    89b7:	5d                   	pop    %rbp
    89b8:	c3                   	ret

00000000000089b9 <br_enc32le>:
    89b9:	55                   	push   %rbp
    89ba:	48 89 e5             	mov    %rsp,%rbp
    89bd:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    89c1:	89 75 f4             	mov    %esi,-0xc(%rbp)
    89c4:	8b 45 f4             	mov    -0xc(%rbp),%eax
    89c7:	89 c2                	mov    %eax,%edx
    89c9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    89cd:	88 10                	mov    %dl,(%rax)
    89cf:	8b 45 f4             	mov    -0xc(%rbp),%eax
    89d2:	c1 e8 08             	shr    $0x8,%eax
    89d5:	89 c2                	mov    %eax,%edx
    89d7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    89db:	48 83 c0 01          	add    $0x1,%rax
    89df:	88 10                	mov    %dl,(%rax)
    89e1:	8b 45 f4             	mov    -0xc(%rbp),%eax
    89e4:	c1 e8 10             	shr    $0x10,%eax
    89e7:	89 c2                	mov    %eax,%edx
    89e9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    89ed:	48 83 c0 02          	add    $0x2,%rax
    89f1:	88 10                	mov    %dl,(%rax)
    89f3:	8b 45 f4             	mov    -0xc(%rbp),%eax
    89f6:	c1 e8 18             	shr    $0x18,%eax
    89f9:	89 c2                	mov    %eax,%edx
    89fb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    89ff:	48 83 c0 03          	add    $0x3,%rax
    8a03:	88 10                	mov    %dl,(%rax)
    8a05:	90                   	nop
    8a06:	5d                   	pop    %rbp
    8a07:	c3                   	ret

0000000000008a08 <br_range_enc32le>:
    8a08:	f3 0f 1e fa          	endbr64
    8a0c:	55                   	push   %rbp
    8a0d:	48 89 e5             	mov    %rsp,%rbp
    8a10:	48 83 ec 18          	sub    $0x18,%rsp
    8a14:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    8a18:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    8a1c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    8a20:	eb 21                	jmp    8a43 <br_range_enc32le+0x3b>
    8a22:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8a26:	48 8d 50 04          	lea    0x4(%rax),%rdx
    8a2a:	48 89 55 f0          	mov    %rdx,-0x10(%rbp)
    8a2e:	8b 10                	mov    (%rax),%edx
    8a30:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    8a34:	89 d6                	mov    %edx,%esi
    8a36:	48 89 c7             	mov    %rax,%rdi
    8a39:	e8 7b ff ff ff       	call   89b9 <br_enc32le>
    8a3e:	48 83 45 f8 04       	addq   $0x4,-0x8(%rbp)
    8a43:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8a47:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    8a4b:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    8a4f:	48 85 c0             	test   %rax,%rax
    8a52:	75 ce                	jne    8a22 <br_range_enc32le+0x1a>
    8a54:	90                   	nop
    8a55:	90                   	nop
    8a56:	c9                   	leave
    8a57:	c3                   	ret

0000000000008a58 <br_aes_ct64_bitslice_Sbox>:
    8a58:	f3 0f 1e fa          	endbr64
    8a5c:	55                   	push   %rbp
    8a5d:	48 89 e5             	mov    %rsp,%rbp
    8a60:	48 81 ec 70 03 00 00 	sub    $0x370,%rsp
    8a67:	48 89 bd 18 fc ff ff 	mov    %rdi,-0x3e8(%rbp)
    8a6e:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8a75:	48 8b 40 38          	mov    0x38(%rax),%rax
    8a79:	48 89 85 28 fc ff ff 	mov    %rax,-0x3d8(%rbp)
    8a80:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8a87:	48 8b 40 30          	mov    0x30(%rax),%rax
    8a8b:	48 89 85 30 fc ff ff 	mov    %rax,-0x3d0(%rbp)
    8a92:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8a99:	48 8b 40 28          	mov    0x28(%rax),%rax
    8a9d:	48 89 85 38 fc ff ff 	mov    %rax,-0x3c8(%rbp)
    8aa4:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8aab:	48 8b 40 20          	mov    0x20(%rax),%rax
    8aaf:	48 89 85 40 fc ff ff 	mov    %rax,-0x3c0(%rbp)
    8ab6:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8abd:	48 8b 40 18          	mov    0x18(%rax),%rax
    8ac1:	48 89 85 48 fc ff ff 	mov    %rax,-0x3b8(%rbp)
    8ac8:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8acf:	48 8b 40 10          	mov    0x10(%rax),%rax
    8ad3:	48 89 85 50 fc ff ff 	mov    %rax,-0x3b0(%rbp)
    8ada:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8ae1:	48 8b 40 08          	mov    0x8(%rax),%rax
    8ae5:	48 89 85 58 fc ff ff 	mov    %rax,-0x3a8(%rbp)
    8aec:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    8af3:	48 8b 00             	mov    (%rax),%rax
    8af6:	48 89 85 60 fc ff ff 	mov    %rax,-0x3a0(%rbp)
    8afd:	48 8b 85 40 fc ff ff 	mov    -0x3c0(%rbp),%rax
    8b04:	48 33 85 50 fc ff ff 	xor    -0x3b0(%rbp),%rax
    8b0b:	48 89 85 68 fc ff ff 	mov    %rax,-0x398(%rbp)
    8b12:	48 8b 85 28 fc ff ff 	mov    -0x3d8(%rbp),%rax
    8b19:	48 33 85 58 fc ff ff 	xor    -0x3a8(%rbp),%rax
    8b20:	48 89 85 70 fc ff ff 	mov    %rax,-0x390(%rbp)
    8b27:	48 8b 85 28 fc ff ff 	mov    -0x3d8(%rbp),%rax
    8b2e:	48 33 85 40 fc ff ff 	xor    -0x3c0(%rbp),%rax
    8b35:	48 89 85 78 fc ff ff 	mov    %rax,-0x388(%rbp)
    8b3c:	48 8b 85 28 fc ff ff 	mov    -0x3d8(%rbp),%rax
    8b43:	48 33 85 50 fc ff ff 	xor    -0x3b0(%rbp),%rax
    8b4a:	48 89 85 80 fc ff ff 	mov    %rax,-0x380(%rbp)
    8b51:	48 8b 85 30 fc ff ff 	mov    -0x3d0(%rbp),%rax
    8b58:	48 33 85 38 fc ff ff 	xor    -0x3c8(%rbp),%rax
    8b5f:	48 89 85 88 fc ff ff 	mov    %rax,-0x378(%rbp)
    8b66:	48 8b 85 88 fc ff ff 	mov    -0x378(%rbp),%rax
    8b6d:	48 33 85 60 fc ff ff 	xor    -0x3a0(%rbp),%rax
    8b74:	48 89 85 90 fc ff ff 	mov    %rax,-0x370(%rbp)
    8b7b:	48 8b 85 90 fc ff ff 	mov    -0x370(%rbp),%rax
    8b82:	48 33 85 40 fc ff ff 	xor    -0x3c0(%rbp),%rax
    8b89:	48 89 85 98 fc ff ff 	mov    %rax,-0x368(%rbp)
    8b90:	48 8b 85 70 fc ff ff 	mov    -0x390(%rbp),%rax
    8b97:	48 33 85 68 fc ff ff 	xor    -0x398(%rbp),%rax
    8b9e:	48 89 85 a0 fc ff ff 	mov    %rax,-0x360(%rbp)
    8ba5:	48 8b 85 90 fc ff ff 	mov    -0x370(%rbp),%rax
    8bac:	48 33 85 28 fc ff ff 	xor    -0x3d8(%rbp),%rax
    8bb3:	48 89 85 a8 fc ff ff 	mov    %rax,-0x358(%rbp)
    8bba:	48 8b 85 90 fc ff ff 	mov    -0x370(%rbp),%rax
    8bc1:	48 33 85 58 fc ff ff 	xor    -0x3a8(%rbp),%rax
    8bc8:	48 89 85 b0 fc ff ff 	mov    %rax,-0x350(%rbp)
    8bcf:	48 8b 85 b0 fc ff ff 	mov    -0x350(%rbp),%rax
    8bd6:	48 33 85 80 fc ff ff 	xor    -0x380(%rbp),%rax
    8bdd:	48 89 85 b8 fc ff ff 	mov    %rax,-0x348(%rbp)
    8be4:	48 8b 85 48 fc ff ff 	mov    -0x3b8(%rbp),%rax
    8beb:	48 33 85 a0 fc ff ff 	xor    -0x360(%rbp),%rax
    8bf2:	48 89 85 c0 fc ff ff 	mov    %rax,-0x340(%rbp)
    8bf9:	48 8b 85 c0 fc ff ff 	mov    -0x340(%rbp),%rax
    8c00:	48 33 85 50 fc ff ff 	xor    -0x3b0(%rbp),%rax
    8c07:	48 89 85 c8 fc ff ff 	mov    %rax,-0x338(%rbp)
    8c0e:	48 8b 85 c0 fc ff ff 	mov    -0x340(%rbp),%rax
    8c15:	48 33 85 30 fc ff ff 	xor    -0x3d0(%rbp),%rax
    8c1c:	48 89 85 d0 fc ff ff 	mov    %rax,-0x330(%rbp)
    8c23:	48 8b 85 c8 fc ff ff 	mov    -0x338(%rbp),%rax
    8c2a:	48 33 85 60 fc ff ff 	xor    -0x3a0(%rbp),%rax
    8c31:	48 89 85 d8 fc ff ff 	mov    %rax,-0x328(%rbp)
    8c38:	48 8b 85 c8 fc ff ff 	mov    -0x338(%rbp),%rax
    8c3f:	48 33 85 88 fc ff ff 	xor    -0x378(%rbp),%rax
    8c46:	48 89 85 e0 fc ff ff 	mov    %rax,-0x320(%rbp)
    8c4d:	48 8b 85 d0 fc ff ff 	mov    -0x330(%rbp),%rax
    8c54:	48 33 85 78 fc ff ff 	xor    -0x388(%rbp),%rax
    8c5b:	48 89 85 e8 fc ff ff 	mov    %rax,-0x318(%rbp)
    8c62:	48 8b 85 60 fc ff ff 	mov    -0x3a0(%rbp),%rax
    8c69:	48 33 85 e8 fc ff ff 	xor    -0x318(%rbp),%rax
    8c70:	48 89 85 f0 fc ff ff 	mov    %rax,-0x310(%rbp)
    8c77:	48 8b 85 e0 fc ff ff 	mov    -0x320(%rbp),%rax
    8c7e:	48 33 85 e8 fc ff ff 	xor    -0x318(%rbp),%rax
    8c85:	48 89 85 f8 fc ff ff 	mov    %rax,-0x308(%rbp)
    8c8c:	48 8b 85 e0 fc ff ff 	mov    -0x320(%rbp),%rax
    8c93:	48 33 85 80 fc ff ff 	xor    -0x380(%rbp),%rax
    8c9a:	48 89 85 00 fd ff ff 	mov    %rax,-0x300(%rbp)
    8ca1:	48 8b 85 88 fc ff ff 	mov    -0x378(%rbp),%rax
    8ca8:	48 33 85 e8 fc ff ff 	xor    -0x318(%rbp),%rax
    8caf:	48 89 85 08 fd ff ff 	mov    %rax,-0x2f8(%rbp)
    8cb6:	48 8b 85 70 fc ff ff 	mov    -0x390(%rbp),%rax
    8cbd:	48 33 85 08 fd ff ff 	xor    -0x2f8(%rbp),%rax
    8cc4:	48 89 85 10 fd ff ff 	mov    %rax,-0x2f0(%rbp)
    8ccb:	48 8b 85 28 fc ff ff 	mov    -0x3d8(%rbp),%rax
    8cd2:	48 33 85 08 fd ff ff 	xor    -0x2f8(%rbp),%rax
    8cd9:	48 89 85 18 fd ff ff 	mov    %rax,-0x2e8(%rbp)
    8ce0:	48 8b 85 a0 fc ff ff 	mov    -0x360(%rbp),%rax
    8ce7:	48 23 85 c8 fc ff ff 	and    -0x338(%rbp),%rax
    8cee:	48 89 85 20 fd ff ff 	mov    %rax,-0x2e0(%rbp)
    8cf5:	48 8b 85 b8 fc ff ff 	mov    -0x348(%rbp),%rax
    8cfc:	48 23 85 d8 fc ff ff 	and    -0x328(%rbp),%rax
    8d03:	48 89 85 28 fd ff ff 	mov    %rax,-0x2d8(%rbp)
    8d0a:	48 8b 85 28 fd ff ff 	mov    -0x2d8(%rbp),%rax
    8d11:	48 33 85 20 fd ff ff 	xor    -0x2e0(%rbp),%rax
    8d18:	48 89 85 30 fd ff ff 	mov    %rax,-0x2d0(%rbp)
    8d1f:	48 8b 85 98 fc ff ff 	mov    -0x368(%rbp),%rax
    8d26:	48 23 85 60 fc ff ff 	and    -0x3a0(%rbp),%rax
    8d2d:	48 89 85 38 fd ff ff 	mov    %rax,-0x2c8(%rbp)
    8d34:	48 8b 85 38 fd ff ff 	mov    -0x2c8(%rbp),%rax
    8d3b:	48 33 85 20 fd ff ff 	xor    -0x2e0(%rbp),%rax
    8d42:	48 89 85 40 fd ff ff 	mov    %rax,-0x2c0(%rbp)
    8d49:	48 8b 85 70 fc ff ff 	mov    -0x390(%rbp),%rax
    8d50:	48 23 85 08 fd ff ff 	and    -0x2f8(%rbp),%rax
    8d57:	48 89 85 48 fd ff ff 	mov    %rax,-0x2b8(%rbp)
    8d5e:	48 8b 85 b0 fc ff ff 	mov    -0x350(%rbp),%rax
    8d65:	48 23 85 90 fc ff ff 	and    -0x370(%rbp),%rax
    8d6c:	48 89 85 50 fd ff ff 	mov    %rax,-0x2b0(%rbp)
    8d73:	48 8b 85 50 fd ff ff 	mov    -0x2b0(%rbp),%rax
    8d7a:	48 33 85 48 fd ff ff 	xor    -0x2b8(%rbp),%rax
    8d81:	48 89 85 58 fd ff ff 	mov    %rax,-0x2a8(%rbp)
    8d88:	48 8b 85 a8 fc ff ff 	mov    -0x358(%rbp),%rax
    8d8f:	48 23 85 f0 fc ff ff 	and    -0x310(%rbp),%rax
    8d96:	48 89 85 60 fd ff ff 	mov    %rax,-0x2a0(%rbp)
    8d9d:	48 8b 85 60 fd ff ff 	mov    -0x2a0(%rbp),%rax
    8da4:	48 33 85 48 fd ff ff 	xor    -0x2b8(%rbp),%rax
    8dab:	48 89 85 68 fd ff ff 	mov    %rax,-0x298(%rbp)
    8db2:	48 8b 85 78 fc ff ff 	mov    -0x388(%rbp),%rax
    8db9:	48 23 85 e8 fc ff ff 	and    -0x318(%rbp),%rax
    8dc0:	48 89 85 70 fd ff ff 	mov    %rax,-0x290(%rbp)
    8dc7:	48 8b 85 68 fc ff ff 	mov    -0x398(%rbp),%rax
    8dce:	48 23 85 f8 fc ff ff 	and    -0x308(%rbp),%rax
    8dd5:	48 89 85 78 fd ff ff 	mov    %rax,-0x288(%rbp)
    8ddc:	48 8b 85 78 fd ff ff 	mov    -0x288(%rbp),%rax
    8de3:	48 33 85 70 fd ff ff 	xor    -0x290(%rbp),%rax
    8dea:	48 89 85 80 fd ff ff 	mov    %rax,-0x280(%rbp)
    8df1:	48 8b 85 80 fc ff ff 	mov    -0x380(%rbp),%rax
    8df8:	48 23 85 e0 fc ff ff 	and    -0x320(%rbp),%rax
    8dff:	48 89 85 88 fd ff ff 	mov    %rax,-0x278(%rbp)
    8e06:	48 8b 85 88 fd ff ff 	mov    -0x278(%rbp),%rax
    8e0d:	48 33 85 70 fd ff ff 	xor    -0x290(%rbp),%rax
    8e14:	48 89 85 90 fd ff ff 	mov    %rax,-0x270(%rbp)
    8e1b:	48 8b 85 30 fd ff ff 	mov    -0x2d0(%rbp),%rax
    8e22:	48 33 85 80 fd ff ff 	xor    -0x280(%rbp),%rax
    8e29:	48 89 85 98 fd ff ff 	mov    %rax,-0x268(%rbp)
    8e30:	48 8b 85 40 fd ff ff 	mov    -0x2c0(%rbp),%rax
    8e37:	48 33 85 90 fd ff ff 	xor    -0x270(%rbp),%rax
    8e3e:	48 89 85 a0 fd ff ff 	mov    %rax,-0x260(%rbp)
    8e45:	48 8b 85 58 fd ff ff 	mov    -0x2a8(%rbp),%rax
    8e4c:	48 33 85 80 fd ff ff 	xor    -0x280(%rbp),%rax
    8e53:	48 89 85 a8 fd ff ff 	mov    %rax,-0x258(%rbp)
    8e5a:	48 8b 85 68 fd ff ff 	mov    -0x298(%rbp),%rax
    8e61:	48 33 85 90 fd ff ff 	xor    -0x270(%rbp),%rax
    8e68:	48 89 85 b0 fd ff ff 	mov    %rax,-0x250(%rbp)
    8e6f:	48 8b 85 98 fd ff ff 	mov    -0x268(%rbp),%rax
    8e76:	48 33 85 d0 fc ff ff 	xor    -0x330(%rbp),%rax
    8e7d:	48 89 85 b8 fd ff ff 	mov    %rax,-0x248(%rbp)
    8e84:	48 8b 85 a0 fd ff ff 	mov    -0x260(%rbp),%rax
    8e8b:	48 33 85 00 fd ff ff 	xor    -0x300(%rbp),%rax
    8e92:	48 89 85 c0 fd ff ff 	mov    %rax,-0x240(%rbp)
    8e99:	48 8b 85 a8 fd ff ff 	mov    -0x258(%rbp),%rax
    8ea0:	48 33 85 10 fd ff ff 	xor    -0x2f0(%rbp),%rax
    8ea7:	48 89 85 c8 fd ff ff 	mov    %rax,-0x238(%rbp)
    8eae:	48 8b 85 b0 fd ff ff 	mov    -0x250(%rbp),%rax
    8eb5:	48 33 85 18 fd ff ff 	xor    -0x2e8(%rbp),%rax
    8ebc:	48 89 85 d0 fd ff ff 	mov    %rax,-0x230(%rbp)
    8ec3:	48 8b 85 b8 fd ff ff 	mov    -0x248(%rbp),%rax
    8eca:	48 33 85 c0 fd ff ff 	xor    -0x240(%rbp),%rax
    8ed1:	48 89 85 d8 fd ff ff 	mov    %rax,-0x228(%rbp)
    8ed8:	48 8b 85 b8 fd ff ff 	mov    -0x248(%rbp),%rax
    8edf:	48 23 85 c8 fd ff ff 	and    -0x238(%rbp),%rax
    8ee6:	48 89 85 e0 fd ff ff 	mov    %rax,-0x220(%rbp)
    8eed:	48 8b 85 d0 fd ff ff 	mov    -0x230(%rbp),%rax
    8ef4:	48 33 85 e0 fd ff ff 	xor    -0x220(%rbp),%rax
    8efb:	48 89 85 e8 fd ff ff 	mov    %rax,-0x218(%rbp)
    8f02:	48 8b 85 d8 fd ff ff 	mov    -0x228(%rbp),%rax
    8f09:	48 23 85 e8 fd ff ff 	and    -0x218(%rbp),%rax
    8f10:	48 89 85 f0 fd ff ff 	mov    %rax,-0x210(%rbp)
    8f17:	48 8b 85 f0 fd ff ff 	mov    -0x210(%rbp),%rax
    8f1e:	48 33 85 c0 fd ff ff 	xor    -0x240(%rbp),%rax
    8f25:	48 89 85 f8 fd ff ff 	mov    %rax,-0x208(%rbp)
    8f2c:	48 8b 85 c8 fd ff ff 	mov    -0x238(%rbp),%rax
    8f33:	48 33 85 d0 fd ff ff 	xor    -0x230(%rbp),%rax
    8f3a:	48 89 85 00 fe ff ff 	mov    %rax,-0x200(%rbp)
    8f41:	48 8b 85 c0 fd ff ff 	mov    -0x240(%rbp),%rax
    8f48:	48 33 85 e0 fd ff ff 	xor    -0x220(%rbp),%rax
    8f4f:	48 89 85 08 fe ff ff 	mov    %rax,-0x1f8(%rbp)
    8f56:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    8f5d:	48 23 85 00 fe ff ff 	and    -0x200(%rbp),%rax
    8f64:	48 89 85 10 fe ff ff 	mov    %rax,-0x1f0(%rbp)
    8f6b:	48 8b 85 10 fe ff ff 	mov    -0x1f0(%rbp),%rax
    8f72:	48 33 85 d0 fd ff ff 	xor    -0x230(%rbp),%rax
    8f79:	48 89 85 18 fe ff ff 	mov    %rax,-0x1e8(%rbp)
    8f80:	48 8b 85 c8 fd ff ff 	mov    -0x238(%rbp),%rax
    8f87:	48 33 85 18 fe ff ff 	xor    -0x1e8(%rbp),%rax
    8f8e:	48 89 85 20 fe ff ff 	mov    %rax,-0x1e0(%rbp)
    8f95:	48 8b 85 e8 fd ff ff 	mov    -0x218(%rbp),%rax
    8f9c:	48 33 85 18 fe ff ff 	xor    -0x1e8(%rbp),%rax
    8fa3:	48 89 85 28 fe ff ff 	mov    %rax,-0x1d8(%rbp)
    8faa:	48 8b 85 d0 fd ff ff 	mov    -0x230(%rbp),%rax
    8fb1:	48 23 85 28 fe ff ff 	and    -0x1d8(%rbp),%rax
    8fb8:	48 89 85 30 fe ff ff 	mov    %rax,-0x1d0(%rbp)
    8fbf:	48 8b 85 30 fe ff ff 	mov    -0x1d0(%rbp),%rax
    8fc6:	48 33 85 20 fe ff ff 	xor    -0x1e0(%rbp),%rax
    8fcd:	48 89 85 38 fe ff ff 	mov    %rax,-0x1c8(%rbp)
    8fd4:	48 8b 85 e8 fd ff ff 	mov    -0x218(%rbp),%rax
    8fdb:	48 33 85 30 fe ff ff 	xor    -0x1d0(%rbp),%rax
    8fe2:	48 89 85 40 fe ff ff 	mov    %rax,-0x1c0(%rbp)
    8fe9:	48 8b 85 f8 fd ff ff 	mov    -0x208(%rbp),%rax
    8ff0:	48 23 85 40 fe ff ff 	and    -0x1c0(%rbp),%rax
    8ff7:	48 89 85 48 fe ff ff 	mov    %rax,-0x1b8(%rbp)
    8ffe:	48 8b 85 d8 fd ff ff 	mov    -0x228(%rbp),%rax
    9005:	48 33 85 48 fe ff ff 	xor    -0x1b8(%rbp),%rax
    900c:	48 89 85 50 fe ff ff 	mov    %rax,-0x1b0(%rbp)
    9013:	48 8b 85 50 fe ff ff 	mov    -0x1b0(%rbp),%rax
    901a:	48 33 85 38 fe ff ff 	xor    -0x1c8(%rbp),%rax
    9021:	48 89 85 58 fe ff ff 	mov    %rax,-0x1a8(%rbp)
    9028:	48 8b 85 f8 fd ff ff 	mov    -0x208(%rbp),%rax
    902f:	48 33 85 18 fe ff ff 	xor    -0x1e8(%rbp),%rax
    9036:	48 89 85 60 fe ff ff 	mov    %rax,-0x1a0(%rbp)
    903d:	48 8b 85 f8 fd ff ff 	mov    -0x208(%rbp),%rax
    9044:	48 33 85 50 fe ff ff 	xor    -0x1b0(%rbp),%rax
    904b:	48 89 85 68 fe ff ff 	mov    %rax,-0x198(%rbp)
    9052:	48 8b 85 18 fe ff ff 	mov    -0x1e8(%rbp),%rax
    9059:	48 33 85 38 fe ff ff 	xor    -0x1c8(%rbp),%rax
    9060:	48 89 85 70 fe ff ff 	mov    %rax,-0x190(%rbp)
    9067:	48 8b 85 60 fe ff ff 	mov    -0x1a0(%rbp),%rax
    906e:	48 33 85 58 fe ff ff 	xor    -0x1a8(%rbp),%rax
    9075:	48 89 85 78 fe ff ff 	mov    %rax,-0x188(%rbp)
    907c:	48 8b 85 70 fe ff ff 	mov    -0x190(%rbp),%rax
    9083:	48 23 85 c8 fc ff ff 	and    -0x338(%rbp),%rax
    908a:	48 89 85 80 fe ff ff 	mov    %rax,-0x180(%rbp)
    9091:	48 8b 85 38 fe ff ff 	mov    -0x1c8(%rbp),%rax
    9098:	48 23 85 d8 fc ff ff 	and    -0x328(%rbp),%rax
    909f:	48 89 85 88 fe ff ff 	mov    %rax,-0x178(%rbp)
    90a6:	48 8b 85 18 fe ff ff 	mov    -0x1e8(%rbp),%rax
    90ad:	48 23 85 60 fc ff ff 	and    -0x3a0(%rbp),%rax
    90b4:	48 89 85 90 fe ff ff 	mov    %rax,-0x170(%rbp)
    90bb:	48 8b 85 68 fe ff ff 	mov    -0x198(%rbp),%rax
    90c2:	48 23 85 08 fd ff ff 	and    -0x2f8(%rbp),%rax
    90c9:	48 89 85 98 fe ff ff 	mov    %rax,-0x168(%rbp)
    90d0:	48 8b 85 50 fe ff ff 	mov    -0x1b0(%rbp),%rax
    90d7:	48 23 85 90 fc ff ff 	and    -0x370(%rbp),%rax
    90de:	48 89 85 a0 fe ff ff 	mov    %rax,-0x160(%rbp)
    90e5:	48 8b 85 f8 fd ff ff 	mov    -0x208(%rbp),%rax
    90ec:	48 23 85 f0 fc ff ff 	and    -0x310(%rbp),%rax
    90f3:	48 89 85 a8 fe ff ff 	mov    %rax,-0x158(%rbp)
    90fa:	48 8b 85 60 fe ff ff 	mov    -0x1a0(%rbp),%rax
    9101:	48 23 85 e8 fc ff ff 	and    -0x318(%rbp),%rax
    9108:	48 89 85 b0 fe ff ff 	mov    %rax,-0x150(%rbp)
    910f:	48 8b 85 78 fe ff ff 	mov    -0x188(%rbp),%rax
    9116:	48 23 85 f8 fc ff ff 	and    -0x308(%rbp),%rax
    911d:	48 89 85 b8 fe ff ff 	mov    %rax,-0x148(%rbp)
    9124:	48 8b 85 58 fe ff ff 	mov    -0x1a8(%rbp),%rax
    912b:	48 23 85 e0 fc ff ff 	and    -0x320(%rbp),%rax
    9132:	48 89 85 c0 fe ff ff 	mov    %rax,-0x140(%rbp)
    9139:	48 8b 85 70 fe ff ff 	mov    -0x190(%rbp),%rax
    9140:	48 23 85 a0 fc ff ff 	and    -0x360(%rbp),%rax
    9147:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
    914e:	48 8b 85 38 fe ff ff 	mov    -0x1c8(%rbp),%rax
    9155:	48 23 85 b8 fc ff ff 	and    -0x348(%rbp),%rax
    915c:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
    9163:	48 8b 85 18 fe ff ff 	mov    -0x1e8(%rbp),%rax
    916a:	48 23 85 98 fc ff ff 	and    -0x368(%rbp),%rax
    9171:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9178:	48 8b 85 68 fe ff ff 	mov    -0x198(%rbp),%rax
    917f:	48 23 85 70 fc ff ff 	and    -0x390(%rbp),%rax
    9186:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    918d:	48 8b 85 50 fe ff ff 	mov    -0x1b0(%rbp),%rax
    9194:	48 23 85 b0 fc ff ff 	and    -0x350(%rbp),%rax
    919b:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    91a2:	48 8b 85 f8 fd ff ff 	mov    -0x208(%rbp),%rax
    91a9:	48 23 85 a8 fc ff ff 	and    -0x358(%rbp),%rax
    91b0:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    91b7:	48 8b 85 60 fe ff ff 	mov    -0x1a0(%rbp),%rax
    91be:	48 23 85 78 fc ff ff 	and    -0x388(%rbp),%rax
    91c5:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    91cc:	48 8b 85 78 fe ff ff 	mov    -0x188(%rbp),%rax
    91d3:	48 23 85 68 fc ff ff 	and    -0x398(%rbp),%rax
    91da:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    91e1:	48 8b 85 58 fe ff ff 	mov    -0x1a8(%rbp),%rax
    91e8:	48 23 85 80 fc ff ff 	and    -0x380(%rbp),%rax
    91ef:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    91f6:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    91fd:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    9204:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    920b:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    9212:	48 33 85 d8 fe ff ff 	xor    -0x128(%rbp),%rax
    9219:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    9220:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
    9227:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    922e:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    9235:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    923c:	48 33 85 d0 fe ff ff 	xor    -0x130(%rbp),%rax
    9243:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
    924a:	48 8b 85 90 fe ff ff 	mov    -0x170(%rbp),%rax
    9251:	48 33 85 e0 fe ff ff 	xor    -0x120(%rbp),%rax
    9258:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
    925f:	48 8b 85 90 fe ff ff 	mov    -0x170(%rbp),%rax
    9266:	48 33 85 a8 fe ff ff 	xor    -0x158(%rbp),%rax
    926d:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    9274:	48 8b 85 b8 fe ff ff 	mov    -0x148(%rbp),%rax
    927b:	48 33 85 c0 fe ff ff 	xor    -0x140(%rbp),%rax
    9282:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    9289:	48 8b 85 80 fe ff ff 	mov    -0x180(%rbp),%rax
    9290:	48 33 85 98 fe ff ff 	xor    -0x168(%rbp),%rax
    9297:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    929e:	48 8b 85 b0 fe ff ff 	mov    -0x150(%rbp),%rax
    92a5:	48 33 85 b8 fe ff ff 	xor    -0x148(%rbp),%rax
    92ac:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    92b3:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    92ba:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    92c1:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    92c8:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    92cf:	48 33 85 20 ff ff ff 	xor    -0xe0(%rbp),%rax
    92d6:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    92dd:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    92e4:	48 33 85 48 ff ff ff 	xor    -0xb8(%rbp),%rax
    92eb:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    92f2:	48 8b 85 a0 fe ff ff 	mov    -0x160(%rbp),%rax
    92f9:	48 33 85 10 ff ff ff 	xor    -0xf0(%rbp),%rax
    9300:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    9307:	48 8b 85 98 fe ff ff 	mov    -0x168(%rbp),%rax
    930e:	48 33 85 50 ff ff ff 	xor    -0xb0(%rbp),%rax
    9315:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    931c:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    9323:	48 33 85 68 ff ff ff 	xor    -0x98(%rbp),%rax
    932a:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    932e:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    9335:	48 33 85 68 ff ff ff 	xor    -0x98(%rbp),%rax
    933c:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    9340:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9347:	48 33 85 70 ff ff ff 	xor    -0x90(%rbp),%rax
    934e:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    9352:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    9359:	48 33 85 70 ff ff ff 	xor    -0x90(%rbp),%rax
    9360:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    9364:	48 8b 85 a0 fe ff ff 	mov    -0x160(%rbp),%rax
    936b:	48 33 85 78 ff ff ff 	xor    -0x88(%rbp),%rax
    9372:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    9376:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    937a:	48 33 45 90          	xor    -0x70(%rbp),%rax
    937e:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    9382:	48 8b 85 88 fe ff ff 	mov    -0x178(%rbp),%rax
    9389:	48 33 45 98          	xor    -0x68(%rbp),%rax
    938d:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    9391:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9398:	48 33 45 98          	xor    -0x68(%rbp),%rax
    939c:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    93a0:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    93a4:	48 33 85 60 ff ff ff 	xor    -0xa0(%rbp),%rax
    93ab:	48 f7 d0             	not    %rax
    93ae:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    93b2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    93b6:	48 33 85 20 ff ff ff 	xor    -0xe0(%rbp),%rax
    93bd:	48 f7 d0             	not    %rax
    93c0:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    93c4:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    93c8:	48 33 45 a8          	xor    -0x58(%rbp),%rax
    93cc:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    93d0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    93d7:	48 33 45 b0          	xor    -0x50(%rbp),%rax
    93db:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    93df:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    93e6:	48 33 45 b0          	xor    -0x50(%rbp),%rax
    93ea:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    93ee:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    93f5:	48 33 45 a8          	xor    -0x58(%rbp),%rax
    93f9:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    93fd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9401:	48 33 45 a0          	xor    -0x60(%rbp),%rax
    9405:	48 f7 d0             	not    %rax
    9408:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    940c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9410:	48 33 85 58 ff ff ff 	xor    -0xa8(%rbp),%rax
    9417:	48 f7 d0             	not    %rax
    941a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    941e:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    9425:	48 83 c0 38          	add    $0x38,%rax
    9429:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    942d:	48 89 10             	mov    %rdx,(%rax)
    9430:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    9437:	48 83 c0 30          	add    $0x30,%rax
    943b:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    943f:	48 89 10             	mov    %rdx,(%rax)
    9442:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    9449:	48 83 c0 28          	add    $0x28,%rax
    944d:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    9451:	48 89 10             	mov    %rdx,(%rax)
    9454:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    945b:	48 83 c0 20          	add    $0x20,%rax
    945f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    9463:	48 89 10             	mov    %rdx,(%rax)
    9466:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    946d:	48 83 c0 18          	add    $0x18,%rax
    9471:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    9475:	48 89 10             	mov    %rdx,(%rax)
    9478:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    947f:	48 83 c0 10          	add    $0x10,%rax
    9483:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    9487:	48 89 10             	mov    %rdx,(%rax)
    948a:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    9491:	48 83 c0 08          	add    $0x8,%rax
    9495:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    9499:	48 89 10             	mov    %rdx,(%rax)
    949c:	48 8b 85 18 fc ff ff 	mov    -0x3e8(%rbp),%rax
    94a3:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    94a7:	48 89 10             	mov    %rdx,(%rax)
    94aa:	90                   	nop
    94ab:	c9                   	leave
    94ac:	c3                   	ret

00000000000094ad <br_aes_ct64_ortho>:
    94ad:	f3 0f 1e fa          	endbr64
    94b1:	55                   	push   %rbp
    94b2:	48 89 e5             	mov    %rsp,%rbp
    94b5:	48 83 ec 50          	sub    $0x50,%rsp
    94b9:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    94c0:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    94c7:	48 8b 00             	mov    (%rax),%rax
    94ca:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    94d1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    94d8:	48 8b 40 08          	mov    0x8(%rax),%rax
    94dc:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    94e3:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    94ea:	55 55 55 
    94ed:	48 23 85 40 ff ff ff 	and    -0xc0(%rbp),%rax
    94f4:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    94fb:	48 8d 0c 12          	lea    (%rdx,%rdx,1),%rcx
    94ff:	48 ba aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rdx
    9506:	aa aa aa 
    9509:	48 21 ca             	and    %rcx,%rdx
    950c:	48 09 c2             	or     %rax,%rdx
    950f:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9516:	48 89 10             	mov    %rdx,(%rax)
    9519:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9520:	48 d1 e8             	shr    $1,%rax
    9523:	48 89 c2             	mov    %rax,%rdx
    9526:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    952d:	55 55 55 
    9530:	48 89 d1             	mov    %rdx,%rcx
    9533:	48 21 c1             	and    %rax,%rcx
    9536:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    953d:	aa aa aa 
    9540:	48 23 85 48 ff ff ff 	and    -0xb8(%rbp),%rax
    9547:	48 89 c2             	mov    %rax,%rdx
    954a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9551:	48 83 c0 08          	add    $0x8,%rax
    9555:	48 09 ca             	or     %rcx,%rdx
    9558:	48 89 10             	mov    %rdx,(%rax)
    955b:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9562:	48 8b 40 10          	mov    0x10(%rax),%rax
    9566:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    956d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9574:	48 8b 40 18          	mov    0x18(%rax),%rax
    9578:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    957f:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    9586:	55 55 55 
    9589:	48 23 85 50 ff ff ff 	and    -0xb0(%rbp),%rax
    9590:	48 89 c2             	mov    %rax,%rdx
    9593:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    959a:	48 8d 0c 00          	lea    (%rax,%rax,1),%rcx
    959e:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    95a5:	aa aa aa 
    95a8:	48 21 c1             	and    %rax,%rcx
    95ab:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    95b2:	48 83 c0 10          	add    $0x10,%rax
    95b6:	48 09 ca             	or     %rcx,%rdx
    95b9:	48 89 10             	mov    %rdx,(%rax)
    95bc:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    95c3:	48 d1 e8             	shr    $1,%rax
    95c6:	48 89 c2             	mov    %rax,%rdx
    95c9:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    95d0:	55 55 55 
    95d3:	48 89 d1             	mov    %rdx,%rcx
    95d6:	48 21 c1             	and    %rax,%rcx
    95d9:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    95e0:	aa aa aa 
    95e3:	48 23 85 58 ff ff ff 	and    -0xa8(%rbp),%rax
    95ea:	48 89 c2             	mov    %rax,%rdx
    95ed:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    95f4:	48 83 c0 18          	add    $0x18,%rax
    95f8:	48 09 ca             	or     %rcx,%rdx
    95fb:	48 89 10             	mov    %rdx,(%rax)
    95fe:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9605:	48 8b 40 20          	mov    0x20(%rax),%rax
    9609:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    9610:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9617:	48 8b 40 28          	mov    0x28(%rax),%rax
    961b:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    9622:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    9629:	55 55 55 
    962c:	48 23 85 60 ff ff ff 	and    -0xa0(%rbp),%rax
    9633:	48 89 c2             	mov    %rax,%rdx
    9636:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    963d:	48 8d 0c 00          	lea    (%rax,%rax,1),%rcx
    9641:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    9648:	aa aa aa 
    964b:	48 21 c1             	and    %rax,%rcx
    964e:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9655:	48 83 c0 20          	add    $0x20,%rax
    9659:	48 09 ca             	or     %rcx,%rdx
    965c:	48 89 10             	mov    %rdx,(%rax)
    965f:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    9666:	48 d1 e8             	shr    $1,%rax
    9669:	48 89 c2             	mov    %rax,%rdx
    966c:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    9673:	55 55 55 
    9676:	48 89 d1             	mov    %rdx,%rcx
    9679:	48 21 c1             	and    %rax,%rcx
    967c:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    9683:	aa aa aa 
    9686:	48 23 85 68 ff ff ff 	and    -0x98(%rbp),%rax
    968d:	48 89 c2             	mov    %rax,%rdx
    9690:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9697:	48 83 c0 28          	add    $0x28,%rax
    969b:	48 09 ca             	or     %rcx,%rdx
    969e:	48 89 10             	mov    %rdx,(%rax)
    96a1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    96a8:	48 8b 40 30          	mov    0x30(%rax),%rax
    96ac:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    96b3:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    96ba:	48 8b 40 38          	mov    0x38(%rax),%rax
    96be:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    96c5:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    96cc:	55 55 55 
    96cf:	48 23 85 70 ff ff ff 	and    -0x90(%rbp),%rax
    96d6:	48 89 c2             	mov    %rax,%rdx
    96d9:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    96e0:	48 8d 0c 00          	lea    (%rax,%rax,1),%rcx
    96e4:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    96eb:	aa aa aa 
    96ee:	48 21 c1             	and    %rax,%rcx
    96f1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    96f8:	48 83 c0 30          	add    $0x30,%rax
    96fc:	48 09 ca             	or     %rcx,%rdx
    96ff:	48 89 10             	mov    %rdx,(%rax)
    9702:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9709:	48 d1 e8             	shr    $1,%rax
    970c:	48 89 c2             	mov    %rax,%rdx
    970f:	48 b8 55 55 55 55 55 	movabs $0x5555555555555555,%rax
    9716:	55 55 55 
    9719:	48 89 d1             	mov    %rdx,%rcx
    971c:	48 21 c1             	and    %rax,%rcx
    971f:	48 b8 aa aa aa aa aa 	movabs $0xaaaaaaaaaaaaaaaa,%rax
    9726:	aa aa aa 
    9729:	48 23 85 78 ff ff ff 	and    -0x88(%rbp),%rax
    9730:	48 89 c2             	mov    %rax,%rdx
    9733:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    973a:	48 83 c0 38          	add    $0x38,%rax
    973e:	48 09 ca             	or     %rcx,%rdx
    9741:	48 89 10             	mov    %rdx,(%rax)
    9744:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    974b:	48 8b 00             	mov    (%rax),%rax
    974e:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    9752:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9759:	48 8b 40 10          	mov    0x10(%rax),%rax
    975d:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    9761:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    9768:	33 33 33 
    976b:	48 23 45 80          	and    -0x80(%rbp),%rax
    976f:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    9773:	48 8d 0c 95 00 00 00 	lea    0x0(,%rdx,4),%rcx
    977a:	00 
    977b:	48 ba cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rdx
    9782:	cc cc cc 
    9785:	48 21 ca             	and    %rcx,%rdx
    9788:	48 09 c2             	or     %rax,%rdx
    978b:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9792:	48 89 10             	mov    %rdx,(%rax)
    9795:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    9799:	48 c1 e8 02          	shr    $0x2,%rax
    979d:	48 89 c2             	mov    %rax,%rdx
    97a0:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    97a7:	33 33 33 
    97aa:	48 89 d1             	mov    %rdx,%rcx
    97ad:	48 21 c1             	and    %rax,%rcx
    97b0:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    97b7:	cc cc cc 
    97ba:	48 23 45 88          	and    -0x78(%rbp),%rax
    97be:	48 89 c2             	mov    %rax,%rdx
    97c1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    97c8:	48 83 c0 10          	add    $0x10,%rax
    97cc:	48 09 ca             	or     %rcx,%rdx
    97cf:	48 89 10             	mov    %rdx,(%rax)
    97d2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    97d9:	48 8b 40 08          	mov    0x8(%rax),%rax
    97dd:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    97e1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    97e8:	48 8b 40 18          	mov    0x18(%rax),%rax
    97ec:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    97f0:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    97f7:	33 33 33 
    97fa:	48 23 45 90          	and    -0x70(%rbp),%rax
    97fe:	48 89 c2             	mov    %rax,%rdx
    9801:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9805:	48 8d 0c 85 00 00 00 	lea    0x0(,%rax,4),%rcx
    980c:	00 
    980d:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    9814:	cc cc cc 
    9817:	48 21 c1             	and    %rax,%rcx
    981a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9821:	48 83 c0 08          	add    $0x8,%rax
    9825:	48 09 ca             	or     %rcx,%rdx
    9828:	48 89 10             	mov    %rdx,(%rax)
    982b:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    982f:	48 c1 e8 02          	shr    $0x2,%rax
    9833:	48 89 c2             	mov    %rax,%rdx
    9836:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    983d:	33 33 33 
    9840:	48 89 d1             	mov    %rdx,%rcx
    9843:	48 21 c1             	and    %rax,%rcx
    9846:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    984d:	cc cc cc 
    9850:	48 23 45 98          	and    -0x68(%rbp),%rax
    9854:	48 89 c2             	mov    %rax,%rdx
    9857:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    985e:	48 83 c0 18          	add    $0x18,%rax
    9862:	48 09 ca             	or     %rcx,%rdx
    9865:	48 89 10             	mov    %rdx,(%rax)
    9868:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    986f:	48 8b 40 20          	mov    0x20(%rax),%rax
    9873:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    9877:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    987e:	48 8b 40 30          	mov    0x30(%rax),%rax
    9882:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    9886:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    988d:	33 33 33 
    9890:	48 23 45 a0          	and    -0x60(%rbp),%rax
    9894:	48 89 c2             	mov    %rax,%rdx
    9897:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    989b:	48 8d 0c 85 00 00 00 	lea    0x0(,%rax,4),%rcx
    98a2:	00 
    98a3:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    98aa:	cc cc cc 
    98ad:	48 21 c1             	and    %rax,%rcx
    98b0:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    98b7:	48 83 c0 20          	add    $0x20,%rax
    98bb:	48 09 ca             	or     %rcx,%rdx
    98be:	48 89 10             	mov    %rdx,(%rax)
    98c1:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    98c5:	48 c1 e8 02          	shr    $0x2,%rax
    98c9:	48 89 c2             	mov    %rax,%rdx
    98cc:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    98d3:	33 33 33 
    98d6:	48 89 d1             	mov    %rdx,%rcx
    98d9:	48 21 c1             	and    %rax,%rcx
    98dc:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    98e3:	cc cc cc 
    98e6:	48 23 45 a8          	and    -0x58(%rbp),%rax
    98ea:	48 89 c2             	mov    %rax,%rdx
    98ed:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    98f4:	48 83 c0 30          	add    $0x30,%rax
    98f8:	48 09 ca             	or     %rcx,%rdx
    98fb:	48 89 10             	mov    %rdx,(%rax)
    98fe:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9905:	48 8b 40 28          	mov    0x28(%rax),%rax
    9909:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    990d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9914:	48 8b 40 38          	mov    0x38(%rax),%rax
    9918:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    991c:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    9923:	33 33 33 
    9926:	48 23 45 b0          	and    -0x50(%rbp),%rax
    992a:	48 89 c2             	mov    %rax,%rdx
    992d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    9931:	48 8d 0c 85 00 00 00 	lea    0x0(,%rax,4),%rcx
    9938:	00 
    9939:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    9940:	cc cc cc 
    9943:	48 21 c1             	and    %rax,%rcx
    9946:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    994d:	48 83 c0 28          	add    $0x28,%rax
    9951:	48 09 ca             	or     %rcx,%rdx
    9954:	48 89 10             	mov    %rdx,(%rax)
    9957:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    995b:	48 c1 e8 02          	shr    $0x2,%rax
    995f:	48 89 c2             	mov    %rax,%rdx
    9962:	48 b8 33 33 33 33 33 	movabs $0x3333333333333333,%rax
    9969:	33 33 33 
    996c:	48 89 d1             	mov    %rdx,%rcx
    996f:	48 21 c1             	and    %rax,%rcx
    9972:	48 b8 cc cc cc cc cc 	movabs $0xcccccccccccccccc,%rax
    9979:	cc cc cc 
    997c:	48 23 45 b8          	and    -0x48(%rbp),%rax
    9980:	48 89 c2             	mov    %rax,%rdx
    9983:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    998a:	48 83 c0 38          	add    $0x38,%rax
    998e:	48 09 ca             	or     %rcx,%rdx
    9991:	48 89 10             	mov    %rdx,(%rax)
    9994:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    999b:	48 8b 00             	mov    (%rax),%rax
    999e:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    99a2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    99a9:	48 8b 40 20          	mov    0x20(%rax),%rax
    99ad:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    99b1:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    99b8:	0f 0f 0f 
    99bb:	48 23 45 c0          	and    -0x40(%rbp),%rax
    99bf:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    99c3:	48 89 d1             	mov    %rdx,%rcx
    99c6:	48 c1 e1 04          	shl    $0x4,%rcx
    99ca:	48 ba f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rdx
    99d1:	f0 f0 f0 
    99d4:	48 21 ca             	and    %rcx,%rdx
    99d7:	48 09 c2             	or     %rax,%rdx
    99da:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    99e1:	48 89 10             	mov    %rdx,(%rax)
    99e4:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    99e8:	48 c1 e8 04          	shr    $0x4,%rax
    99ec:	48 89 c2             	mov    %rax,%rdx
    99ef:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    99f6:	0f 0f 0f 
    99f9:	48 89 d1             	mov    %rdx,%rcx
    99fc:	48 21 c1             	and    %rax,%rcx
    99ff:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9a06:	f0 f0 f0 
    9a09:	48 23 45 c8          	and    -0x38(%rbp),%rax
    9a0d:	48 89 c2             	mov    %rax,%rdx
    9a10:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a17:	48 83 c0 20          	add    $0x20,%rax
    9a1b:	48 09 ca             	or     %rcx,%rdx
    9a1e:	48 89 10             	mov    %rdx,(%rax)
    9a21:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a28:	48 8b 40 08          	mov    0x8(%rax),%rax
    9a2c:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    9a30:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a37:	48 8b 40 28          	mov    0x28(%rax),%rax
    9a3b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    9a3f:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    9a46:	0f 0f 0f 
    9a49:	48 23 45 d0          	and    -0x30(%rbp),%rax
    9a4d:	48 89 c2             	mov    %rax,%rdx
    9a50:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9a54:	48 c1 e0 04          	shl    $0x4,%rax
    9a58:	48 89 c1             	mov    %rax,%rcx
    9a5b:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9a62:	f0 f0 f0 
    9a65:	48 21 c1             	and    %rax,%rcx
    9a68:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a6f:	48 83 c0 08          	add    $0x8,%rax
    9a73:	48 09 ca             	or     %rcx,%rdx
    9a76:	48 89 10             	mov    %rdx,(%rax)
    9a79:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9a7d:	48 c1 e8 04          	shr    $0x4,%rax
    9a81:	48 89 c2             	mov    %rax,%rdx
    9a84:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    9a8b:	0f 0f 0f 
    9a8e:	48 89 d1             	mov    %rdx,%rcx
    9a91:	48 21 c1             	and    %rax,%rcx
    9a94:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9a9b:	f0 f0 f0 
    9a9e:	48 23 45 d8          	and    -0x28(%rbp),%rax
    9aa2:	48 89 c2             	mov    %rax,%rdx
    9aa5:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9aac:	48 83 c0 28          	add    $0x28,%rax
    9ab0:	48 09 ca             	or     %rcx,%rdx
    9ab3:	48 89 10             	mov    %rdx,(%rax)
    9ab6:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9abd:	48 8b 40 10          	mov    0x10(%rax),%rax
    9ac1:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    9ac5:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9acc:	48 8b 40 30          	mov    0x30(%rax),%rax
    9ad0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    9ad4:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    9adb:	0f 0f 0f 
    9ade:	48 23 45 e0          	and    -0x20(%rbp),%rax
    9ae2:	48 89 c2             	mov    %rax,%rdx
    9ae5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    9ae9:	48 c1 e0 04          	shl    $0x4,%rax
    9aed:	48 89 c1             	mov    %rax,%rcx
    9af0:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9af7:	f0 f0 f0 
    9afa:	48 21 c1             	and    %rax,%rcx
    9afd:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9b04:	48 83 c0 10          	add    $0x10,%rax
    9b08:	48 09 ca             	or     %rcx,%rdx
    9b0b:	48 89 10             	mov    %rdx,(%rax)
    9b0e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9b12:	48 c1 e8 04          	shr    $0x4,%rax
    9b16:	48 89 c2             	mov    %rax,%rdx
    9b19:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    9b20:	0f 0f 0f 
    9b23:	48 89 d1             	mov    %rdx,%rcx
    9b26:	48 21 c1             	and    %rax,%rcx
    9b29:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9b30:	f0 f0 f0 
    9b33:	48 23 45 e8          	and    -0x18(%rbp),%rax
    9b37:	48 89 c2             	mov    %rax,%rdx
    9b3a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9b41:	48 83 c0 30          	add    $0x30,%rax
    9b45:	48 09 ca             	or     %rcx,%rdx
    9b48:	48 89 10             	mov    %rdx,(%rax)
    9b4b:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9b52:	48 8b 40 18          	mov    0x18(%rax),%rax
    9b56:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    9b5a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9b61:	48 8b 40 38          	mov    0x38(%rax),%rax
    9b65:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    9b69:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    9b70:	0f 0f 0f 
    9b73:	48 23 45 f0          	and    -0x10(%rbp),%rax
    9b77:	48 89 c2             	mov    %rax,%rdx
    9b7a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9b7e:	48 c1 e0 04          	shl    $0x4,%rax
    9b82:	48 89 c1             	mov    %rax,%rcx
    9b85:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9b8c:	f0 f0 f0 
    9b8f:	48 21 c1             	and    %rax,%rcx
    9b92:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9b99:	48 83 c0 18          	add    $0x18,%rax
    9b9d:	48 09 ca             	or     %rcx,%rdx
    9ba0:	48 89 10             	mov    %rdx,(%rax)
    9ba3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9ba7:	48 c1 e8 04          	shr    $0x4,%rax
    9bab:	48 89 c2             	mov    %rax,%rdx
    9bae:	48 b8 0f 0f 0f 0f 0f 	movabs $0xf0f0f0f0f0f0f0f,%rax
    9bb5:	0f 0f 0f 
    9bb8:	48 89 d1             	mov    %rdx,%rcx
    9bbb:	48 21 c1             	and    %rax,%rcx
    9bbe:	48 b8 f0 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f0,%rax
    9bc5:	f0 f0 f0 
    9bc8:	48 23 45 f8          	and    -0x8(%rbp),%rax
    9bcc:	48 89 c2             	mov    %rax,%rdx
    9bcf:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9bd6:	48 83 c0 38          	add    $0x38,%rax
    9bda:	48 09 ca             	or     %rcx,%rdx
    9bdd:	48 89 10             	mov    %rdx,(%rax)
    9be0:	90                   	nop
    9be1:	c9                   	leave
    9be2:	c3                   	ret

0000000000009be3 <br_aes_ct64_interleave_in>:
    9be3:	f3 0f 1e fa          	endbr64
    9be7:	55                   	push   %rbp
    9be8:	48 89 e5             	mov    %rsp,%rbp
    9beb:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    9bef:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    9bf3:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    9bf7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    9bfb:	8b 00                	mov    (%rax),%eax
    9bfd:	89 c0                	mov    %eax,%eax
    9bff:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    9c03:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    9c07:	48 83 c0 04          	add    $0x4,%rax
    9c0b:	8b 00                	mov    (%rax),%eax
    9c0d:	89 c0                	mov    %eax,%eax
    9c0f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    9c13:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    9c17:	48 83 c0 08          	add    $0x8,%rax
    9c1b:	8b 00                	mov    (%rax),%eax
    9c1d:	89 c0                	mov    %eax,%eax
    9c1f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    9c23:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    9c27:	48 83 c0 0c          	add    $0xc,%rax
    9c2b:	8b 00                	mov    (%rax),%eax
    9c2d:	89 c0                	mov    %eax,%eax
    9c2f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    9c33:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9c37:	48 c1 e0 10          	shl    $0x10,%rax
    9c3b:	48 09 45 e0          	or     %rax,-0x20(%rbp)
    9c3f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    9c43:	48 c1 e0 10          	shl    $0x10,%rax
    9c47:	48 09 45 e8          	or     %rax,-0x18(%rbp)
    9c4b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9c4f:	48 c1 e0 10          	shl    $0x10,%rax
    9c53:	48 09 45 f0          	or     %rax,-0x10(%rbp)
    9c57:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9c5b:	48 c1 e0 10          	shl    $0x10,%rax
    9c5f:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    9c63:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9c6a:	ff 00 00 
    9c6d:	48 21 45 e0          	and    %rax,-0x20(%rbp)
    9c71:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9c78:	ff 00 00 
    9c7b:	48 21 45 e8          	and    %rax,-0x18(%rbp)
    9c7f:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9c86:	ff 00 00 
    9c89:	48 21 45 f0          	and    %rax,-0x10(%rbp)
    9c8d:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9c94:	ff 00 00 
    9c97:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    9c9b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9c9f:	48 c1 e0 08          	shl    $0x8,%rax
    9ca3:	48 09 45 e0          	or     %rax,-0x20(%rbp)
    9ca7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    9cab:	48 c1 e0 08          	shl    $0x8,%rax
    9caf:	48 09 45 e8          	or     %rax,-0x18(%rbp)
    9cb3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9cb7:	48 c1 e0 08          	shl    $0x8,%rax
    9cbb:	48 09 45 f0          	or     %rax,-0x10(%rbp)
    9cbf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9cc3:	48 c1 e0 08          	shl    $0x8,%rax
    9cc7:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    9ccb:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9cd2:	00 ff 00 
    9cd5:	48 21 45 e0          	and    %rax,-0x20(%rbp)
    9cd9:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9ce0:	00 ff 00 
    9ce3:	48 21 45 e8          	and    %rax,-0x18(%rbp)
    9ce7:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9cee:	00 ff 00 
    9cf1:	48 21 45 f0          	and    %rax,-0x10(%rbp)
    9cf5:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9cfc:	00 ff 00 
    9cff:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    9d03:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9d07:	48 c1 e0 08          	shl    $0x8,%rax
    9d0b:	48 0b 45 e0          	or     -0x20(%rbp),%rax
    9d0f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    9d13:	48 89 02             	mov    %rax,(%rdx)
    9d16:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9d1a:	48 c1 e0 08          	shl    $0x8,%rax
    9d1e:	48 0b 45 e8          	or     -0x18(%rbp),%rax
    9d22:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    9d26:	48 89 02             	mov    %rax,(%rdx)
    9d29:	90                   	nop
    9d2a:	5d                   	pop    %rbp
    9d2b:	c3                   	ret

0000000000009d2c <br_aes_ct64_interleave_out>:
    9d2c:	f3 0f 1e fa          	endbr64
    9d30:	55                   	push   %rbp
    9d31:	48 89 e5             	mov    %rsp,%rbp
    9d34:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    9d38:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    9d3c:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    9d40:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9d47:	00 ff 00 
    9d4a:	48 23 45 d0          	and    -0x30(%rbp),%rax
    9d4e:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    9d52:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9d59:	00 ff 00 
    9d5c:	48 23 45 c8          	and    -0x38(%rbp),%rax
    9d60:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    9d64:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9d68:	48 c1 e8 08          	shr    $0x8,%rax
    9d6c:	48 89 c2             	mov    %rax,%rdx
    9d6f:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9d76:	00 ff 00 
    9d79:	48 21 d0             	and    %rdx,%rax
    9d7c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    9d80:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    9d84:	48 c1 e8 08          	shr    $0x8,%rax
    9d88:	48 89 c2             	mov    %rax,%rdx
    9d8b:	48 b8 ff 00 ff 00 ff 	movabs $0xff00ff00ff00ff,%rax
    9d92:	00 ff 00 
    9d95:	48 21 d0             	and    %rdx,%rax
    9d98:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    9d9c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9da0:	48 c1 e8 08          	shr    $0x8,%rax
    9da4:	48 09 45 e0          	or     %rax,-0x20(%rbp)
    9da8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    9dac:	48 c1 e8 08          	shr    $0x8,%rax
    9db0:	48 09 45 e8          	or     %rax,-0x18(%rbp)
    9db4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9db8:	48 c1 e8 08          	shr    $0x8,%rax
    9dbc:	48 09 45 f0          	or     %rax,-0x10(%rbp)
    9dc0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9dc4:	48 c1 e8 08          	shr    $0x8,%rax
    9dc8:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    9dcc:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9dd3:	ff 00 00 
    9dd6:	48 21 45 e0          	and    %rax,-0x20(%rbp)
    9dda:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9de1:	ff 00 00 
    9de4:	48 21 45 e8          	and    %rax,-0x18(%rbp)
    9de8:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9def:	ff 00 00 
    9df2:	48 21 45 f0          	and    %rax,-0x10(%rbp)
    9df6:	48 b8 ff ff 00 00 ff 	movabs $0xffff0000ffff,%rax
    9dfd:	ff 00 00 
    9e00:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    9e04:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9e08:	89 c2                	mov    %eax,%edx
    9e0a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9e0e:	48 c1 e8 10          	shr    $0x10,%rax
    9e12:	09 c2                	or     %eax,%edx
    9e14:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9e18:	89 10                	mov    %edx,(%rax)
    9e1a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    9e1e:	89 c1                	mov    %eax,%ecx
    9e20:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    9e24:	48 c1 e8 10          	shr    $0x10,%rax
    9e28:	89 c2                	mov    %eax,%edx
    9e2a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9e2e:	48 83 c0 04          	add    $0x4,%rax
    9e32:	09 ca                	or     %ecx,%edx
    9e34:	89 10                	mov    %edx,(%rax)
    9e36:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9e3a:	89 c1                	mov    %eax,%ecx
    9e3c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    9e40:	48 c1 e8 10          	shr    $0x10,%rax
    9e44:	89 c2                	mov    %eax,%edx
    9e46:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9e4a:	48 83 c0 08          	add    $0x8,%rax
    9e4e:	09 ca                	or     %ecx,%edx
    9e50:	89 10                	mov    %edx,(%rax)
    9e52:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9e56:	89 c1                	mov    %eax,%ecx
    9e58:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    9e5c:	48 c1 e8 10          	shr    $0x10,%rax
    9e60:	89 c2                	mov    %eax,%edx
    9e62:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9e66:	48 83 c0 0c          	add    $0xc,%rax
    9e6a:	09 ca                	or     %ecx,%edx
    9e6c:	89 10                	mov    %edx,(%rax)
    9e6e:	90                   	nop
    9e6f:	5d                   	pop    %rbp
    9e70:	c3                   	ret

0000000000009e71 <sub_word>:
    9e71:	f3 0f 1e fa          	endbr64
    9e75:	55                   	push   %rbp
    9e76:	48 89 e5             	mov    %rsp,%rbp
    9e79:	48 83 ec 60          	sub    $0x60,%rsp
    9e7d:	89 7d ac             	mov    %edi,-0x54(%rbp)
    9e80:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    9e87:	00 00 
    9e89:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    9e8d:	31 c0                	xor    %eax,%eax
    9e8f:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    9e93:	ba 40 00 00 00       	mov    $0x40,%edx
    9e98:	be 00 00 00 00       	mov    $0x0,%esi
    9e9d:	48 89 c7             	mov    %rax,%rdi
    9ea0:	e8 5b 73 ff ff       	call   1200 <memset@plt>
    9ea5:	8b 45 ac             	mov    -0x54(%rbp),%eax
    9ea8:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    9eac:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    9eb0:	48 89 c7             	mov    %rax,%rdi
    9eb3:	e8 f5 f5 ff ff       	call   94ad <br_aes_ct64_ortho>
    9eb8:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    9ebc:	48 89 c7             	mov    %rax,%rdi
    9ebf:	e8 94 eb ff ff       	call   8a58 <br_aes_ct64_bitslice_Sbox>
    9ec4:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    9ec8:	48 89 c7             	mov    %rax,%rdi
    9ecb:	e8 dd f5 ff ff       	call   94ad <br_aes_ct64_ortho>
    9ed0:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    9ed4:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    9ed8:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    9edf:	00 00 
    9ee1:	74 05                	je     9ee8 <sub_word+0x77>
    9ee3:	e8 e8 72 ff ff       	call   11d0 <__stack_chk_fail@plt>
    9ee8:	c9                   	leave
    9ee9:	c3                   	ret

0000000000009eea <br_aes_ct64_keysched>:
    9eea:	f3 0f 1e fa          	endbr64
    9eee:	55                   	push   %rbp
    9eef:	48 89 e5             	mov    %rsp,%rbp
    9ef2:	48 81 ec 80 01 00 00 	sub    $0x180,%rsp
    9ef9:	48 89 bd 98 fe ff ff 	mov    %rdi,-0x168(%rbp)
    9f00:	48 89 b5 90 fe ff ff 	mov    %rsi,-0x170(%rbp)
    9f07:	89 95 8c fe ff ff    	mov    %edx,-0x174(%rbp)
    9f0d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    9f14:	00 00 
    9f16:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    9f1a:	31 c0                	xor    %eax,%eax
    9f1c:	8b 85 8c fe ff ff    	mov    -0x174(%rbp),%eax
    9f22:	83 e8 10             	sub    $0x10,%eax
    9f25:	c1 e8 02             	shr    $0x2,%eax
    9f28:	83 c0 0a             	add    $0xa,%eax
    9f2b:	89 85 b4 fe ff ff    	mov    %eax,-0x14c(%rbp)
    9f31:	8b 85 8c fe ff ff    	mov    -0x174(%rbp),%eax
    9f37:	c1 e8 02             	shr    $0x2,%eax
    9f3a:	89 85 b8 fe ff ff    	mov    %eax,-0x148(%rbp)
    9f40:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9f46:	83 c0 01             	add    $0x1,%eax
    9f49:	c1 e0 02             	shl    $0x2,%eax
    9f4c:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
    9f52:	8b 85 8c fe ff ff    	mov    -0x174(%rbp),%eax
    9f58:	c1 e8 02             	shr    $0x2,%eax
    9f5b:	89 c1                	mov    %eax,%ecx
    9f5d:	48 8b 95 90 fe ff ff 	mov    -0x170(%rbp),%rdx
    9f64:	48 8d 85 00 ff ff ff 	lea    -0x100(%rbp),%rax
    9f6b:	48 89 ce             	mov    %rcx,%rsi
    9f6e:	48 89 c7             	mov    %rax,%rdi
    9f71:	e8 c3 e9 ff ff       	call   8939 <br_range_dec32le>
    9f76:	8b 85 8c fe ff ff    	mov    -0x174(%rbp),%eax
    9f7c:	c1 e8 02             	shr    $0x2,%eax
    9f7f:	83 e8 01             	sub    $0x1,%eax
    9f82:	89 c0                	mov    %eax,%eax
    9f84:	8b 84 85 00 ff ff ff 	mov    -0x100(%rbp,%rax,4),%eax
    9f8b:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    9f91:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    9f97:	89 85 a4 fe ff ff    	mov    %eax,-0x15c(%rbp)
    9f9d:	c7 85 a8 fe ff ff 00 	movl   $0x0,-0x158(%rbp)
    9fa4:	00 00 00 
    9fa7:	c7 85 ac fe ff ff 00 	movl   $0x0,-0x154(%rbp)
    9fae:	00 00 00 
    9fb1:	e9 bd 00 00 00       	jmp    a073 <br_aes_ct64_keysched+0x189>
    9fb6:	83 bd a8 fe ff ff 00 	cmpl   $0x0,-0x158(%rbp)
    9fbd:	75 34                	jne    9ff3 <br_aes_ct64_keysched+0x109>
    9fbf:	c1 8d b0 fe ff ff 08 	rorl   $0x8,-0x150(%rbp)
    9fc6:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    9fcc:	89 c7                	mov    %eax,%edi
    9fce:	e8 9e fe ff ff       	call   9e71 <sub_word>
    9fd3:	89 c2                	mov    %eax,%edx
    9fd5:	8b 85 ac fe ff ff    	mov    -0x154(%rbp),%eax
    9fdb:	48 8d 0d c6 41 00 00 	lea    0x41c6(%rip),%rcx        # e1a8 <Rcon>
    9fe2:	0f b6 04 08          	movzbl (%rax,%rcx,1),%eax
    9fe6:	0f b6 c0             	movzbl %al,%eax
    9fe9:	31 d0                	xor    %edx,%eax
    9feb:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    9ff1:	eb 25                	jmp    a018 <br_aes_ct64_keysched+0x12e>
    9ff3:	83 bd b8 fe ff ff 06 	cmpl   $0x6,-0x148(%rbp)
    9ffa:	76 1c                	jbe    a018 <br_aes_ct64_keysched+0x12e>
    9ffc:	83 bd a8 fe ff ff 04 	cmpl   $0x4,-0x158(%rbp)
    a003:	75 13                	jne    a018 <br_aes_ct64_keysched+0x12e>
    a005:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    a00b:	89 c7                	mov    %eax,%edi
    a00d:	e8 5f fe ff ff       	call   9e71 <sub_word>
    a012:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    a018:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    a01e:	2b 85 b8 fe ff ff    	sub    -0x148(%rbp),%eax
    a024:	89 c0                	mov    %eax,%eax
    a026:	8b 84 85 00 ff ff ff 	mov    -0x100(%rbp,%rax,4),%eax
    a02d:	31 85 b0 fe ff ff    	xor    %eax,-0x150(%rbp)
    a033:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    a039:	8b 95 b0 fe ff ff    	mov    -0x150(%rbp),%edx
    a03f:	89 94 85 00 ff ff ff 	mov    %edx,-0x100(%rbp,%rax,4)
    a046:	83 85 a8 fe ff ff 01 	addl   $0x1,-0x158(%rbp)
    a04d:	8b 85 a8 fe ff ff    	mov    -0x158(%rbp),%eax
    a053:	3b 85 b8 fe ff ff    	cmp    -0x148(%rbp),%eax
    a059:	75 11                	jne    a06c <br_aes_ct64_keysched+0x182>
    a05b:	c7 85 a8 fe ff ff 00 	movl   $0x0,-0x158(%rbp)
    a062:	00 00 00 
    a065:	83 85 ac fe ff ff 01 	addl   $0x1,-0x154(%rbp)
    a06c:	83 85 a4 fe ff ff 01 	addl   $0x1,-0x15c(%rbp)
    a073:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    a079:	3b 85 bc fe ff ff    	cmp    -0x144(%rbp),%eax
    a07f:	0f 82 31 ff ff ff    	jb     9fb6 <br_aes_ct64_keysched+0xcc>
    a085:	c7 85 a4 fe ff ff 00 	movl   $0x0,-0x15c(%rbp)
    a08c:	00 00 00 
    a08f:	c7 85 a8 fe ff ff 00 	movl   $0x0,-0x158(%rbp)
    a096:	00 00 00 
    a099:	e9 99 01 00 00       	jmp    a237 <br_aes_ct64_keysched+0x34d>
    a09e:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    a0a4:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    a0ab:	00 
    a0ac:	48 8d 85 00 ff ff ff 	lea    -0x100(%rbp),%rax
    a0b3:	48 01 c2             	add    %rax,%rdx
    a0b6:	48 8d 85 c0 fe ff ff 	lea    -0x140(%rbp),%rax
    a0bd:	48 8d 48 20          	lea    0x20(%rax),%rcx
    a0c1:	48 8d 85 c0 fe ff ff 	lea    -0x140(%rbp),%rax
    a0c8:	48 89 ce             	mov    %rcx,%rsi
    a0cb:	48 89 c7             	mov    %rax,%rdi
    a0ce:	e8 10 fb ff ff       	call   9be3 <br_aes_ct64_interleave_in>
    a0d3:	48 8b 85 c0 fe ff ff 	mov    -0x140(%rbp),%rax
    a0da:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
    a0e1:	48 8b 85 c0 fe ff ff 	mov    -0x140(%rbp),%rax
    a0e8:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
    a0ef:	48 8b 85 c0 fe ff ff 	mov    -0x140(%rbp),%rax
    a0f6:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    a0fd:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    a104:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    a10b:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    a112:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a119:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    a120:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a127:	48 8d 85 c0 fe ff ff 	lea    -0x140(%rbp),%rax
    a12e:	48 89 c7             	mov    %rax,%rdi
    a131:	e8 77 f3 ff ff       	call   94ad <br_aes_ct64_ortho>
    a136:	48 8b 95 c0 fe ff ff 	mov    -0x140(%rbp),%rdx
    a13d:	48 b8 11 11 11 11 11 	movabs $0x1111111111111111,%rax
    a144:	11 11 11 
    a147:	48 21 c2             	and    %rax,%rdx
    a14a:	48 8b 8d c8 fe ff ff 	mov    -0x138(%rbp),%rcx
    a151:	48 b8 22 22 22 22 22 	movabs $0x2222222222222222,%rax
    a158:	22 22 22 
    a15b:	48 21 c8             	and    %rcx,%rax
    a15e:	48 09 c2             	or     %rax,%rdx
    a161:	48 8b 8d d0 fe ff ff 	mov    -0x130(%rbp),%rcx
    a168:	48 b8 44 44 44 44 44 	movabs $0x4444444444444444,%rax
    a16f:	44 44 44 
    a172:	48 21 c8             	and    %rcx,%rax
    a175:	48 89 d1             	mov    %rdx,%rcx
    a178:	48 09 c1             	or     %rax,%rcx
    a17b:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    a182:	48 b8 88 88 88 88 88 	movabs $0x8888888888888888,%rax
    a189:	88 88 88 
    a18c:	48 21 c2             	and    %rax,%rdx
    a18f:	8b 85 a8 fe ff ff    	mov    -0x158(%rbp),%eax
    a195:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    a19c:	00 
    a19d:	48 8b 85 98 fe ff ff 	mov    -0x168(%rbp),%rax
    a1a4:	48 01 f0             	add    %rsi,%rax
    a1a7:	48 09 ca             	or     %rcx,%rdx
    a1aa:	48 89 10             	mov    %rdx,(%rax)
    a1ad:	48 8b 95 e0 fe ff ff 	mov    -0x120(%rbp),%rdx
    a1b4:	48 b8 11 11 11 11 11 	movabs $0x1111111111111111,%rax
    a1bb:	11 11 11 
    a1be:	48 21 c2             	and    %rax,%rdx
    a1c1:	48 8b 8d e8 fe ff ff 	mov    -0x118(%rbp),%rcx
    a1c8:	48 b8 22 22 22 22 22 	movabs $0x2222222222222222,%rax
    a1cf:	22 22 22 
    a1d2:	48 21 c8             	and    %rcx,%rax
    a1d5:	48 09 c2             	or     %rax,%rdx
    a1d8:	48 8b 8d f0 fe ff ff 	mov    -0x110(%rbp),%rcx
    a1df:	48 b8 44 44 44 44 44 	movabs $0x4444444444444444,%rax
    a1e6:	44 44 44 
    a1e9:	48 21 c8             	and    %rcx,%rax
    a1ec:	48 89 d1             	mov    %rdx,%rcx
    a1ef:	48 09 c1             	or     %rax,%rcx
    a1f2:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    a1f9:	48 b8 88 88 88 88 88 	movabs $0x8888888888888888,%rax
    a200:	88 88 88 
    a203:	48 21 c2             	and    %rax,%rdx
    a206:	8b 85 a8 fe ff ff    	mov    -0x158(%rbp),%eax
    a20c:	83 c0 01             	add    $0x1,%eax
    a20f:	89 c0                	mov    %eax,%eax
    a211:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    a218:	00 
    a219:	48 8b 85 98 fe ff ff 	mov    -0x168(%rbp),%rax
    a220:	48 01 f0             	add    %rsi,%rax
    a223:	48 09 ca             	or     %rcx,%rdx
    a226:	48 89 10             	mov    %rdx,(%rax)
    a229:	83 85 a4 fe ff ff 04 	addl   $0x4,-0x15c(%rbp)
    a230:	83 85 a8 fe ff ff 02 	addl   $0x2,-0x158(%rbp)
    a237:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    a23d:	3b 85 bc fe ff ff    	cmp    -0x144(%rbp),%eax
    a243:	0f 82 55 fe ff ff    	jb     a09e <br_aes_ct64_keysched+0x1b4>
    a249:	90                   	nop
    a24a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a24e:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    a255:	00 00 
    a257:	74 05                	je     a25e <br_aes_ct64_keysched+0x374>
    a259:	e8 72 6f ff ff       	call   11d0 <__stack_chk_fail@plt>
    a25e:	c9                   	leave
    a25f:	c3                   	ret

000000000000a260 <br_aes_ct64_skey_expand>:
    a260:	f3 0f 1e fa          	endbr64
    a264:	55                   	push   %rbp
    a265:	48 89 e5             	mov    %rsp,%rbp
    a268:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    a26c:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    a270:	89 55 bc             	mov    %edx,-0x44(%rbp)
    a273:	8b 45 bc             	mov    -0x44(%rbp),%eax
    a276:	83 c0 01             	add    $0x1,%eax
    a279:	01 c0                	add    %eax,%eax
    a27b:	89 45 dc             	mov    %eax,-0x24(%rbp)
    a27e:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    a285:	c7 45 d8 00 00 00 00 	movl   $0x0,-0x28(%rbp)
    a28c:	e9 12 01 00 00       	jmp    a3a3 <br_aes_ct64_skey_expand+0x143>
    a291:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    a294:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a29b:	00 
    a29c:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a2a0:	48 01 d0             	add    %rdx,%rax
    a2a3:	48 8b 00             	mov    (%rax),%rax
    a2a6:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    a2aa:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    a2ae:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    a2b2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    a2b6:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    a2ba:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a2be:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    a2c2:	48 b8 11 11 11 11 11 	movabs $0x1111111111111111,%rax
    a2c9:	11 11 11 
    a2cc:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    a2d0:	48 b8 22 22 22 22 22 	movabs $0x2222222222222222,%rax
    a2d7:	22 22 22 
    a2da:	48 21 45 f0          	and    %rax,-0x10(%rbp)
    a2de:	48 b8 44 44 44 44 44 	movabs $0x4444444444444444,%rax
    a2e5:	44 44 44 
    a2e8:	48 21 45 e8          	and    %rax,-0x18(%rbp)
    a2ec:	48 b8 88 88 88 88 88 	movabs $0x8888888888888888,%rax
    a2f3:	88 88 88 
    a2f6:	48 21 45 e0          	and    %rax,-0x20(%rbp)
    a2fa:	48 d1 6d f0          	shrq   $1,-0x10(%rbp)
    a2fe:	48 c1 6d e8 02       	shrq   $0x2,-0x18(%rbp)
    a303:	48 c1 6d e0 03       	shrq   $0x3,-0x20(%rbp)
    a308:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a30c:	48 c1 e0 04          	shl    $0x4,%rax
    a310:	8b 55 d8             	mov    -0x28(%rbp),%edx
    a313:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    a31a:	00 
    a31b:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    a31f:	48 01 ca             	add    %rcx,%rdx
    a322:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    a326:	48 89 02             	mov    %rax,(%rdx)
    a329:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a32d:	48 c1 e0 04          	shl    $0x4,%rax
    a331:	8b 55 d8             	mov    -0x28(%rbp),%edx
    a334:	83 c2 01             	add    $0x1,%edx
    a337:	89 d2                	mov    %edx,%edx
    a339:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    a340:	00 
    a341:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    a345:	48 01 ca             	add    %rcx,%rdx
    a348:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    a34c:	48 89 02             	mov    %rax,(%rdx)
    a34f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    a353:	48 c1 e0 04          	shl    $0x4,%rax
    a357:	8b 55 d8             	mov    -0x28(%rbp),%edx
    a35a:	83 c2 02             	add    $0x2,%edx
    a35d:	89 d2                	mov    %edx,%edx
    a35f:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    a366:	00 
    a367:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    a36b:	48 01 ca             	add    %rcx,%rdx
    a36e:	48 2b 45 e8          	sub    -0x18(%rbp),%rax
    a372:	48 89 02             	mov    %rax,(%rdx)
    a375:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    a379:	48 c1 e0 04          	shl    $0x4,%rax
    a37d:	8b 55 d8             	mov    -0x28(%rbp),%edx
    a380:	83 c2 03             	add    $0x3,%edx
    a383:	89 d2                	mov    %edx,%edx
    a385:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    a38c:	00 
    a38d:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    a391:	48 01 ca             	add    %rcx,%rdx
    a394:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    a398:	48 89 02             	mov    %rax,(%rdx)
    a39b:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    a39f:	83 45 d8 04          	addl   $0x4,-0x28(%rbp)
    a3a3:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    a3a6:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    a3a9:	0f 82 e2 fe ff ff    	jb     a291 <br_aes_ct64_skey_expand+0x31>
    a3af:	90                   	nop
    a3b0:	90                   	nop
    a3b1:	5d                   	pop    %rbp
    a3b2:	c3                   	ret

000000000000a3b3 <add_round_key>:
    a3b3:	55                   	push   %rbp
    a3b4:	48 89 e5             	mov    %rsp,%rbp
    a3b7:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    a3bb:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    a3bf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a3c3:	48 8b 10             	mov    (%rax),%rdx
    a3c6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a3ca:	48 8b 00             	mov    (%rax),%rax
    a3cd:	48 31 c2             	xor    %rax,%rdx
    a3d0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a3d4:	48 89 10             	mov    %rdx,(%rax)
    a3d7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a3db:	48 83 c0 08          	add    $0x8,%rax
    a3df:	48 8b 08             	mov    (%rax),%rcx
    a3e2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a3e6:	48 83 c0 08          	add    $0x8,%rax
    a3ea:	48 8b 10             	mov    (%rax),%rdx
    a3ed:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a3f1:	48 83 c0 08          	add    $0x8,%rax
    a3f5:	48 31 ca             	xor    %rcx,%rdx
    a3f8:	48 89 10             	mov    %rdx,(%rax)
    a3fb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a3ff:	48 83 c0 10          	add    $0x10,%rax
    a403:	48 8b 08             	mov    (%rax),%rcx
    a406:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a40a:	48 83 c0 10          	add    $0x10,%rax
    a40e:	48 8b 10             	mov    (%rax),%rdx
    a411:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a415:	48 83 c0 10          	add    $0x10,%rax
    a419:	48 31 ca             	xor    %rcx,%rdx
    a41c:	48 89 10             	mov    %rdx,(%rax)
    a41f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a423:	48 83 c0 18          	add    $0x18,%rax
    a427:	48 8b 08             	mov    (%rax),%rcx
    a42a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a42e:	48 83 c0 18          	add    $0x18,%rax
    a432:	48 8b 10             	mov    (%rax),%rdx
    a435:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a439:	48 83 c0 18          	add    $0x18,%rax
    a43d:	48 31 ca             	xor    %rcx,%rdx
    a440:	48 89 10             	mov    %rdx,(%rax)
    a443:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a447:	48 83 c0 20          	add    $0x20,%rax
    a44b:	48 8b 08             	mov    (%rax),%rcx
    a44e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a452:	48 83 c0 20          	add    $0x20,%rax
    a456:	48 8b 10             	mov    (%rax),%rdx
    a459:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a45d:	48 83 c0 20          	add    $0x20,%rax
    a461:	48 31 ca             	xor    %rcx,%rdx
    a464:	48 89 10             	mov    %rdx,(%rax)
    a467:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a46b:	48 83 c0 28          	add    $0x28,%rax
    a46f:	48 8b 08             	mov    (%rax),%rcx
    a472:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a476:	48 83 c0 28          	add    $0x28,%rax
    a47a:	48 8b 10             	mov    (%rax),%rdx
    a47d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a481:	48 83 c0 28          	add    $0x28,%rax
    a485:	48 31 ca             	xor    %rcx,%rdx
    a488:	48 89 10             	mov    %rdx,(%rax)
    a48b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a48f:	48 83 c0 30          	add    $0x30,%rax
    a493:	48 8b 08             	mov    (%rax),%rcx
    a496:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a49a:	48 83 c0 30          	add    $0x30,%rax
    a49e:	48 8b 10             	mov    (%rax),%rdx
    a4a1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a4a5:	48 83 c0 30          	add    $0x30,%rax
    a4a9:	48 31 ca             	xor    %rcx,%rdx
    a4ac:	48 89 10             	mov    %rdx,(%rax)
    a4af:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a4b3:	48 83 c0 38          	add    $0x38,%rax
    a4b7:	48 8b 08             	mov    (%rax),%rcx
    a4ba:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    a4be:	48 83 c0 38          	add    $0x38,%rax
    a4c2:	48 8b 10             	mov    (%rax),%rdx
    a4c5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a4c9:	48 83 c0 38          	add    $0x38,%rax
    a4cd:	48 31 ca             	xor    %rcx,%rdx
    a4d0:	48 89 10             	mov    %rdx,(%rax)
    a4d3:	90                   	nop
    a4d4:	5d                   	pop    %rbp
    a4d5:	c3                   	ret

000000000000a4d6 <shift_rows>:
    a4d6:	55                   	push   %rbp
    a4d7:	48 89 e5             	mov    %rsp,%rbp
    a4da:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    a4de:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    a4e5:	e9 cd 00 00 00       	jmp    a5b7 <shift_rows+0xe1>
    a4ea:	8b 45 f4             	mov    -0xc(%rbp),%eax
    a4ed:	48 98                	cltq
    a4ef:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a4f6:	00 
    a4f7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    a4fb:	48 01 d0             	add    %rdx,%rax
    a4fe:	48 8b 00             	mov    (%rax),%rax
    a501:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    a505:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a509:	0f b7 c0             	movzwl %ax,%eax
    a50c:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    a510:	48 c1 ea 04          	shr    $0x4,%rdx
    a514:	81 e2 00 00 ff 0f    	and    $0xfff0000,%edx
    a51a:	48 09 c2             	or     %rax,%rdx
    a51d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a521:	48 c1 e0 0c          	shl    $0xc,%rax
    a525:	25 00 00 00 f0       	and    $0xf0000000,%eax
    a52a:	48 09 c2             	or     %rax,%rdx
    a52d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a531:	48 c1 e8 08          	shr    $0x8,%rax
    a535:	48 89 c1             	mov    %rax,%rcx
    a538:	48 b8 00 00 00 00 ff 	movabs $0xff00000000,%rax
    a53f:	00 00 00 
    a542:	48 21 c8             	and    %rcx,%rax
    a545:	48 09 c2             	or     %rax,%rdx
    a548:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a54c:	48 c1 e0 08          	shl    $0x8,%rax
    a550:	48 89 c1             	mov    %rax,%rcx
    a553:	48 b8 00 00 00 00 00 	movabs $0xff0000000000,%rax
    a55a:	ff 00 00 
    a55d:	48 21 c8             	and    %rcx,%rax
    a560:	48 09 c2             	or     %rax,%rdx
    a563:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a567:	48 c1 e8 0c          	shr    $0xc,%rax
    a56b:	48 89 c1             	mov    %rax,%rcx
    a56e:	48 b8 00 00 00 00 00 	movabs $0xf000000000000,%rax
    a575:	00 0f 00 
    a578:	48 21 c8             	and    %rcx,%rax
    a57b:	48 89 d1             	mov    %rdx,%rcx
    a57e:	48 09 c1             	or     %rax,%rcx
    a581:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a585:	48 c1 e0 04          	shl    $0x4,%rax
    a589:	48 89 c2             	mov    %rax,%rdx
    a58c:	48 b8 00 00 00 00 00 	movabs $0xfff0000000000000,%rax
    a593:	00 f0 ff 
    a596:	48 21 c2             	and    %rax,%rdx
    a599:	8b 45 f4             	mov    -0xc(%rbp),%eax
    a59c:	48 98                	cltq
    a59e:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
    a5a5:	00 
    a5a6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    a5aa:	48 01 f0             	add    %rsi,%rax
    a5ad:	48 09 ca             	or     %rcx,%rdx
    a5b0:	48 89 10             	mov    %rdx,(%rax)
    a5b3:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    a5b7:	83 7d f4 07          	cmpl   $0x7,-0xc(%rbp)
    a5bb:	0f 8e 29 ff ff ff    	jle    a4ea <shift_rows+0x14>
    a5c1:	90                   	nop
    a5c2:	90                   	nop
    a5c3:	5d                   	pop    %rbp
    a5c4:	c3                   	ret

000000000000a5c5 <rotr32>:
    a5c5:	55                   	push   %rbp
    a5c6:	48 89 e5             	mov    %rsp,%rbp
    a5c9:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    a5cd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a5d1:	48 c1 c0 20          	rol    $0x20,%rax
    a5d5:	5d                   	pop    %rbp
    a5d6:	c3                   	ret

000000000000a5d7 <mix_columns>:
    a5d7:	55                   	push   %rbp
    a5d8:	48 89 e5             	mov    %rsp,%rbp
    a5db:	53                   	push   %rbx
    a5dc:	48 81 ec 88 00 00 00 	sub    $0x88,%rsp
    a5e3:	48 89 bd 70 ff ff ff 	mov    %rdi,-0x90(%rbp)
    a5ea:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a5f1:	48 8b 00             	mov    (%rax),%rax
    a5f4:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    a5fb:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a602:	48 8b 40 08          	mov    0x8(%rax),%rax
    a606:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    a60a:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a611:	48 8b 40 10          	mov    0x10(%rax),%rax
    a615:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    a619:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a620:	48 8b 40 18          	mov    0x18(%rax),%rax
    a624:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    a628:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a62f:	48 8b 40 20          	mov    0x20(%rax),%rax
    a633:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    a637:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a63e:	48 8b 40 28          	mov    0x28(%rax),%rax
    a642:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    a646:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a64d:	48 8b 40 30          	mov    0x30(%rax),%rax
    a651:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    a655:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a65c:	48 8b 40 38          	mov    0x38(%rax),%rax
    a660:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    a664:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    a66b:	48 c1 c8 10          	ror    $0x10,%rax
    a66f:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    a673:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a677:	48 c1 c8 10          	ror    $0x10,%rax
    a67b:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    a67f:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a683:	48 c1 c8 10          	ror    $0x10,%rax
    a687:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    a68b:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a68f:	48 c1 c8 10          	ror    $0x10,%rax
    a693:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    a697:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a69b:	48 c1 c8 10          	ror    $0x10,%rax
    a69f:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    a6a3:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a6a7:	48 c1 c8 10          	ror    $0x10,%rax
    a6ab:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    a6af:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a6b3:	48 c1 c8 10          	ror    $0x10,%rax
    a6b7:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    a6bb:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    a6bf:	48 c1 c8 10          	ror    $0x10,%rax
    a6c3:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    a6c7:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    a6cb:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    a6cf:	48 33 45 b8          	xor    -0x48(%rbp),%rax
    a6d3:	48 89 c3             	mov    %rax,%rbx
    a6d6:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    a6dd:	48 33 45 b8          	xor    -0x48(%rbp),%rax
    a6e1:	48 89 c7             	mov    %rax,%rdi
    a6e4:	e8 dc fe ff ff       	call   a5c5 <rotr32>
    a6e9:	48 31 c3             	xor    %rax,%rbx
    a6ec:	48 89 da             	mov    %rbx,%rdx
    a6ef:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    a6f6:	48 89 10             	mov    %rdx,(%rax)
    a6f9:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    a700:	48 33 45 b8          	xor    -0x48(%rbp),%rax
    a704:	48 33 45 b0          	xor    -0x50(%rbp),%rax
    a708:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    a70c:	48 33 45 c0          	xor    -0x40(%rbp),%rax
    a710:	48 89 c3             	mov    %rax,%rbx
    a713:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a717:	48 33 45 c0          	xor    -0x40(%rbp),%rax
    a71b:	48 89 c7             	mov    %rax,%rdi
    a71e:	e8 a2 fe ff ff       	call   a5c5 <rotr32>
    a723:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a72a:	48 83 c2 08          	add    $0x8,%rdx
    a72e:	48 31 d8             	xor    %rbx,%rax
    a731:	48 89 02             	mov    %rax,(%rdx)
    a734:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a738:	48 33 45 c0          	xor    -0x40(%rbp),%rax
    a73c:	48 33 45 c8          	xor    -0x38(%rbp),%rax
    a740:	48 89 c3             	mov    %rax,%rbx
    a743:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a747:	48 33 45 c8          	xor    -0x38(%rbp),%rax
    a74b:	48 89 c7             	mov    %rax,%rdi
    a74e:	e8 72 fe ff ff       	call   a5c5 <rotr32>
    a753:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a75a:	48 83 c2 10          	add    $0x10,%rdx
    a75e:	48 31 d8             	xor    %rbx,%rax
    a761:	48 89 02             	mov    %rax,(%rdx)
    a764:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a768:	48 33 45 c8          	xor    -0x38(%rbp),%rax
    a76c:	48 33 45 b0          	xor    -0x50(%rbp),%rax
    a770:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    a774:	48 33 45 d0          	xor    -0x30(%rbp),%rax
    a778:	48 89 c3             	mov    %rax,%rbx
    a77b:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a77f:	48 33 45 d0          	xor    -0x30(%rbp),%rax
    a783:	48 89 c7             	mov    %rax,%rdi
    a786:	e8 3a fe ff ff       	call   a5c5 <rotr32>
    a78b:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a792:	48 83 c2 18          	add    $0x18,%rdx
    a796:	48 31 d8             	xor    %rbx,%rax
    a799:	48 89 02             	mov    %rax,(%rdx)
    a79c:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a7a0:	48 33 45 d0          	xor    -0x30(%rbp),%rax
    a7a4:	48 33 45 b0          	xor    -0x50(%rbp),%rax
    a7a8:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    a7ac:	48 33 45 d8          	xor    -0x28(%rbp),%rax
    a7b0:	48 89 c3             	mov    %rax,%rbx
    a7b3:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a7b7:	48 33 45 d8          	xor    -0x28(%rbp),%rax
    a7bb:	48 89 c7             	mov    %rax,%rdi
    a7be:	e8 02 fe ff ff       	call   a5c5 <rotr32>
    a7c3:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a7ca:	48 83 c2 20          	add    $0x20,%rdx
    a7ce:	48 31 d8             	xor    %rbx,%rax
    a7d1:	48 89 02             	mov    %rax,(%rdx)
    a7d4:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a7d8:	48 33 45 d8          	xor    -0x28(%rbp),%rax
    a7dc:	48 33 45 e0          	xor    -0x20(%rbp),%rax
    a7e0:	48 89 c3             	mov    %rax,%rbx
    a7e3:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a7e7:	48 33 45 e0          	xor    -0x20(%rbp),%rax
    a7eb:	48 89 c7             	mov    %rax,%rdi
    a7ee:	e8 d2 fd ff ff       	call   a5c5 <rotr32>
    a7f3:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a7fa:	48 83 c2 28          	add    $0x28,%rdx
    a7fe:	48 31 d8             	xor    %rbx,%rax
    a801:	48 89 02             	mov    %rax,(%rdx)
    a804:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a808:	48 33 45 e0          	xor    -0x20(%rbp),%rax
    a80c:	48 33 45 e8          	xor    -0x18(%rbp),%rax
    a810:	48 89 c3             	mov    %rax,%rbx
    a813:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a817:	48 33 45 e8          	xor    -0x18(%rbp),%rax
    a81b:	48 89 c7             	mov    %rax,%rdi
    a81e:	e8 a2 fd ff ff       	call   a5c5 <rotr32>
    a823:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a82a:	48 83 c2 30          	add    $0x30,%rdx
    a82e:	48 31 d8             	xor    %rbx,%rax
    a831:	48 89 02             	mov    %rax,(%rdx)
    a834:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a838:	48 33 45 e8          	xor    -0x18(%rbp),%rax
    a83c:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    a840:	48 89 c3             	mov    %rax,%rbx
    a843:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    a847:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    a84b:	48 89 c7             	mov    %rax,%rdi
    a84e:	e8 72 fd ff ff       	call   a5c5 <rotr32>
    a853:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    a85a:	48 83 c2 38          	add    $0x38,%rdx
    a85e:	48 31 d8             	xor    %rbx,%rax
    a861:	48 89 02             	mov    %rax,(%rdx)
    a864:	90                   	nop
    a865:	48 81 c4 88 00 00 00 	add    $0x88,%rsp
    a86c:	5b                   	pop    %rbx
    a86d:	5d                   	pop    %rbp
    a86e:	c3                   	ret

000000000000a86f <inc4_be>:
    a86f:	f3 0f 1e fa          	endbr64
    a873:	55                   	push   %rbp
    a874:	48 89 e5             	mov    %rsp,%rbp
    a877:	48 83 ec 18          	sub    $0x18,%rsp
    a87b:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    a87f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    a883:	8b 00                	mov    (%rax),%eax
    a885:	89 c7                	mov    %eax,%edi
    a887:	e8 01 e1 ff ff       	call   898d <br_swap32>
    a88c:	83 c0 04             	add    $0x4,%eax
    a88f:	89 45 fc             	mov    %eax,-0x4(%rbp)
    a892:	8b 45 fc             	mov    -0x4(%rbp),%eax
    a895:	89 c7                	mov    %eax,%edi
    a897:	e8 f1 e0 ff ff       	call   898d <br_swap32>
    a89c:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    a8a0:	89 02                	mov    %eax,(%rdx)
    a8a2:	90                   	nop
    a8a3:	c9                   	leave
    a8a4:	c3                   	ret

000000000000a8a5 <aes_ecb4x>:
    a8a5:	f3 0f 1e fa          	endbr64
    a8a9:	55                   	push   %rbp
    a8aa:	48 89 e5             	mov    %rsp,%rbp
    a8ad:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
    a8b4:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    a8bb:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
    a8c2:	48 89 95 48 ff ff ff 	mov    %rdx,-0xb8(%rbp)
    a8c9:	89 8d 44 ff ff ff    	mov    %ecx,-0xbc(%rbp)
    a8cf:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    a8d6:	00 00 
    a8d8:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    a8dc:	31 c0                	xor    %eax,%eax
    a8de:	48 8b 8d 50 ff ff ff 	mov    -0xb0(%rbp),%rcx
    a8e5:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    a8ec:	ba 40 00 00 00       	mov    $0x40,%edx
    a8f1:	48 89 ce             	mov    %rcx,%rsi
    a8f4:	48 89 c7             	mov    %rax,%rdi
    a8f7:	e8 34 69 ff ff       	call   1230 <memcpy@plt>
    a8fc:	c7 85 6c ff ff ff 00 	movl   $0x0,-0x94(%rbp)
    a903:	00 00 00 
    a906:	eb 56                	jmp    a95e <aes_ecb4x+0xb9>
    a908:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    a90e:	c1 e0 02             	shl    $0x2,%eax
    a911:	89 c0                	mov    %eax,%eax
    a913:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    a91a:	00 
    a91b:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    a922:	48 01 c2             	add    %rax,%rdx
    a925:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    a92b:	8d 48 04             	lea    0x4(%rax),%ecx
    a92e:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a932:	89 c9                	mov    %ecx,%ecx
    a934:	48 c1 e1 03          	shl    $0x3,%rcx
    a938:	48 01 c1             	add    %rax,%rcx
    a93b:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a93f:	8b b5 6c ff ff ff    	mov    -0x94(%rbp),%esi
    a945:	48 c1 e6 03          	shl    $0x3,%rsi
    a949:	48 01 f0             	add    %rsi,%rax
    a94c:	48 89 ce             	mov    %rcx,%rsi
    a94f:	48 89 c7             	mov    %rax,%rdi
    a952:	e8 8c f2 ff ff       	call   9be3 <br_aes_ct64_interleave_in>
    a957:	83 85 6c ff ff ff 01 	addl   $0x1,-0x94(%rbp)
    a95e:	83 bd 6c ff ff ff 03 	cmpl   $0x3,-0x94(%rbp)
    a965:	76 a1                	jbe    a908 <aes_ecb4x+0x63>
    a967:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a96b:	48 89 c7             	mov    %rax,%rdi
    a96e:	e8 3a eb ff ff       	call   94ad <br_aes_ct64_ortho>
    a973:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    a97a:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a97e:	48 89 d6             	mov    %rdx,%rsi
    a981:	48 89 c7             	mov    %rax,%rdi
    a984:	e8 2a fa ff ff       	call   a3b3 <add_round_key>
    a989:	c7 85 6c ff ff ff 01 	movl   $0x1,-0x94(%rbp)
    a990:	00 00 00 
    a993:	eb 57                	jmp    a9ec <aes_ecb4x+0x147>
    a995:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a999:	48 89 c7             	mov    %rax,%rdi
    a99c:	e8 b7 e0 ff ff       	call   8a58 <br_aes_ct64_bitslice_Sbox>
    a9a1:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a9a5:	48 89 c7             	mov    %rax,%rdi
    a9a8:	e8 29 fb ff ff       	call   a4d6 <shift_rows>
    a9ad:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a9b1:	48 89 c7             	mov    %rax,%rdi
    a9b4:	e8 1e fc ff ff       	call   a5d7 <mix_columns>
    a9b9:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    a9bf:	c1 e0 03             	shl    $0x3,%eax
    a9c2:	89 c0                	mov    %eax,%eax
    a9c4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a9cb:	00 
    a9cc:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    a9d3:	48 01 c2             	add    %rax,%rdx
    a9d6:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a9da:	48 89 d6             	mov    %rdx,%rsi
    a9dd:	48 89 c7             	mov    %rax,%rdi
    a9e0:	e8 ce f9 ff ff       	call   a3b3 <add_round_key>
    a9e5:	83 85 6c ff ff ff 01 	addl   $0x1,-0x94(%rbp)
    a9ec:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    a9f2:	3b 85 44 ff ff ff    	cmp    -0xbc(%rbp),%eax
    a9f8:	72 9b                	jb     a995 <aes_ecb4x+0xf0>
    a9fa:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    a9fe:	48 89 c7             	mov    %rax,%rdi
    aa01:	e8 52 e0 ff ff       	call   8a58 <br_aes_ct64_bitslice_Sbox>
    aa06:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    aa0a:	48 89 c7             	mov    %rax,%rdi
    aa0d:	e8 c4 fa ff ff       	call   a4d6 <shift_rows>
    aa12:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    aa18:	c1 e0 03             	shl    $0x3,%eax
    aa1b:	89 c0                	mov    %eax,%eax
    aa1d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    aa24:	00 
    aa25:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    aa2c:	48 01 c2             	add    %rax,%rdx
    aa2f:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    aa33:	48 89 d6             	mov    %rdx,%rsi
    aa36:	48 89 c7             	mov    %rax,%rdi
    aa39:	e8 75 f9 ff ff       	call   a3b3 <add_round_key>
    aa3e:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    aa42:	48 89 c7             	mov    %rax,%rdi
    aa45:	e8 63 ea ff ff       	call   94ad <br_aes_ct64_ortho>
    aa4a:	c7 85 6c ff ff ff 00 	movl   $0x0,-0x94(%rbp)
    aa51:	00 00 00 
    aa54:	eb 4a                	jmp    aaa0 <aes_ecb4x+0x1fb>
    aa56:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    aa5c:	83 c0 04             	add    $0x4,%eax
    aa5f:	89 c0                	mov    %eax,%eax
    aa61:	48 8b 54 c5 b0       	mov    -0x50(%rbp,%rax,8),%rdx
    aa66:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    aa6c:	48 8b 4c c5 b0       	mov    -0x50(%rbp,%rax,8),%rcx
    aa71:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    aa77:	c1 e0 02             	shl    $0x2,%eax
    aa7a:	89 c0                	mov    %eax,%eax
    aa7c:	48 8d 34 85 00 00 00 	lea    0x0(,%rax,4),%rsi
    aa83:	00 
    aa84:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    aa8b:	48 01 f0             	add    %rsi,%rax
    aa8e:	48 89 ce             	mov    %rcx,%rsi
    aa91:	48 89 c7             	mov    %rax,%rdi
    aa94:	e8 93 f2 ff ff       	call   9d2c <br_aes_ct64_interleave_out>
    aa99:	83 85 6c ff ff ff 01 	addl   $0x1,-0x94(%rbp)
    aaa0:	83 bd 6c ff ff ff 03 	cmpl   $0x3,-0x94(%rbp)
    aaa7:	76 ad                	jbe    aa56 <aes_ecb4x+0x1b1>
    aaa9:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    aab0:	48 8b 8d 58 ff ff ff 	mov    -0xa8(%rbp),%rcx
    aab7:	ba 10 00 00 00       	mov    $0x10,%edx
    aabc:	48 89 c6             	mov    %rax,%rsi
    aabf:	48 89 cf             	mov    %rcx,%rdi
    aac2:	e8 41 df ff ff       	call   8a08 <br_range_enc32le>
    aac7:	90                   	nop
    aac8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    aacc:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    aad3:	00 00 
    aad5:	74 05                	je     aadc <aes_ecb4x+0x237>
    aad7:	e8 f4 66 ff ff       	call   11d0 <__stack_chk_fail@plt>
    aadc:	c9                   	leave
    aadd:	c3                   	ret

000000000000aade <aes_ctr4x>:
    aade:	f3 0f 1e fa          	endbr64
    aae2:	55                   	push   %rbp
    aae3:	48 89 e5             	mov    %rsp,%rbp
    aae6:	48 83 ec 20          	sub    $0x20,%rsp
    aaea:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    aaee:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    aaf2:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    aaf6:	89 4d e4             	mov    %ecx,-0x1c(%rbp)
    aaf9:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    aafc:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    ab00:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    ab04:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ab08:	48 89 c7             	mov    %rax,%rdi
    ab0b:	e8 95 fd ff ff       	call   a8a5 <aes_ecb4x>
    ab10:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ab14:	48 83 c0 0c          	add    $0xc,%rax
    ab18:	48 89 c7             	mov    %rax,%rdi
    ab1b:	e8 4f fd ff ff       	call   a86f <inc4_be>
    ab20:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ab24:	48 83 c0 1c          	add    $0x1c,%rax
    ab28:	48 89 c7             	mov    %rax,%rdi
    ab2b:	e8 3f fd ff ff       	call   a86f <inc4_be>
    ab30:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ab34:	48 83 c0 2c          	add    $0x2c,%rax
    ab38:	48 89 c7             	mov    %rax,%rdi
    ab3b:	e8 2f fd ff ff       	call   a86f <inc4_be>
    ab40:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ab44:	48 83 c0 3c          	add    $0x3c,%rax
    ab48:	48 89 c7             	mov    %rax,%rdi
    ab4b:	e8 1f fd ff ff       	call   a86f <inc4_be>
    ab50:	90                   	nop
    ab51:	c9                   	leave
    ab52:	c3                   	ret

000000000000ab53 <aes_ecb>:
    ab53:	f3 0f 1e fa          	endbr64
    ab57:	55                   	push   %rbp
    ab58:	48 89 e5             	mov    %rsp,%rbp
    ab5b:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
    ab62:	48 89 bd 68 ff ff ff 	mov    %rdi,-0x98(%rbp)
    ab69:	48 89 b5 60 ff ff ff 	mov    %rsi,-0xa0(%rbp)
    ab70:	48 89 95 58 ff ff ff 	mov    %rdx,-0xa8(%rbp)
    ab77:	48 89 8d 50 ff ff ff 	mov    %rcx,-0xb0(%rbp)
    ab7e:	44 89 85 4c ff ff ff 	mov    %r8d,-0xb4(%rbp)
    ab85:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    ab8c:	00 00 
    ab8e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ab92:	31 c0                	xor    %eax,%eax
    ab94:	eb 56                	jmp    abec <aes_ecb+0x99>
    ab96:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    ab9d:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    aba4:	be 10 00 00 00       	mov    $0x10,%esi
    aba9:	48 89 c7             	mov    %rax,%rdi
    abac:	e8 88 dd ff ff       	call   8939 <br_range_dec32le>
    abb1:	8b 8d 4c ff ff ff    	mov    -0xb4(%rbp),%ecx
    abb7:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    abbe:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    abc5:	48 8b bd 68 ff ff ff 	mov    -0x98(%rbp),%rdi
    abcc:	48 89 c6             	mov    %rax,%rsi
    abcf:	e8 d1 fc ff ff       	call   a8a5 <aes_ecb4x>
    abd4:	48 83 ad 58 ff ff ff 	subq   $0x4,-0xa8(%rbp)
    abdb:	04 
    abdc:	48 83 85 60 ff ff ff 	addq   $0x40,-0xa0(%rbp)
    abe3:	40 
    abe4:	48 83 85 68 ff ff ff 	addq   $0x40,-0x98(%rbp)
    abeb:	40 
    abec:	48 83 bd 58 ff ff ff 	cmpq   $0x3,-0xa8(%rbp)
    abf3:	03 
    abf4:	77 a0                	ja     ab96 <aes_ecb+0x43>
    abf6:	48 83 bd 58 ff ff ff 	cmpq   $0x0,-0xa8(%rbp)
    abfd:	00 
    abfe:	74 6c                	je     ac6c <aes_ecb+0x119>
    ac00:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    ac07:	48 8d 0c 85 00 00 00 	lea    0x0(,%rax,4),%rcx
    ac0e:	00 
    ac0f:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    ac16:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    ac1d:	48 89 ce             	mov    %rcx,%rsi
    ac20:	48 89 c7             	mov    %rax,%rdi
    ac23:	e8 11 dd ff ff       	call   8939 <br_range_dec32le>
    ac28:	8b 8d 4c ff ff ff    	mov    -0xb4(%rbp),%ecx
    ac2e:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    ac35:	48 8d b5 70 ff ff ff 	lea    -0x90(%rbp),%rsi
    ac3c:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    ac40:	48 89 c7             	mov    %rax,%rdi
    ac43:	e8 5d fc ff ff       	call   a8a5 <aes_ecb4x>
    ac48:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    ac4f:	48 c1 e0 04          	shl    $0x4,%rax
    ac53:	48 89 c2             	mov    %rax,%rdx
    ac56:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    ac5a:	48 8b 8d 68 ff ff ff 	mov    -0x98(%rbp),%rcx
    ac61:	48 89 c6             	mov    %rax,%rsi
    ac64:	48 89 cf             	mov    %rcx,%rdi
    ac67:	e8 c4 65 ff ff       	call   1230 <memcpy@plt>
    ac6c:	90                   	nop
    ac6d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ac71:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    ac78:	00 00 
    ac7a:	74 05                	je     ac81 <aes_ecb+0x12e>
    ac7c:	e8 4f 65 ff ff       	call   11d0 <__stack_chk_fail@plt>
    ac81:	c9                   	leave
    ac82:	c3                   	ret

000000000000ac83 <aes_ctr>:
    ac83:	f3 0f 1e fa          	endbr64
    ac87:	55                   	push   %rbp
    ac88:	48 89 e5             	mov    %rsp,%rbp
    ac8b:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
    ac92:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    ac99:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
    aca0:	48 89 95 48 ff ff ff 	mov    %rdx,-0xb8(%rbp)
    aca7:	48 89 8d 40 ff ff ff 	mov    %rcx,-0xc0(%rbp)
    acae:	44 89 85 3c ff ff ff 	mov    %r8d,-0xc4(%rbp)
    acb5:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    acbc:	00 00 
    acbe:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    acc2:	31 c0                	xor    %eax,%eax
    acc4:	c7 85 64 ff ff ff 00 	movl   $0x0,-0x9c(%rbp)
    accb:	00 00 00 
    acce:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    acd5:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    acdc:	be 03 00 00 00       	mov    $0x3,%esi
    ace1:	48 89 c7             	mov    %rax,%rdi
    ace4:	e8 50 dc ff ff       	call   8939 <br_range_dec32le>
    ace9:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    acf0:	48 83 c0 10          	add    $0x10,%rax
    acf4:	48 8d 8d 70 ff ff ff 	lea    -0x90(%rbp),%rcx
    acfb:	ba 0c 00 00 00       	mov    $0xc,%edx
    ad00:	48 89 ce             	mov    %rcx,%rsi
    ad03:	48 89 c7             	mov    %rax,%rdi
    ad06:	e8 25 65 ff ff       	call   1230 <memcpy@plt>
    ad0b:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    ad12:	48 83 c0 20          	add    $0x20,%rax
    ad16:	48 8d 8d 70 ff ff ff 	lea    -0x90(%rbp),%rcx
    ad1d:	ba 0c 00 00 00       	mov    $0xc,%edx
    ad22:	48 89 ce             	mov    %rcx,%rsi
    ad25:	48 89 c7             	mov    %rax,%rdi
    ad28:	e8 03 65 ff ff       	call   1230 <memcpy@plt>
    ad2d:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    ad34:	48 83 c0 30          	add    $0x30,%rax
    ad38:	48 8d 8d 70 ff ff ff 	lea    -0x90(%rbp),%rcx
    ad3f:	ba 0c 00 00 00       	mov    $0xc,%edx
    ad44:	48 89 ce             	mov    %rcx,%rsi
    ad47:	48 89 c7             	mov    %rax,%rdi
    ad4a:	e8 e1 64 ff ff       	call   1230 <memcpy@plt>
    ad4f:	8b 85 64 ff ff ff    	mov    -0x9c(%rbp),%eax
    ad55:	89 c7                	mov    %eax,%edi
    ad57:	e8 31 dc ff ff       	call   898d <br_swap32>
    ad5c:	89 85 7c ff ff ff    	mov    %eax,-0x84(%rbp)
    ad62:	8b 85 64 ff ff ff    	mov    -0x9c(%rbp),%eax
    ad68:	83 c0 01             	add    $0x1,%eax
    ad6b:	89 c7                	mov    %eax,%edi
    ad6d:	e8 1b dc ff ff       	call   898d <br_swap32>
    ad72:	89 45 8c             	mov    %eax,-0x74(%rbp)
    ad75:	8b 85 64 ff ff ff    	mov    -0x9c(%rbp),%eax
    ad7b:	83 c0 02             	add    $0x2,%eax
    ad7e:	89 c7                	mov    %eax,%edi
    ad80:	e8 08 dc ff ff       	call   898d <br_swap32>
    ad85:	89 45 9c             	mov    %eax,-0x64(%rbp)
    ad88:	8b 85 64 ff ff ff    	mov    -0x9c(%rbp),%eax
    ad8e:	83 c0 03             	add    $0x3,%eax
    ad91:	89 c7                	mov    %eax,%edi
    ad93:	e8 f5 db ff ff       	call   898d <br_swap32>
    ad98:	89 45 ac             	mov    %eax,-0x54(%rbp)
    ad9b:	eb 33                	jmp    add0 <aes_ctr+0x14d>
    ad9d:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    ada3:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    adaa:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    adb1:	48 8b bd 58 ff ff ff 	mov    -0xa8(%rbp),%rdi
    adb8:	48 89 c6             	mov    %rax,%rsi
    adbb:	e8 1e fd ff ff       	call   aade <aes_ctr4x>
    adc0:	48 83 85 58 ff ff ff 	addq   $0x40,-0xa8(%rbp)
    adc7:	40 
    adc8:	48 83 ad 50 ff ff ff 	subq   $0x40,-0xb0(%rbp)
    adcf:	40 
    add0:	48 83 bd 50 ff ff ff 	cmpq   $0x40,-0xb0(%rbp)
    add7:	40 
    add8:	77 c3                	ja     ad9d <aes_ctr+0x11a>
    adda:	48 83 bd 50 ff ff ff 	cmpq   $0x0,-0xb0(%rbp)
    ade1:	00 
    ade2:	74 69                	je     ae4d <aes_ctr+0x1ca>
    ade4:	8b 8d 3c ff ff ff    	mov    -0xc4(%rbp),%ecx
    adea:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    adf1:	48 8d b5 70 ff ff ff 	lea    -0x90(%rbp),%rsi
    adf8:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    adfc:	48 89 c7             	mov    %rax,%rdi
    adff:	e8 da fc ff ff       	call   aade <aes_ctr4x>
    ae04:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
    ae0b:	00 00 00 00 
    ae0f:	eb 2c                	jmp    ae3d <aes_ctr+0x1ba>
    ae11:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    ae18:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    ae1f:	48 01 c2             	add    %rax,%rdx
    ae22:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    ae26:	48 8b 8d 68 ff ff ff 	mov    -0x98(%rbp),%rcx
    ae2d:	48 01 c8             	add    %rcx,%rax
    ae30:	0f b6 00             	movzbl (%rax),%eax
    ae33:	88 02                	mov    %al,(%rdx)
    ae35:	48 83 85 68 ff ff ff 	addq   $0x1,-0x98(%rbp)
    ae3c:	01 
    ae3d:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    ae44:	48 3b 85 50 ff ff ff 	cmp    -0xb0(%rbp),%rax
    ae4b:	72 c4                	jb     ae11 <aes_ctr+0x18e>
    ae4d:	90                   	nop
    ae4e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae52:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    ae59:	00 00 
    ae5b:	74 05                	je     ae62 <aes_ctr+0x1df>
    ae5d:	e8 6e 63 ff ff       	call   11d0 <__stack_chk_fail@plt>
    ae62:	c9                   	leave
    ae63:	c3                   	ret

000000000000ae64 <aes128_ecb_keyexp>:
    ae64:	f3 0f 1e fa          	endbr64
    ae68:	55                   	push   %rbp
    ae69:	48 89 e5             	mov    %rsp,%rbp
    ae6c:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
    ae73:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    ae7a:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    ae81:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    ae88:	00 00 
    ae8a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ae8e:	31 c0                	xor    %eax,%eax
    ae90:	bf c0 02 00 00       	mov    $0x2c0,%edi
    ae95:	e8 a6 63 ff ff       	call   1240 <malloc@plt>
    ae9a:	48 89 c2             	mov    %rax,%rdx
    ae9d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    aea4:	48 89 10             	mov    %rdx,(%rax)
    aea7:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    aeae:	48 8b 00             	mov    (%rax),%rax
    aeb1:	48 85 c0             	test   %rax,%rax
    aeb4:	75 0a                	jne    aec0 <aes128_ecb_keyexp+0x5c>
    aeb6:	bf 6f 00 00 00       	mov    $0x6f,%edi
    aebb:	e8 b0 63 ff ff       	call   1270 <exit@plt>
    aec0:	48 8b 8d 30 ff ff ff 	mov    -0xd0(%rbp),%rcx
    aec7:	48 8d 85 40 ff ff ff 	lea    -0xc0(%rbp),%rax
    aece:	ba 10 00 00 00       	mov    $0x10,%edx
    aed3:	48 89 ce             	mov    %rcx,%rsi
    aed6:	48 89 c7             	mov    %rax,%rdi
    aed9:	e8 0c f0 ff ff       	call   9eea <br_aes_ct64_keysched>
    aede:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    aee5:	48 8b 08             	mov    (%rax),%rcx
    aee8:	48 8d 85 40 ff ff ff 	lea    -0xc0(%rbp),%rax
    aeef:	ba 0a 00 00 00       	mov    $0xa,%edx
    aef4:	48 89 c6             	mov    %rax,%rsi
    aef7:	48 89 cf             	mov    %rcx,%rdi
    aefa:	e8 61 f3 ff ff       	call   a260 <br_aes_ct64_skey_expand>
    aeff:	90                   	nop
    af00:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af04:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    af0b:	00 00 
    af0d:	74 05                	je     af14 <aes128_ecb_keyexp+0xb0>
    af0f:	e8 bc 62 ff ff       	call   11d0 <__stack_chk_fail@plt>
    af14:	c9                   	leave
    af15:	c3                   	ret

000000000000af16 <aes128_ctr_keyexp>:
    af16:	f3 0f 1e fa          	endbr64
    af1a:	55                   	push   %rbp
    af1b:	48 89 e5             	mov    %rsp,%rbp
    af1e:	48 83 ec 10          	sub    $0x10,%rsp
    af22:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    af26:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    af2a:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    af2e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af32:	48 89 d6             	mov    %rdx,%rsi
    af35:	48 89 c7             	mov    %rax,%rdi
    af38:	e8 27 ff ff ff       	call   ae64 <aes128_ecb_keyexp>
    af3d:	90                   	nop
    af3e:	c9                   	leave
    af3f:	c3                   	ret

000000000000af40 <aes192_ecb_keyexp>:
    af40:	f3 0f 1e fa          	endbr64
    af44:	55                   	push   %rbp
    af45:	48 89 e5             	mov    %rsp,%rbp
    af48:	48 81 ec f0 00 00 00 	sub    $0xf0,%rsp
    af4f:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
    af56:	48 89 b5 10 ff ff ff 	mov    %rsi,-0xf0(%rbp)
    af5d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    af64:	00 00 
    af66:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    af6a:	31 c0                	xor    %eax,%eax
    af6c:	bf 40 03 00 00       	mov    $0x340,%edi
    af71:	e8 ca 62 ff ff       	call   1240 <malloc@plt>
    af76:	48 89 c2             	mov    %rax,%rdx
    af79:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    af80:	48 89 10             	mov    %rdx,(%rax)
    af83:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    af8a:	48 8b 00             	mov    (%rax),%rax
    af8d:	48 85 c0             	test   %rax,%rax
    af90:	75 0a                	jne    af9c <aes192_ecb_keyexp+0x5c>
    af92:	bf 6f 00 00 00       	mov    $0x6f,%edi
    af97:	e8 d4 62 ff ff       	call   1270 <exit@plt>
    af9c:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    afa3:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    afaa:	ba 18 00 00 00       	mov    $0x18,%edx
    afaf:	48 89 ce             	mov    %rcx,%rsi
    afb2:	48 89 c7             	mov    %rax,%rdi
    afb5:	e8 30 ef ff ff       	call   9eea <br_aes_ct64_keysched>
    afba:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    afc1:	48 8b 08             	mov    (%rax),%rcx
    afc4:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    afcb:	ba 0c 00 00 00       	mov    $0xc,%edx
    afd0:	48 89 c6             	mov    %rax,%rsi
    afd3:	48 89 cf             	mov    %rcx,%rdi
    afd6:	e8 85 f2 ff ff       	call   a260 <br_aes_ct64_skey_expand>
    afdb:	90                   	nop
    afdc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    afe0:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    afe7:	00 00 
    afe9:	74 05                	je     aff0 <aes192_ecb_keyexp+0xb0>
    afeb:	e8 e0 61 ff ff       	call   11d0 <__stack_chk_fail@plt>
    aff0:	c9                   	leave
    aff1:	c3                   	ret

000000000000aff2 <aes192_ctr_keyexp>:
    aff2:	f3 0f 1e fa          	endbr64
    aff6:	55                   	push   %rbp
    aff7:	48 89 e5             	mov    %rsp,%rbp
    affa:	48 83 ec 10          	sub    $0x10,%rsp
    affe:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b002:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b006:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    b00a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b00e:	48 89 d6             	mov    %rdx,%rsi
    b011:	48 89 c7             	mov    %rax,%rdi
    b014:	e8 27 ff ff ff       	call   af40 <aes192_ecb_keyexp>
    b019:	90                   	nop
    b01a:	c9                   	leave
    b01b:	c3                   	ret

000000000000b01c <aes256_ecb_keyexp>:
    b01c:	f3 0f 1e fa          	endbr64
    b020:	55                   	push   %rbp
    b021:	48 89 e5             	mov    %rsp,%rbp
    b024:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    b02b:	48 89 bd f8 fe ff ff 	mov    %rdi,-0x108(%rbp)
    b032:	48 89 b5 f0 fe ff ff 	mov    %rsi,-0x110(%rbp)
    b039:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b040:	00 00 
    b042:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    b046:	31 c0                	xor    %eax,%eax
    b048:	bf c0 03 00 00       	mov    $0x3c0,%edi
    b04d:	e8 ee 61 ff ff       	call   1240 <malloc@plt>
    b052:	48 89 c2             	mov    %rax,%rdx
    b055:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    b05c:	48 89 10             	mov    %rdx,(%rax)
    b05f:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    b066:	48 8b 00             	mov    (%rax),%rax
    b069:	48 85 c0             	test   %rax,%rax
    b06c:	75 0a                	jne    b078 <aes256_ecb_keyexp+0x5c>
    b06e:	bf 6f 00 00 00       	mov    $0x6f,%edi
    b073:	e8 f8 61 ff ff       	call   1270 <exit@plt>
    b078:	48 8b 8d f0 fe ff ff 	mov    -0x110(%rbp),%rcx
    b07f:	48 8d 85 00 ff ff ff 	lea    -0x100(%rbp),%rax
    b086:	ba 20 00 00 00       	mov    $0x20,%edx
    b08b:	48 89 ce             	mov    %rcx,%rsi
    b08e:	48 89 c7             	mov    %rax,%rdi
    b091:	e8 54 ee ff ff       	call   9eea <br_aes_ct64_keysched>
    b096:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    b09d:	48 8b 08             	mov    (%rax),%rcx
    b0a0:	48 8d 85 00 ff ff ff 	lea    -0x100(%rbp),%rax
    b0a7:	ba 0e 00 00 00       	mov    $0xe,%edx
    b0ac:	48 89 c6             	mov    %rax,%rsi
    b0af:	48 89 cf             	mov    %rcx,%rdi
    b0b2:	e8 a9 f1 ff ff       	call   a260 <br_aes_ct64_skey_expand>
    b0b7:	90                   	nop
    b0b8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b0bc:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    b0c3:	00 00 
    b0c5:	74 05                	je     b0cc <aes256_ecb_keyexp+0xb0>
    b0c7:	e8 04 61 ff ff       	call   11d0 <__stack_chk_fail@plt>
    b0cc:	c9                   	leave
    b0cd:	c3                   	ret

000000000000b0ce <aes256_ctr_keyexp>:
    b0ce:	f3 0f 1e fa          	endbr64
    b0d2:	55                   	push   %rbp
    b0d3:	48 89 e5             	mov    %rsp,%rbp
    b0d6:	48 83 ec 10          	sub    $0x10,%rsp
    b0da:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b0de:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b0e2:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    b0e6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b0ea:	48 89 d6             	mov    %rdx,%rsi
    b0ed:	48 89 c7             	mov    %rax,%rdi
    b0f0:	e8 27 ff ff ff       	call   b01c <aes256_ecb_keyexp>
    b0f5:	90                   	nop
    b0f6:	c9                   	leave
    b0f7:	c3                   	ret

000000000000b0f8 <aes128_ecb>:
    b0f8:	f3 0f 1e fa          	endbr64
    b0fc:	55                   	push   %rbp
    b0fd:	48 89 e5             	mov    %rsp,%rbp
    b100:	48 83 ec 20          	sub    $0x20,%rsp
    b104:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b108:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b10c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b110:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    b114:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b118:	48 8b 08             	mov    (%rax),%rcx
    b11b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b11f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    b123:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b127:	41 b8 0a 00 00 00    	mov    $0xa,%r8d
    b12d:	48 89 c7             	mov    %rax,%rdi
    b130:	e8 1e fa ff ff       	call   ab53 <aes_ecb>
    b135:	90                   	nop
    b136:	c9                   	leave
    b137:	c3                   	ret

000000000000b138 <aes128_ctr>:
    b138:	f3 0f 1e fa          	endbr64
    b13c:	55                   	push   %rbp
    b13d:	48 89 e5             	mov    %rsp,%rbp
    b140:	48 83 ec 20          	sub    $0x20,%rsp
    b144:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b148:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b14c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b150:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    b154:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b158:	48 8b 08             	mov    (%rax),%rcx
    b15b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b15f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    b163:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b167:	41 b8 0a 00 00 00    	mov    $0xa,%r8d
    b16d:	48 89 c7             	mov    %rax,%rdi
    b170:	e8 0e fb ff ff       	call   ac83 <aes_ctr>
    b175:	90                   	nop
    b176:	c9                   	leave
    b177:	c3                   	ret

000000000000b178 <aes192_ecb>:
    b178:	f3 0f 1e fa          	endbr64
    b17c:	55                   	push   %rbp
    b17d:	48 89 e5             	mov    %rsp,%rbp
    b180:	48 83 ec 20          	sub    $0x20,%rsp
    b184:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b188:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b18c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b190:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    b194:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b198:	48 8b 08             	mov    (%rax),%rcx
    b19b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b19f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    b1a3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b1a7:	41 b8 0c 00 00 00    	mov    $0xc,%r8d
    b1ad:	48 89 c7             	mov    %rax,%rdi
    b1b0:	e8 9e f9 ff ff       	call   ab53 <aes_ecb>
    b1b5:	90                   	nop
    b1b6:	c9                   	leave
    b1b7:	c3                   	ret

000000000000b1b8 <aes192_ctr>:
    b1b8:	f3 0f 1e fa          	endbr64
    b1bc:	55                   	push   %rbp
    b1bd:	48 89 e5             	mov    %rsp,%rbp
    b1c0:	48 83 ec 20          	sub    $0x20,%rsp
    b1c4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b1c8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b1cc:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b1d0:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    b1d4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b1d8:	48 8b 08             	mov    (%rax),%rcx
    b1db:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b1df:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    b1e3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b1e7:	41 b8 0c 00 00 00    	mov    $0xc,%r8d
    b1ed:	48 89 c7             	mov    %rax,%rdi
    b1f0:	e8 8e fa ff ff       	call   ac83 <aes_ctr>
    b1f5:	90                   	nop
    b1f6:	c9                   	leave
    b1f7:	c3                   	ret

000000000000b1f8 <aes256_ecb>:
    b1f8:	f3 0f 1e fa          	endbr64
    b1fc:	55                   	push   %rbp
    b1fd:	48 89 e5             	mov    %rsp,%rbp
    b200:	48 83 ec 20          	sub    $0x20,%rsp
    b204:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b208:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b20c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b210:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    b214:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b218:	48 8b 08             	mov    (%rax),%rcx
    b21b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b21f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    b223:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b227:	41 b8 0e 00 00 00    	mov    $0xe,%r8d
    b22d:	48 89 c7             	mov    %rax,%rdi
    b230:	e8 1e f9 ff ff       	call   ab53 <aes_ecb>
    b235:	90                   	nop
    b236:	c9                   	leave
    b237:	c3                   	ret

000000000000b238 <aes256_ctr>:
    b238:	f3 0f 1e fa          	endbr64
    b23c:	55                   	push   %rbp
    b23d:	48 89 e5             	mov    %rsp,%rbp
    b240:	48 83 ec 20          	sub    $0x20,%rsp
    b244:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b248:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b24c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b250:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    b254:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b258:	48 8b 08             	mov    (%rax),%rcx
    b25b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b25f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    b263:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b267:	41 b8 0e 00 00 00    	mov    $0xe,%r8d
    b26d:	48 89 c7             	mov    %rax,%rdi
    b270:	e8 0e fa ff ff       	call   ac83 <aes_ctr>
    b275:	90                   	nop
    b276:	c9                   	leave
    b277:	c3                   	ret

000000000000b278 <aes128_ctx_release>:
    b278:	f3 0f 1e fa          	endbr64
    b27c:	55                   	push   %rbp
    b27d:	48 89 e5             	mov    %rsp,%rbp
    b280:	48 83 ec 10          	sub    $0x10,%rsp
    b284:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b288:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b28c:	48 8b 00             	mov    (%rax),%rax
    b28f:	48 89 c7             	mov    %rax,%rdi
    b292:	e8 d9 5e ff ff       	call   1170 <free@plt>
    b297:	90                   	nop
    b298:	c9                   	leave
    b299:	c3                   	ret

000000000000b29a <aes192_ctx_release>:
    b29a:	f3 0f 1e fa          	endbr64
    b29e:	55                   	push   %rbp
    b29f:	48 89 e5             	mov    %rsp,%rbp
    b2a2:	48 83 ec 10          	sub    $0x10,%rsp
    b2a6:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b2aa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b2ae:	48 8b 00             	mov    (%rax),%rax
    b2b1:	48 89 c7             	mov    %rax,%rdi
    b2b4:	e8 b7 5e ff ff       	call   1170 <free@plt>
    b2b9:	90                   	nop
    b2ba:	c9                   	leave
    b2bb:	c3                   	ret

000000000000b2bc <aes256_ctx_release>:
    b2bc:	f3 0f 1e fa          	endbr64
    b2c0:	55                   	push   %rbp
    b2c1:	48 89 e5             	mov    %rsp,%rbp
    b2c4:	48 83 ec 10          	sub    $0x10,%rsp
    b2c8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b2cc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b2d0:	48 8b 00             	mov    (%rax),%rax
    b2d3:	48 89 c7             	mov    %rax,%rdi
    b2d6:	e8 95 5e ff ff       	call   1170 <free@plt>
    b2db:	90                   	nop
    b2dc:	c9                   	leave
    b2dd:	c3                   	ret

000000000000b2de <AES_128_CTR>:
    b2de:	f3 0f 1e fa          	endbr64
    b2e2:	55                   	push   %rbp
    b2e3:	48 89 e5             	mov    %rsp,%rbp
    b2e6:	48 83 ec 50          	sub    $0x50,%rsp
    b2ea:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    b2ee:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    b2f2:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    b2f6:	48 89 4d b0          	mov    %rcx,-0x50(%rbp)
    b2fa:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b301:	00 00 
    b303:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    b307:	31 c0                	xor    %eax,%eax
    b309:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    b310:	00 
    b311:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    b318:	00 
    b319:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    b31d:	48 8d 45 d8          	lea    -0x28(%rbp),%rax
    b321:	48 89 d6             	mov    %rdx,%rsi
    b324:	48 89 c7             	mov    %rax,%rdi
    b327:	e8 ea fb ff ff       	call   af16 <aes128_ctr_keyexp>
    b32c:	48 8d 55 d8          	lea    -0x28(%rbp),%rdx
    b330:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    b334:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    b338:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
    b33c:	48 89 d1             	mov    %rdx,%rcx
    b33f:	48 89 c2             	mov    %rax,%rdx
    b342:	e8 f1 fd ff ff       	call   b138 <aes128_ctr>
    b347:	48 8d 45 d8          	lea    -0x28(%rbp),%rax
    b34b:	48 89 c7             	mov    %rax,%rdi
    b34e:	e8 25 ff ff ff       	call   b278 <aes128_ctx_release>
    b353:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    b357:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    b35b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    b362:	00 00 
    b364:	74 05                	je     b36b <AES_128_CTR+0x8d>
    b366:	e8 65 5e ff ff       	call   11d0 <__stack_chk_fail@plt>
    b36b:	c9                   	leave
    b36c:	c3                   	ret

000000000000b36d <AES_256_ECB>:
    b36d:	f3 0f 1e fa          	endbr64
    b371:	55                   	push   %rbp
    b372:	48 89 e5             	mov    %rsp,%rbp
    b375:	48 83 ec 30          	sub    $0x30,%rsp
    b379:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    b37d:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    b381:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    b385:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b38c:	00 00 
    b38e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    b392:	31 c0                	xor    %eax,%eax
    b394:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    b398:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    b39c:	48 89 d6             	mov    %rdx,%rsi
    b39f:	48 89 c7             	mov    %rax,%rdi
    b3a2:	e8 75 fc ff ff       	call   b01c <aes256_ecb_keyexp>
    b3a7:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    b3ab:	48 8b 75 e8          	mov    -0x18(%rbp),%rsi
    b3af:	48 8b 7d d8          	mov    -0x28(%rbp),%rdi
    b3b3:	48 89 c1             	mov    %rax,%rcx
    b3b6:	ba 01 00 00 00       	mov    $0x1,%edx
    b3bb:	e8 38 fe ff ff       	call   b1f8 <aes256_ecb>
    b3c0:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    b3c4:	48 89 c7             	mov    %rax,%rdi
    b3c7:	e8 f0 fe ff ff       	call   b2bc <aes256_ctx_release>
    b3cc:	90                   	nop
    b3cd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b3d1:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    b3d8:	00 00 
    b3da:	74 05                	je     b3e1 <AES_256_ECB+0x74>
    b3dc:	e8 ef 5d ff ff       	call   11d0 <__stack_chk_fail@plt>
    b3e1:	c9                   	leave
    b3e2:	c3                   	ret

000000000000b3e3 <load64>:
    b3e3:	f3 0f 1e fa          	endbr64
    b3e7:	55                   	push   %rbp
    b3e8:	48 89 e5             	mov    %rsp,%rbp
    b3eb:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    b3ef:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    b3f6:	00 
    b3f7:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    b3fe:	00 
    b3ff:	eb 29                	jmp    b42a <load64+0x47>
    b401:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b405:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b409:	48 01 d0             	add    %rdx,%rax
    b40c:	0f b6 00             	movzbl (%rax),%eax
    b40f:	0f b6 d0             	movzbl %al,%edx
    b412:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b416:	c1 e0 03             	shl    $0x3,%eax
    b419:	89 c1                	mov    %eax,%ecx
    b41b:	48 d3 e2             	shl    %cl,%rdx
    b41e:	48 89 d0             	mov    %rdx,%rax
    b421:	48 09 45 f0          	or     %rax,-0x10(%rbp)
    b425:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    b42a:	48 83 7d f8 07       	cmpq   $0x7,-0x8(%rbp)
    b42f:	76 d0                	jbe    b401 <load64+0x1e>
    b431:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b435:	5d                   	pop    %rbp
    b436:	c3                   	ret

000000000000b437 <store64>:
    b437:	f3 0f 1e fa          	endbr64
    b43b:	55                   	push   %rbp
    b43c:	48 89 e5             	mov    %rsp,%rbp
    b43f:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    b443:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    b447:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    b44e:	00 
    b44f:	eb 27                	jmp    b478 <store64+0x41>
    b451:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b455:	c1 e0 03             	shl    $0x3,%eax
    b458:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    b45c:	89 c1                	mov    %eax,%ecx
    b45e:	48 d3 ea             	shr    %cl,%rdx
    b461:	48 89 d1             	mov    %rdx,%rcx
    b464:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    b468:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b46c:	48 01 d0             	add    %rdx,%rax
    b46f:	89 ca                	mov    %ecx,%edx
    b471:	88 10                	mov    %dl,(%rax)
    b473:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    b478:	48 83 7d f8 07       	cmpq   $0x7,-0x8(%rbp)
    b47d:	76 d2                	jbe    b451 <store64+0x1a>
    b47f:	90                   	nop
    b480:	90                   	nop
    b481:	5d                   	pop    %rbp
    b482:	c3                   	ret

000000000000b483 <KeccakF1600_StatePermute>:
    b483:	f3 0f 1e fa          	endbr64
    b487:	55                   	push   %rbp
    b488:	48 89 e5             	mov    %rsp,%rbp
    b48b:	48 81 ec 80 01 00 00 	sub    $0x180,%rsp
    b492:	48 89 bd 08 fe ff ff 	mov    %rdi,-0x1f8(%rbp)
    b499:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b4a0:	48 8b 00             	mov    (%rax),%rax
    b4a3:	48 89 85 20 fe ff ff 	mov    %rax,-0x1e0(%rbp)
    b4aa:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b4b1:	48 8b 40 08          	mov    0x8(%rax),%rax
    b4b5:	48 89 85 28 fe ff ff 	mov    %rax,-0x1d8(%rbp)
    b4bc:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b4c3:	48 8b 40 10          	mov    0x10(%rax),%rax
    b4c7:	48 89 85 30 fe ff ff 	mov    %rax,-0x1d0(%rbp)
    b4ce:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b4d5:	48 8b 40 18          	mov    0x18(%rax),%rax
    b4d9:	48 89 85 38 fe ff ff 	mov    %rax,-0x1c8(%rbp)
    b4e0:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b4e7:	48 8b 40 20          	mov    0x20(%rax),%rax
    b4eb:	48 89 85 40 fe ff ff 	mov    %rax,-0x1c0(%rbp)
    b4f2:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b4f9:	48 8b 40 28          	mov    0x28(%rax),%rax
    b4fd:	48 89 85 48 fe ff ff 	mov    %rax,-0x1b8(%rbp)
    b504:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b50b:	48 8b 40 30          	mov    0x30(%rax),%rax
    b50f:	48 89 85 50 fe ff ff 	mov    %rax,-0x1b0(%rbp)
    b516:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b51d:	48 8b 40 38          	mov    0x38(%rax),%rax
    b521:	48 89 85 58 fe ff ff 	mov    %rax,-0x1a8(%rbp)
    b528:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b52f:	48 8b 40 40          	mov    0x40(%rax),%rax
    b533:	48 89 85 60 fe ff ff 	mov    %rax,-0x1a0(%rbp)
    b53a:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b541:	48 8b 40 48          	mov    0x48(%rax),%rax
    b545:	48 89 85 68 fe ff ff 	mov    %rax,-0x198(%rbp)
    b54c:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b553:	48 8b 40 50          	mov    0x50(%rax),%rax
    b557:	48 89 85 70 fe ff ff 	mov    %rax,-0x190(%rbp)
    b55e:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b565:	48 8b 40 58          	mov    0x58(%rax),%rax
    b569:	48 89 85 78 fe ff ff 	mov    %rax,-0x188(%rbp)
    b570:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b577:	48 8b 40 60          	mov    0x60(%rax),%rax
    b57b:	48 89 85 80 fe ff ff 	mov    %rax,-0x180(%rbp)
    b582:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b589:	48 8b 40 68          	mov    0x68(%rax),%rax
    b58d:	48 89 85 88 fe ff ff 	mov    %rax,-0x178(%rbp)
    b594:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b59b:	48 8b 40 70          	mov    0x70(%rax),%rax
    b59f:	48 89 85 90 fe ff ff 	mov    %rax,-0x170(%rbp)
    b5a6:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b5ad:	48 8b 40 78          	mov    0x78(%rax),%rax
    b5b1:	48 89 85 98 fe ff ff 	mov    %rax,-0x168(%rbp)
    b5b8:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b5bf:	48 8b 80 80 00 00 00 	mov    0x80(%rax),%rax
    b5c6:	48 89 85 a0 fe ff ff 	mov    %rax,-0x160(%rbp)
    b5cd:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b5d4:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    b5db:	48 89 85 a8 fe ff ff 	mov    %rax,-0x158(%rbp)
    b5e2:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b5e9:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    b5f0:	48 89 85 b0 fe ff ff 	mov    %rax,-0x150(%rbp)
    b5f7:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b5fe:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    b605:	48 89 85 b8 fe ff ff 	mov    %rax,-0x148(%rbp)
    b60c:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b613:	48 8b 80 a0 00 00 00 	mov    0xa0(%rax),%rax
    b61a:	48 89 85 c0 fe ff ff 	mov    %rax,-0x140(%rbp)
    b621:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b628:	48 8b 80 a8 00 00 00 	mov    0xa8(%rax),%rax
    b62f:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
    b636:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b63d:	48 8b 80 b0 00 00 00 	mov    0xb0(%rax),%rax
    b644:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
    b64b:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b652:	48 8b 80 b8 00 00 00 	mov    0xb8(%rax),%rax
    b659:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    b660:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    b667:	48 8b 80 c0 00 00 00 	mov    0xc0(%rax),%rax
    b66e:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    b675:	c7 85 1c fe ff ff 00 	movl   $0x0,-0x1e4(%rbp)
    b67c:	00 00 00 
    b67f:	e9 66 0e 00 00       	jmp    c4ea <KeccakF1600_StatePermute+0x1067>
    b684:	48 8b 85 20 fe ff ff 	mov    -0x1e0(%rbp),%rax
    b68b:	48 33 85 48 fe ff ff 	xor    -0x1b8(%rbp),%rax
    b692:	48 33 85 70 fe ff ff 	xor    -0x190(%rbp),%rax
    b699:	48 33 85 98 fe ff ff 	xor    -0x168(%rbp),%rax
    b6a0:	48 33 85 c0 fe ff ff 	xor    -0x140(%rbp),%rax
    b6a7:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    b6ae:	48 8b 85 28 fe ff ff 	mov    -0x1d8(%rbp),%rax
    b6b5:	48 33 85 50 fe ff ff 	xor    -0x1b0(%rbp),%rax
    b6bc:	48 33 85 78 fe ff ff 	xor    -0x188(%rbp),%rax
    b6c3:	48 33 85 a0 fe ff ff 	xor    -0x160(%rbp),%rax
    b6ca:	48 33 85 c8 fe ff ff 	xor    -0x138(%rbp),%rax
    b6d1:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    b6d8:	48 8b 85 30 fe ff ff 	mov    -0x1d0(%rbp),%rax
    b6df:	48 33 85 58 fe ff ff 	xor    -0x1a8(%rbp),%rax
    b6e6:	48 33 85 80 fe ff ff 	xor    -0x180(%rbp),%rax
    b6ed:	48 33 85 a8 fe ff ff 	xor    -0x158(%rbp),%rax
    b6f4:	48 33 85 d0 fe ff ff 	xor    -0x130(%rbp),%rax
    b6fb:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    b702:	48 8b 85 38 fe ff ff 	mov    -0x1c8(%rbp),%rax
    b709:	48 33 85 60 fe ff ff 	xor    -0x1a0(%rbp),%rax
    b710:	48 33 85 88 fe ff ff 	xor    -0x178(%rbp),%rax
    b717:	48 33 85 b0 fe ff ff 	xor    -0x150(%rbp),%rax
    b71e:	48 33 85 d8 fe ff ff 	xor    -0x128(%rbp),%rax
    b725:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    b72c:	48 8b 85 40 fe ff ff 	mov    -0x1c0(%rbp),%rax
    b733:	48 33 85 68 fe ff ff 	xor    -0x198(%rbp),%rax
    b73a:	48 33 85 90 fe ff ff 	xor    -0x170(%rbp),%rax
    b741:	48 33 85 b8 fe ff ff 	xor    -0x148(%rbp),%rax
    b748:	48 33 85 e0 fe ff ff 	xor    -0x120(%rbp),%rax
    b74f:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    b756:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    b75d:	48 d1 c0             	rol    $1,%rax
    b760:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    b767:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    b76e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    b775:	48 d1 c0             	rol    $1,%rax
    b778:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    b77f:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    b786:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    b78d:	48 d1 c0             	rol    $1,%rax
    b790:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    b797:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    b79e:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    b7a5:	48 d1 c0             	rol    $1,%rax
    b7a8:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    b7af:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
    b7b6:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    b7bd:	48 d1 c0             	rol    $1,%rax
    b7c0:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    b7c7:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
    b7ce:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    b7d5:	48 31 85 20 fe ff ff 	xor    %rax,-0x1e0(%rbp)
    b7dc:	48 8b 85 20 fe ff ff 	mov    -0x1e0(%rbp),%rax
    b7e3:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    b7ea:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    b7f1:	48 31 85 50 fe ff ff 	xor    %rax,-0x1b0(%rbp)
    b7f8:	48 8b 85 50 fe ff ff 	mov    -0x1b0(%rbp),%rax
    b7ff:	48 c1 c8 14          	ror    $0x14,%rax
    b803:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    b80a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    b811:	48 31 85 80 fe ff ff 	xor    %rax,-0x180(%rbp)
    b818:	48 8b 85 80 fe ff ff 	mov    -0x180(%rbp),%rax
    b81f:	48 c1 c8 15          	ror    $0x15,%rax
    b823:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    b82a:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    b831:	48 31 85 b0 fe ff ff 	xor    %rax,-0x150(%rbp)
    b838:	48 8b 85 b0 fe ff ff 	mov    -0x150(%rbp),%rax
    b83f:	48 c1 c0 15          	rol    $0x15,%rax
    b843:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    b84a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    b851:	48 31 85 e0 fe ff ff 	xor    %rax,-0x120(%rbp)
    b858:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    b85f:	48 c1 c0 0e          	rol    $0xe,%rax
    b863:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    b86a:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    b871:	48 f7 d0             	not    %rax
    b874:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    b87b:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    b882:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    b889:	8b 85 1c fe ff ff    	mov    -0x1e4(%rbp),%eax
    b88f:	48 98                	cltq
    b891:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    b898:	00 
    b899:	48 8d 05 20 29 00 00 	lea    0x2920(%rip),%rax        # e1c0 <KeccakF_RoundConstants>
    b8a0:	48 8b 04 02          	mov    (%rdx,%rax,1),%rax
    b8a4:	48 31 85 38 ff ff ff 	xor    %rax,-0xc8(%rbp)
    b8ab:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    b8b2:	48 f7 d0             	not    %rax
    b8b5:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    b8bc:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    b8c3:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    b8ca:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    b8d1:	48 f7 d0             	not    %rax
    b8d4:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    b8db:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    b8e2:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    b8e9:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    b8f0:	48 f7 d0             	not    %rax
    b8f3:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    b8fa:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    b901:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    b908:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    b90f:	48 f7 d0             	not    %rax
    b912:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    b919:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    b920:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    b927:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    b92e:	48 31 85 38 fe ff ff 	xor    %rax,-0x1c8(%rbp)
    b935:	48 8b 85 38 fe ff ff 	mov    -0x1c8(%rbp),%rax
    b93c:	48 c1 c0 1c          	rol    $0x1c,%rax
    b940:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    b947:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    b94e:	48 31 85 68 fe ff ff 	xor    %rax,-0x198(%rbp)
    b955:	48 8b 85 68 fe ff ff 	mov    -0x198(%rbp),%rax
    b95c:	48 c1 c0 14          	rol    $0x14,%rax
    b960:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    b967:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    b96e:	48 31 85 70 fe ff ff 	xor    %rax,-0x190(%rbp)
    b975:	48 8b 85 70 fe ff ff 	mov    -0x190(%rbp),%rax
    b97c:	48 c1 c0 03          	rol    $0x3,%rax
    b980:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    b987:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    b98e:	48 31 85 a0 fe ff ff 	xor    %rax,-0x160(%rbp)
    b995:	48 8b 85 a0 fe ff ff 	mov    -0x160(%rbp),%rax
    b99c:	48 c1 c8 13          	ror    $0x13,%rax
    b9a0:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    b9a7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    b9ae:	48 31 85 d0 fe ff ff 	xor    %rax,-0x130(%rbp)
    b9b5:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    b9bc:	48 c1 c8 03          	ror    $0x3,%rax
    b9c0:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    b9c7:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    b9ce:	48 f7 d0             	not    %rax
    b9d1:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    b9d8:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    b9df:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    b9e6:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    b9ed:	48 f7 d0             	not    %rax
    b9f0:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    b9f7:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    b9fe:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    ba05:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    ba0c:	48 f7 d0             	not    %rax
    ba0f:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    ba16:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    ba1d:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    ba24:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    ba2b:	48 f7 d0             	not    %rax
    ba2e:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    ba35:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    ba3c:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    ba43:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    ba4a:	48 f7 d0             	not    %rax
    ba4d:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    ba54:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    ba5b:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    ba5f:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    ba66:	48 31 85 28 fe ff ff 	xor    %rax,-0x1d8(%rbp)
    ba6d:	48 8b 85 28 fe ff ff 	mov    -0x1d8(%rbp),%rax
    ba74:	48 d1 c0             	rol    $1,%rax
    ba77:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    ba7e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ba85:	48 31 85 58 fe ff ff 	xor    %rax,-0x1a8(%rbp)
    ba8c:	48 8b 85 58 fe ff ff 	mov    -0x1a8(%rbp),%rax
    ba93:	48 c1 c0 06          	rol    $0x6,%rax
    ba97:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    ba9e:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    baa5:	48 31 85 88 fe ff ff 	xor    %rax,-0x178(%rbp)
    baac:	48 8b 85 88 fe ff ff 	mov    -0x178(%rbp),%rax
    bab3:	48 c1 c0 19          	rol    $0x19,%rax
    bab7:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    babe:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    bac5:	48 31 85 b8 fe ff ff 	xor    %rax,-0x148(%rbp)
    bacc:	48 8b 85 b8 fe ff ff 	mov    -0x148(%rbp),%rax
    bad3:	48 c1 c0 08          	rol    $0x8,%rax
    bad7:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    bade:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bae5:	48 31 85 c0 fe ff ff 	xor    %rax,-0x140(%rbp)
    baec:	48 8b 85 c0 fe ff ff 	mov    -0x140(%rbp),%rax
    baf3:	48 c1 c0 12          	rol    $0x12,%rax
    baf7:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    bafe:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    bb05:	48 f7 d0             	not    %rax
    bb08:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    bb0f:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    bb16:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    bb1a:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    bb21:	48 f7 d0             	not    %rax
    bb24:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    bb2b:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    bb32:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    bb36:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    bb3d:	48 f7 d0             	not    %rax
    bb40:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    bb47:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    bb4e:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    bb52:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    bb59:	48 f7 d0             	not    %rax
    bb5c:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    bb63:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    bb6a:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    bb6e:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    bb75:	48 f7 d0             	not    %rax
    bb78:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    bb7f:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    bb86:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    bb8a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    bb91:	48 31 85 40 fe ff ff 	xor    %rax,-0x1c0(%rbp)
    bb98:	48 8b 85 40 fe ff ff 	mov    -0x1c0(%rbp),%rax
    bb9f:	48 c1 c0 1b          	rol    $0x1b,%rax
    bba3:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    bbaa:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bbb1:	48 31 85 48 fe ff ff 	xor    %rax,-0x1b8(%rbp)
    bbb8:	48 8b 85 48 fe ff ff 	mov    -0x1b8(%rbp),%rax
    bbbf:	48 c1 c8 1c          	ror    $0x1c,%rax
    bbc3:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    bbca:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    bbd1:	48 31 85 78 fe ff ff 	xor    %rax,-0x188(%rbp)
    bbd8:	48 8b 85 78 fe ff ff 	mov    -0x188(%rbp),%rax
    bbdf:	48 c1 c0 0a          	rol    $0xa,%rax
    bbe3:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    bbea:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    bbf1:	48 31 85 a8 fe ff ff 	xor    %rax,-0x158(%rbp)
    bbf8:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
    bbff:	48 c1 c0 0f          	rol    $0xf,%rax
    bc03:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    bc0a:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    bc11:	48 31 85 d8 fe ff ff 	xor    %rax,-0x128(%rbp)
    bc18:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    bc1f:	48 c1 c8 08          	ror    $0x8,%rax
    bc23:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    bc2a:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    bc31:	48 f7 d0             	not    %rax
    bc34:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    bc3b:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    bc42:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    bc46:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    bc4d:	48 f7 d0             	not    %rax
    bc50:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    bc57:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    bc5e:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    bc62:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    bc69:	48 f7 d0             	not    %rax
    bc6c:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    bc73:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    bc7a:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    bc7e:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    bc85:	48 f7 d0             	not    %rax
    bc88:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    bc8f:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    bc96:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    bc9a:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    bca1:	48 f7 d0             	not    %rax
    bca4:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    bcab:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    bcb2:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    bcb6:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    bcbd:	48 31 85 30 fe ff ff 	xor    %rax,-0x1d0(%rbp)
    bcc4:	48 8b 85 30 fe ff ff 	mov    -0x1d0(%rbp),%rax
    bccb:	48 c1 c8 02          	ror    $0x2,%rax
    bccf:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    bcd6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    bcdd:	48 31 85 60 fe ff ff 	xor    %rax,-0x1a0(%rbp)
    bce4:	48 8b 85 60 fe ff ff 	mov    -0x1a0(%rbp),%rax
    bceb:	48 c1 c8 09          	ror    $0x9,%rax
    bcef:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    bcf6:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    bcfd:	48 31 85 90 fe ff ff 	xor    %rax,-0x170(%rbp)
    bd04:	48 8b 85 90 fe ff ff 	mov    -0x170(%rbp),%rax
    bd0b:	48 c1 c8 19          	ror    $0x19,%rax
    bd0f:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    bd16:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bd1d:	48 31 85 98 fe ff ff 	xor    %rax,-0x168(%rbp)
    bd24:	48 8b 85 98 fe ff ff 	mov    -0x168(%rbp),%rax
    bd2b:	48 c1 c8 17          	ror    $0x17,%rax
    bd2f:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    bd36:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    bd3d:	48 31 85 c8 fe ff ff 	xor    %rax,-0x138(%rbp)
    bd44:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    bd4b:	48 c1 c0 02          	rol    $0x2,%rax
    bd4f:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    bd56:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    bd5d:	48 f7 d0             	not    %rax
    bd60:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    bd67:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    bd6e:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    bd72:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    bd79:	48 f7 d0             	not    %rax
    bd7c:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    bd83:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    bd8a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    bd8e:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    bd95:	48 f7 d0             	not    %rax
    bd98:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    bd9f:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    bda6:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    bdaa:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    bdb1:	48 f7 d0             	not    %rax
    bdb4:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    bdbb:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    bdc2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    bdc6:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    bdcd:	48 f7 d0             	not    %rax
    bdd0:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    bdd7:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    bdde:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    bde2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    bde9:	48 33 85 60 ff ff ff 	xor    -0xa0(%rbp),%rax
    bdf0:	48 33 45 88          	xor    -0x78(%rbp),%rax
    bdf4:	48 33 45 b0          	xor    -0x50(%rbp),%rax
    bdf8:	48 33 45 d8          	xor    -0x28(%rbp),%rax
    bdfc:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    be03:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    be0a:	48 33 85 68 ff ff ff 	xor    -0x98(%rbp),%rax
    be11:	48 33 45 90          	xor    -0x70(%rbp),%rax
    be15:	48 33 45 b8          	xor    -0x48(%rbp),%rax
    be19:	48 33 45 e0          	xor    -0x20(%rbp),%rax
    be1d:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    be24:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    be2b:	48 33 85 70 ff ff ff 	xor    -0x90(%rbp),%rax
    be32:	48 33 45 98          	xor    -0x68(%rbp),%rax
    be36:	48 33 45 c0          	xor    -0x40(%rbp),%rax
    be3a:	48 33 45 e8          	xor    -0x18(%rbp),%rax
    be3e:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    be45:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    be4c:	48 33 85 78 ff ff ff 	xor    -0x88(%rbp),%rax
    be53:	48 33 45 a0          	xor    -0x60(%rbp),%rax
    be57:	48 33 45 c8          	xor    -0x38(%rbp),%rax
    be5b:	48 33 45 f0          	xor    -0x10(%rbp),%rax
    be5f:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    be66:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    be6d:	48 33 45 80          	xor    -0x80(%rbp),%rax
    be71:	48 33 45 a8          	xor    -0x58(%rbp),%rax
    be75:	48 33 45 d0          	xor    -0x30(%rbp),%rax
    be79:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    be7d:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    be84:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    be8b:	48 d1 c0             	rol    $1,%rax
    be8e:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    be95:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    be9c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    bea3:	48 d1 c0             	rol    $1,%rax
    bea6:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    bead:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    beb4:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    bebb:	48 d1 c0             	rol    $1,%rax
    bebe:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    bec5:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    becc:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    bed3:	48 d1 c0             	rol    $1,%rax
    bed6:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    bedd:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
    bee4:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    beeb:	48 d1 c0             	rol    $1,%rax
    beee:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    bef5:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
    befc:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bf03:	48 31 85 38 ff ff ff 	xor    %rax,-0xc8(%rbp)
    bf0a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    bf11:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    bf18:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    bf1f:	48 31 85 68 ff ff ff 	xor    %rax,-0x98(%rbp)
    bf26:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    bf2d:	48 c1 c8 14          	ror    $0x14,%rax
    bf31:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    bf38:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    bf3f:	48 31 45 98          	xor    %rax,-0x68(%rbp)
    bf43:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    bf47:	48 c1 c8 15          	ror    $0x15,%rax
    bf4b:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    bf52:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    bf59:	48 31 45 c8          	xor    %rax,-0x38(%rbp)
    bf5d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    bf61:	48 c1 c0 15          	rol    $0x15,%rax
    bf65:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    bf6c:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    bf73:	48 31 45 f8          	xor    %rax,-0x8(%rbp)
    bf77:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    bf7b:	48 c1 c0 0e          	rol    $0xe,%rax
    bf7f:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    bf86:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    bf8d:	48 f7 d0             	not    %rax
    bf90:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    bf97:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    bf9e:	48 89 85 20 fe ff ff 	mov    %rax,-0x1e0(%rbp)
    bfa5:	8b 85 1c fe ff ff    	mov    -0x1e4(%rbp),%eax
    bfab:	83 c0 01             	add    $0x1,%eax
    bfae:	48 98                	cltq
    bfb0:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    bfb7:	00 
    bfb8:	48 8d 05 01 22 00 00 	lea    0x2201(%rip),%rax        # e1c0 <KeccakF_RoundConstants>
    bfbf:	48 8b 04 02          	mov    (%rdx,%rax,1),%rax
    bfc3:	48 31 85 20 fe ff ff 	xor    %rax,-0x1e0(%rbp)
    bfca:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    bfd1:	48 f7 d0             	not    %rax
    bfd4:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    bfdb:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    bfe2:	48 89 85 28 fe ff ff 	mov    %rax,-0x1d8(%rbp)
    bfe9:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    bff0:	48 f7 d0             	not    %rax
    bff3:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    bffa:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    c001:	48 89 85 30 fe ff ff 	mov    %rax,-0x1d0(%rbp)
    c008:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    c00f:	48 f7 d0             	not    %rax
    c012:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    c019:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    c020:	48 89 85 38 fe ff ff 	mov    %rax,-0x1c8(%rbp)
    c027:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    c02e:	48 f7 d0             	not    %rax
    c031:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    c038:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    c03f:	48 89 85 40 fe ff ff 	mov    %rax,-0x1c0(%rbp)
    c046:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c04d:	48 31 85 50 ff ff ff 	xor    %rax,-0xb0(%rbp)
    c054:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    c05b:	48 c1 c0 1c          	rol    $0x1c,%rax
    c05f:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    c066:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    c06d:	48 31 45 80          	xor    %rax,-0x80(%rbp)
    c071:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    c075:	48 c1 c0 14          	rol    $0x14,%rax
    c079:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    c080:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    c087:	48 31 45 88          	xor    %rax,-0x78(%rbp)
    c08b:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    c08f:	48 c1 c0 03          	rol    $0x3,%rax
    c093:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    c09a:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    c0a1:	48 31 45 b8          	xor    %rax,-0x48(%rbp)
    c0a5:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    c0a9:	48 c1 c8 13          	ror    $0x13,%rax
    c0ad:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    c0b4:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c0bb:	48 31 45 e8          	xor    %rax,-0x18(%rbp)
    c0bf:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c0c3:	48 c1 c8 03          	ror    $0x3,%rax
    c0c7:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    c0ce:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    c0d5:	48 f7 d0             	not    %rax
    c0d8:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    c0df:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    c0e6:	48 89 85 48 fe ff ff 	mov    %rax,-0x1b8(%rbp)
    c0ed:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c0f4:	48 f7 d0             	not    %rax
    c0f7:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    c0fe:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    c105:	48 89 85 50 fe ff ff 	mov    %rax,-0x1b0(%rbp)
    c10c:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c113:	48 f7 d0             	not    %rax
    c116:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    c11d:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    c124:	48 89 85 58 fe ff ff 	mov    %rax,-0x1a8(%rbp)
    c12b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    c132:	48 f7 d0             	not    %rax
    c135:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    c13c:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    c143:	48 89 85 60 fe ff ff 	mov    %rax,-0x1a0(%rbp)
    c14a:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    c151:	48 f7 d0             	not    %rax
    c154:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    c15b:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    c162:	48 89 85 68 fe ff ff 	mov    %rax,-0x198(%rbp)
    c169:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    c170:	48 31 85 40 ff ff ff 	xor    %rax,-0xc0(%rbp)
    c177:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    c17e:	48 d1 c0             	rol    $1,%rax
    c181:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    c188:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c18f:	48 31 85 70 ff ff ff 	xor    %rax,-0x90(%rbp)
    c196:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    c19d:	48 c1 c0 06          	rol    $0x6,%rax
    c1a1:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    c1a8:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c1af:	48 31 45 a0          	xor    %rax,-0x60(%rbp)
    c1b3:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    c1b7:	48 c1 c0 19          	rol    $0x19,%rax
    c1bb:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    c1c2:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    c1c9:	48 31 45 d0          	xor    %rax,-0x30(%rbp)
    c1cd:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    c1d1:	48 c1 c0 08          	rol    $0x8,%rax
    c1d5:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    c1dc:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    c1e3:	48 31 45 d8          	xor    %rax,-0x28(%rbp)
    c1e7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c1eb:	48 c1 c0 12          	rol    $0x12,%rax
    c1ef:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    c1f6:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    c1fd:	48 f7 d0             	not    %rax
    c200:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    c207:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    c20e:	48 89 85 70 fe ff ff 	mov    %rax,-0x190(%rbp)
    c215:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c21c:	48 f7 d0             	not    %rax
    c21f:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    c226:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    c22d:	48 89 85 78 fe ff ff 	mov    %rax,-0x188(%rbp)
    c234:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c23b:	48 f7 d0             	not    %rax
    c23e:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    c245:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    c24c:	48 89 85 80 fe ff ff 	mov    %rax,-0x180(%rbp)
    c253:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    c25a:	48 f7 d0             	not    %rax
    c25d:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    c264:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    c26b:	48 89 85 88 fe ff ff 	mov    %rax,-0x178(%rbp)
    c272:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    c279:	48 f7 d0             	not    %rax
    c27c:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    c283:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    c28a:	48 89 85 90 fe ff ff 	mov    %rax,-0x170(%rbp)
    c291:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    c298:	48 31 85 58 ff ff ff 	xor    %rax,-0xa8(%rbp)
    c29f:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    c2a6:	48 c1 c0 1b          	rol    $0x1b,%rax
    c2aa:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    c2b1:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    c2b8:	48 31 85 60 ff ff ff 	xor    %rax,-0xa0(%rbp)
    c2bf:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    c2c6:	48 c1 c8 1c          	ror    $0x1c,%rax
    c2ca:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    c2d1:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    c2d8:	48 31 45 90          	xor    %rax,-0x70(%rbp)
    c2dc:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    c2e0:	48 c1 c0 0a          	rol    $0xa,%rax
    c2e4:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    c2eb:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c2f2:	48 31 45 c0          	xor    %rax,-0x40(%rbp)
    c2f6:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    c2fa:	48 c1 c0 0f          	rol    $0xf,%rax
    c2fe:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    c305:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c30c:	48 31 45 f0          	xor    %rax,-0x10(%rbp)
    c310:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    c314:	48 c1 c8 08          	ror    $0x8,%rax
    c318:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    c31f:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    c326:	48 f7 d0             	not    %rax
    c329:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    c330:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    c337:	48 89 85 98 fe ff ff 	mov    %rax,-0x168(%rbp)
    c33e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c345:	48 f7 d0             	not    %rax
    c348:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    c34f:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    c356:	48 89 85 a0 fe ff ff 	mov    %rax,-0x160(%rbp)
    c35d:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c364:	48 f7 d0             	not    %rax
    c367:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    c36e:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    c375:	48 89 85 a8 fe ff ff 	mov    %rax,-0x158(%rbp)
    c37c:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    c383:	48 f7 d0             	not    %rax
    c386:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    c38d:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    c394:	48 89 85 b0 fe ff ff 	mov    %rax,-0x150(%rbp)
    c39b:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    c3a2:	48 f7 d0             	not    %rax
    c3a5:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    c3ac:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    c3b3:	48 89 85 b8 fe ff ff 	mov    %rax,-0x148(%rbp)
    c3ba:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c3c1:	48 31 85 48 ff ff ff 	xor    %rax,-0xb8(%rbp)
    c3c8:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    c3cf:	48 c1 c8 02          	ror    $0x2,%rax
    c3d3:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    c3da:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c3e1:	48 31 85 78 ff ff ff 	xor    %rax,-0x88(%rbp)
    c3e8:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    c3ef:	48 c1 c8 09          	ror    $0x9,%rax
    c3f3:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    c3fa:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    c401:	48 31 45 a8          	xor    %rax,-0x58(%rbp)
    c405:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    c409:	48 c1 c8 19          	ror    $0x19,%rax
    c40d:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    c414:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    c41b:	48 31 45 b0          	xor    %rax,-0x50(%rbp)
    c41f:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    c423:	48 c1 c8 17          	ror    $0x17,%rax
    c427:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    c42e:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    c435:	48 31 45 e0          	xor    %rax,-0x20(%rbp)
    c439:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c43d:	48 c1 c0 02          	rol    $0x2,%rax
    c441:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    c448:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    c44f:	48 f7 d0             	not    %rax
    c452:	48 23 85 f8 fe ff ff 	and    -0x108(%rbp),%rax
    c459:	48 33 85 e8 fe ff ff 	xor    -0x118(%rbp),%rax
    c460:	48 89 85 c0 fe ff ff 	mov    %rax,-0x140(%rbp)
    c467:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c46e:	48 f7 d0             	not    %rax
    c471:	48 23 85 00 ff ff ff 	and    -0x100(%rbp),%rax
    c478:	48 33 85 f0 fe ff ff 	xor    -0x110(%rbp),%rax
    c47f:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
    c486:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c48d:	48 f7 d0             	not    %rax
    c490:	48 23 85 08 ff ff ff 	and    -0xf8(%rbp),%rax
    c497:	48 33 85 f8 fe ff ff 	xor    -0x108(%rbp),%rax
    c49e:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
    c4a5:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    c4ac:	48 f7 d0             	not    %rax
    c4af:	48 23 85 e8 fe ff ff 	and    -0x118(%rbp),%rax
    c4b6:	48 33 85 00 ff ff ff 	xor    -0x100(%rbp),%rax
    c4bd:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    c4c4:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    c4cb:	48 f7 d0             	not    %rax
    c4ce:	48 23 85 f0 fe ff ff 	and    -0x110(%rbp),%rax
    c4d5:	48 33 85 08 ff ff ff 	xor    -0xf8(%rbp),%rax
    c4dc:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    c4e3:	83 85 1c fe ff ff 02 	addl   $0x2,-0x1e4(%rbp)
    c4ea:	83 bd 1c fe ff ff 17 	cmpl   $0x17,-0x1e4(%rbp)
    c4f1:	0f 8e 8d f1 ff ff    	jle    b684 <KeccakF1600_StatePermute+0x201>
    c4f7:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c4fe:	48 8b 95 20 fe ff ff 	mov    -0x1e0(%rbp),%rdx
    c505:	48 89 10             	mov    %rdx,(%rax)
    c508:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c50f:	48 83 c0 08          	add    $0x8,%rax
    c513:	48 8b 95 28 fe ff ff 	mov    -0x1d8(%rbp),%rdx
    c51a:	48 89 10             	mov    %rdx,(%rax)
    c51d:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c524:	48 83 c0 10          	add    $0x10,%rax
    c528:	48 8b 95 30 fe ff ff 	mov    -0x1d0(%rbp),%rdx
    c52f:	48 89 10             	mov    %rdx,(%rax)
    c532:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c539:	48 83 c0 18          	add    $0x18,%rax
    c53d:	48 8b 95 38 fe ff ff 	mov    -0x1c8(%rbp),%rdx
    c544:	48 89 10             	mov    %rdx,(%rax)
    c547:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c54e:	48 83 c0 20          	add    $0x20,%rax
    c552:	48 8b 95 40 fe ff ff 	mov    -0x1c0(%rbp),%rdx
    c559:	48 89 10             	mov    %rdx,(%rax)
    c55c:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c563:	48 83 c0 28          	add    $0x28,%rax
    c567:	48 8b 95 48 fe ff ff 	mov    -0x1b8(%rbp),%rdx
    c56e:	48 89 10             	mov    %rdx,(%rax)
    c571:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c578:	48 83 c0 30          	add    $0x30,%rax
    c57c:	48 8b 95 50 fe ff ff 	mov    -0x1b0(%rbp),%rdx
    c583:	48 89 10             	mov    %rdx,(%rax)
    c586:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c58d:	48 83 c0 38          	add    $0x38,%rax
    c591:	48 8b 95 58 fe ff ff 	mov    -0x1a8(%rbp),%rdx
    c598:	48 89 10             	mov    %rdx,(%rax)
    c59b:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c5a2:	48 83 c0 40          	add    $0x40,%rax
    c5a6:	48 8b 95 60 fe ff ff 	mov    -0x1a0(%rbp),%rdx
    c5ad:	48 89 10             	mov    %rdx,(%rax)
    c5b0:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c5b7:	48 83 c0 48          	add    $0x48,%rax
    c5bb:	48 8b 95 68 fe ff ff 	mov    -0x198(%rbp),%rdx
    c5c2:	48 89 10             	mov    %rdx,(%rax)
    c5c5:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c5cc:	48 83 c0 50          	add    $0x50,%rax
    c5d0:	48 8b 95 70 fe ff ff 	mov    -0x190(%rbp),%rdx
    c5d7:	48 89 10             	mov    %rdx,(%rax)
    c5da:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c5e1:	48 83 c0 58          	add    $0x58,%rax
    c5e5:	48 8b 95 78 fe ff ff 	mov    -0x188(%rbp),%rdx
    c5ec:	48 89 10             	mov    %rdx,(%rax)
    c5ef:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c5f6:	48 83 c0 60          	add    $0x60,%rax
    c5fa:	48 8b 95 80 fe ff ff 	mov    -0x180(%rbp),%rdx
    c601:	48 89 10             	mov    %rdx,(%rax)
    c604:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c60b:	48 83 c0 68          	add    $0x68,%rax
    c60f:	48 8b 95 88 fe ff ff 	mov    -0x178(%rbp),%rdx
    c616:	48 89 10             	mov    %rdx,(%rax)
    c619:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c620:	48 83 c0 70          	add    $0x70,%rax
    c624:	48 8b 95 90 fe ff ff 	mov    -0x170(%rbp),%rdx
    c62b:	48 89 10             	mov    %rdx,(%rax)
    c62e:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c635:	48 83 c0 78          	add    $0x78,%rax
    c639:	48 8b 95 98 fe ff ff 	mov    -0x168(%rbp),%rdx
    c640:	48 89 10             	mov    %rdx,(%rax)
    c643:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c64a:	48 83 e8 80          	sub    $0xffffffffffffff80,%rax
    c64e:	48 8b 95 a0 fe ff ff 	mov    -0x160(%rbp),%rdx
    c655:	48 89 10             	mov    %rdx,(%rax)
    c658:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c65f:	48 05 88 00 00 00    	add    $0x88,%rax
    c665:	48 8b 95 a8 fe ff ff 	mov    -0x158(%rbp),%rdx
    c66c:	48 89 10             	mov    %rdx,(%rax)
    c66f:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c676:	48 05 90 00 00 00    	add    $0x90,%rax
    c67c:	48 8b 95 b0 fe ff ff 	mov    -0x150(%rbp),%rdx
    c683:	48 89 10             	mov    %rdx,(%rax)
    c686:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c68d:	48 05 98 00 00 00    	add    $0x98,%rax
    c693:	48 8b 95 b8 fe ff ff 	mov    -0x148(%rbp),%rdx
    c69a:	48 89 10             	mov    %rdx,(%rax)
    c69d:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c6a4:	48 05 a0 00 00 00    	add    $0xa0,%rax
    c6aa:	48 8b 95 c0 fe ff ff 	mov    -0x140(%rbp),%rdx
    c6b1:	48 89 10             	mov    %rdx,(%rax)
    c6b4:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c6bb:	48 05 a8 00 00 00    	add    $0xa8,%rax
    c6c1:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    c6c8:	48 89 10             	mov    %rdx,(%rax)
    c6cb:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c6d2:	48 05 b0 00 00 00    	add    $0xb0,%rax
    c6d8:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    c6df:	48 89 10             	mov    %rdx,(%rax)
    c6e2:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c6e9:	48 05 b8 00 00 00    	add    $0xb8,%rax
    c6ef:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    c6f6:	48 89 10             	mov    %rdx,(%rax)
    c6f9:	48 8b 85 08 fe ff ff 	mov    -0x1f8(%rbp),%rax
    c700:	48 05 c0 00 00 00    	add    $0xc0,%rax
    c706:	48 8b 95 e0 fe ff ff 	mov    -0x120(%rbp),%rdx
    c70d:	48 89 10             	mov    %rdx,(%rax)
    c710:	90                   	nop
    c711:	c9                   	leave
    c712:	c3                   	ret

000000000000c713 <keccak_absorb>:
    c713:	f3 0f 1e fa          	endbr64
    c717:	55                   	push   %rbp
    c718:	48 89 e5             	mov    %rsp,%rbp
    c71b:	48 81 ec 00 01 00 00 	sub    $0x100,%rsp
    c722:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
    c729:	89 b5 14 ff ff ff    	mov    %esi,-0xec(%rbp)
    c72f:	48 89 95 08 ff ff ff 	mov    %rdx,-0xf8(%rbp)
    c736:	48 89 8d 00 ff ff ff 	mov    %rcx,-0x100(%rbp)
    c73d:	44 89 c0             	mov    %r8d,%eax
    c740:	88 85 10 ff ff ff    	mov    %al,-0xf0(%rbp)
    c746:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    c74d:	00 00 
    c74f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    c753:	31 c0                	xor    %eax,%eax
    c755:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
    c75c:	00 00 00 00 
    c760:	eb 28                	jmp    c78a <keccak_absorb+0x77>
    c762:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c769:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    c770:	00 
    c771:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    c778:	48 01 d0             	add    %rdx,%rax
    c77b:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    c782:	48 83 85 28 ff ff ff 	addq   $0x1,-0xd8(%rbp)
    c789:	01 
    c78a:	48 83 bd 28 ff ff ff 	cmpq   $0x18,-0xd8(%rbp)
    c791:	18 
    c792:	76 ce                	jbe    c762 <keccak_absorb+0x4f>
    c794:	e9 ae 00 00 00       	jmp    c847 <keccak_absorb+0x134>
    c799:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
    c7a0:	00 00 00 00 
    c7a4:	eb 64                	jmp    c80a <keccak_absorb+0xf7>
    c7a6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c7ad:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    c7b4:	00 
    c7b5:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    c7bc:	48 01 d0             	add    %rdx,%rax
    c7bf:	48 89 c7             	mov    %rax,%rdi
    c7c2:	e8 1c ec ff ff       	call   b3e3 <load64>
    c7c7:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    c7ce:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    c7d5:	00 
    c7d6:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c7dd:	48 01 ca             	add    %rcx,%rdx
    c7e0:	48 8b 0a             	mov    (%rdx),%rcx
    c7e3:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    c7ea:	48 8d 34 d5 00 00 00 	lea    0x0(,%rdx,8),%rsi
    c7f1:	00 
    c7f2:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c7f9:	48 01 f2             	add    %rsi,%rdx
    c7fc:	48 31 c8             	xor    %rcx,%rax
    c7ff:	48 89 02             	mov    %rax,(%rdx)
    c802:	48 83 85 28 ff ff ff 	addq   $0x1,-0xd8(%rbp)
    c809:	01 
    c80a:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c810:	c1 e8 03             	shr    $0x3,%eax
    c813:	89 c0                	mov    %eax,%eax
    c815:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    c81c:	72 88                	jb     c7a6 <keccak_absorb+0x93>
    c81e:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    c825:	48 89 c7             	mov    %rax,%rdi
    c828:	e8 56 ec ff ff       	call   b483 <KeccakF1600_StatePermute>
    c82d:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c833:	48 29 85 00 ff ff ff 	sub    %rax,-0x100(%rbp)
    c83a:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c840:	48 01 85 08 ff ff ff 	add    %rax,-0xf8(%rbp)
    c847:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c84d:	48 39 85 00 ff ff ff 	cmp    %rax,-0x100(%rbp)
    c854:	0f 83 3f ff ff ff    	jae    c799 <keccak_absorb+0x86>
    c85a:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
    c861:	00 00 00 00 
    c865:	eb 1c                	jmp    c883 <keccak_absorb+0x170>
    c867:	48 8d 85 30 ff ff ff 	lea    -0xd0(%rbp),%rax
    c86e:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    c875:	48 01 d0             	add    %rdx,%rax
    c878:	c6 00 00             	movb   $0x0,(%rax)
    c87b:	48 83 85 28 ff ff ff 	addq   $0x1,-0xd8(%rbp)
    c882:	01 
    c883:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c889:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    c890:	72 d5                	jb     c867 <keccak_absorb+0x154>
    c892:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
    c899:	00 00 00 00 
    c89d:	eb 2f                	jmp    c8ce <keccak_absorb+0x1bb>
    c89f:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    c8a6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c8ad:	48 01 d0             	add    %rdx,%rax
    c8b0:	0f b6 00             	movzbl (%rax),%eax
    c8b3:	48 8d 95 30 ff ff ff 	lea    -0xd0(%rbp),%rdx
    c8ba:	48 8b 8d 28 ff ff ff 	mov    -0xd8(%rbp),%rcx
    c8c1:	48 01 ca             	add    %rcx,%rdx
    c8c4:	88 02                	mov    %al,(%rdx)
    c8c6:	48 83 85 28 ff ff ff 	addq   $0x1,-0xd8(%rbp)
    c8cd:	01 
    c8ce:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c8d5:	48 3b 85 00 ff ff ff 	cmp    -0x100(%rbp),%rax
    c8dc:	72 c1                	jb     c89f <keccak_absorb+0x18c>
    c8de:	48 8d 85 30 ff ff ff 	lea    -0xd0(%rbp),%rax
    c8e5:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    c8ec:	48 01 c2             	add    %rax,%rdx
    c8ef:	0f b6 85 10 ff ff ff 	movzbl -0xf0(%rbp),%eax
    c8f6:	88 02                	mov    %al,(%rdx)
    c8f8:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c8fe:	83 e8 01             	sub    $0x1,%eax
    c901:	89 c0                	mov    %eax,%eax
    c903:	0f b6 94 05 30 ff ff 	movzbl -0xd0(%rbp,%rax,1),%edx
    c90a:	ff 
    c90b:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c911:	8d 48 ff             	lea    -0x1(%rax),%ecx
    c914:	89 d0                	mov    %edx,%eax
    c916:	83 c8 80             	or     $0xffffff80,%eax
    c919:	89 ca                	mov    %ecx,%edx
    c91b:	88 84 15 30 ff ff ff 	mov    %al,-0xd0(%rbp,%rdx,1)
    c922:	48 c7 85 28 ff ff ff 	movq   $0x0,-0xd8(%rbp)
    c929:	00 00 00 00 
    c92d:	eb 64                	jmp    c993 <keccak_absorb+0x280>
    c92f:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    c936:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    c93d:	00 
    c93e:	48 8d 85 30 ff ff ff 	lea    -0xd0(%rbp),%rax
    c945:	48 01 d0             	add    %rdx,%rax
    c948:	48 89 c7             	mov    %rax,%rdi
    c94b:	e8 93 ea ff ff       	call   b3e3 <load64>
    c950:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    c957:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    c95e:	00 
    c95f:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c966:	48 01 ca             	add    %rcx,%rdx
    c969:	48 8b 0a             	mov    (%rdx),%rcx
    c96c:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    c973:	48 8d 34 d5 00 00 00 	lea    0x0(,%rdx,8),%rsi
    c97a:	00 
    c97b:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c982:	48 01 f2             	add    %rsi,%rdx
    c985:	48 31 c8             	xor    %rcx,%rax
    c988:	48 89 02             	mov    %rax,(%rdx)
    c98b:	48 83 85 28 ff ff ff 	addq   $0x1,-0xd8(%rbp)
    c992:	01 
    c993:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    c999:	c1 e8 03             	shr    $0x3,%eax
    c99c:	89 c0                	mov    %eax,%eax
    c99e:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    c9a5:	72 88                	jb     c92f <keccak_absorb+0x21c>
    c9a7:	90                   	nop
    c9a8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c9ac:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    c9b3:	00 00 
    c9b5:	74 05                	je     c9bc <keccak_absorb+0x2a9>
    c9b7:	e8 14 48 ff ff       	call   11d0 <__stack_chk_fail@plt>
    c9bc:	c9                   	leave
    c9bd:	c3                   	ret

000000000000c9be <keccak_squeezeblocks>:
    c9be:	f3 0f 1e fa          	endbr64
    c9c2:	55                   	push   %rbp
    c9c3:	48 89 e5             	mov    %rsp,%rbp
    c9c6:	48 83 ec 30          	sub    $0x30,%rsp
    c9ca:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    c9ce:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    c9d2:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    c9d6:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
    c9d9:	eb 69                	jmp    ca44 <keccak_squeezeblocks+0x86>
    c9db:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c9df:	48 89 c7             	mov    %rax,%rdi
    c9e2:	e8 9c ea ff ff       	call   b483 <KeccakF1600_StatePermute>
    c9e7:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    c9ee:	00 
    c9ef:	eb 39                	jmp    ca2a <keccak_squeezeblocks+0x6c>
    c9f1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c9f5:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    c9fc:	00 
    c9fd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ca01:	48 01 d0             	add    %rdx,%rax
    ca04:	48 8b 10             	mov    (%rax),%rdx
    ca07:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ca0b:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    ca12:	00 
    ca13:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ca17:	48 01 c8             	add    %rcx,%rax
    ca1a:	48 89 d6             	mov    %rdx,%rsi
    ca1d:	48 89 c7             	mov    %rax,%rdi
    ca20:	e8 12 ea ff ff       	call   b437 <store64>
    ca25:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    ca2a:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    ca2d:	c1 e8 03             	shr    $0x3,%eax
    ca30:	89 c0                	mov    %eax,%eax
    ca32:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    ca36:	72 b9                	jb     c9f1 <keccak_squeezeblocks+0x33>
    ca38:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    ca3b:	48 01 45 e8          	add    %rax,-0x18(%rbp)
    ca3f:	48 83 6d e0 01       	subq   $0x1,-0x20(%rbp)
    ca44:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    ca49:	75 90                	jne    c9db <keccak_squeezeblocks+0x1d>
    ca4b:	90                   	nop
    ca4c:	90                   	nop
    ca4d:	c9                   	leave
    ca4e:	c3                   	ret

000000000000ca4f <keccak_inc_init>:
    ca4f:	f3 0f 1e fa          	endbr64
    ca53:	55                   	push   %rbp
    ca54:	48 89 e5             	mov    %rsp,%rbp
    ca57:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    ca5b:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    ca62:	00 
    ca63:	eb 1f                	jmp    ca84 <keccak_inc_init+0x35>
    ca65:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ca69:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    ca70:	00 
    ca71:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ca75:	48 01 d0             	add    %rdx,%rax
    ca78:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    ca7f:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    ca84:	48 83 7d f8 18       	cmpq   $0x18,-0x8(%rbp)
    ca89:	76 da                	jbe    ca65 <keccak_inc_init+0x16>
    ca8b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ca8f:	48 05 c8 00 00 00    	add    $0xc8,%rax
    ca95:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    ca9c:	90                   	nop
    ca9d:	5d                   	pop    %rbp
    ca9e:	c3                   	ret

000000000000ca9f <keccak_inc_absorb>:
    ca9f:	f3 0f 1e fa          	endbr64
    caa3:	55                   	push   %rbp
    caa4:	48 89 e5             	mov    %rsp,%rbp
    caa7:	48 83 ec 30          	sub    $0x30,%rsp
    caab:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    caaf:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    cab2:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    cab6:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    caba:	e9 08 01 00 00       	jmp    cbc7 <keccak_inc_absorb+0x128>
    cabf:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    cac6:	00 
    cac7:	e9 8c 00 00 00       	jmp    cb58 <keccak_inc_absorb+0xb9>
    cacc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cad0:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cad6:	48 8b 10             	mov    (%rax),%rdx
    cad9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cadd:	48 01 d0             	add    %rdx,%rax
    cae0:	48 c1 e8 03          	shr    $0x3,%rax
    cae4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    caeb:	00 
    caec:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    caf0:	48 01 d0             	add    %rdx,%rax
    caf3:	48 8b 30             	mov    (%rax),%rsi
    caf6:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    cafa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cafe:	48 01 d0             	add    %rdx,%rax
    cb01:	0f b6 00             	movzbl (%rax),%eax
    cb04:	0f b6 d0             	movzbl %al,%edx
    cb07:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cb0b:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cb11:	48 8b 08             	mov    (%rax),%rcx
    cb14:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cb18:	48 01 c8             	add    %rcx,%rax
    cb1b:	83 e0 07             	and    $0x7,%eax
    cb1e:	c1 e0 03             	shl    $0x3,%eax
    cb21:	89 c1                	mov    %eax,%ecx
    cb23:	48 d3 e2             	shl    %cl,%rdx
    cb26:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cb2a:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cb30:	48 8b 08             	mov    (%rax),%rcx
    cb33:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cb37:	48 01 c8             	add    %rcx,%rax
    cb3a:	48 c1 e8 03          	shr    $0x3,%rax
    cb3e:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    cb45:	00 
    cb46:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cb4a:	48 01 c8             	add    %rcx,%rax
    cb4d:	48 31 f2             	xor    %rsi,%rdx
    cb50:	48 89 10             	mov    %rdx,(%rax)
    cb53:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    cb58:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cb5c:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cb62:	48 8b 00             	mov    (%rax),%rax
    cb65:	89 c2                	mov    %eax,%edx
    cb67:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    cb6a:	29 d0                	sub    %edx,%eax
    cb6c:	89 c0                	mov    %eax,%eax
    cb6e:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    cb72:	0f 82 54 ff ff ff    	jb     cacc <keccak_inc_absorb+0x2d>
    cb78:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cb7c:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cb82:	48 8b 10             	mov    (%rax),%rdx
    cb85:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    cb88:	48 29 c2             	sub    %rax,%rdx
    cb8b:	48 89 d0             	mov    %rdx,%rax
    cb8e:	48 01 45 d0          	add    %rax,-0x30(%rbp)
    cb92:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    cb95:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    cb99:	48 81 c2 c8 00 00 00 	add    $0xc8,%rdx
    cba0:	48 8b 12             	mov    (%rdx),%rdx
    cba3:	48 29 d0             	sub    %rdx,%rax
    cba6:	48 01 45 d8          	add    %rax,-0x28(%rbp)
    cbaa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cbae:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cbb4:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    cbbb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cbbf:	48 89 c7             	mov    %rax,%rdi
    cbc2:	e8 bc e8 ff ff       	call   b483 <KeccakF1600_StatePermute>
    cbc7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cbcb:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cbd1:	48 8b 10             	mov    (%rax),%rdx
    cbd4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    cbd8:	48 01 c2             	add    %rax,%rdx
    cbdb:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    cbde:	48 39 c2             	cmp    %rax,%rdx
    cbe1:	0f 83 d8 fe ff ff    	jae    cabf <keccak_inc_absorb+0x20>
    cbe7:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    cbee:	00 
    cbef:	e9 8c 00 00 00       	jmp    cc80 <keccak_inc_absorb+0x1e1>
    cbf4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cbf8:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cbfe:	48 8b 10             	mov    (%rax),%rdx
    cc01:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cc05:	48 01 d0             	add    %rdx,%rax
    cc08:	48 c1 e8 03          	shr    $0x3,%rax
    cc0c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    cc13:	00 
    cc14:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cc18:	48 01 d0             	add    %rdx,%rax
    cc1b:	48 8b 30             	mov    (%rax),%rsi
    cc1e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    cc22:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cc26:	48 01 d0             	add    %rdx,%rax
    cc29:	0f b6 00             	movzbl (%rax),%eax
    cc2c:	0f b6 d0             	movzbl %al,%edx
    cc2f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cc33:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cc39:	48 8b 08             	mov    (%rax),%rcx
    cc3c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cc40:	48 01 c8             	add    %rcx,%rax
    cc43:	83 e0 07             	and    $0x7,%eax
    cc46:	c1 e0 03             	shl    $0x3,%eax
    cc49:	89 c1                	mov    %eax,%ecx
    cc4b:	48 d3 e2             	shl    %cl,%rdx
    cc4e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cc52:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cc58:	48 8b 08             	mov    (%rax),%rcx
    cc5b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cc5f:	48 01 c8             	add    %rcx,%rax
    cc62:	48 c1 e8 03          	shr    $0x3,%rax
    cc66:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    cc6d:	00 
    cc6e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cc72:	48 01 c8             	add    %rcx,%rax
    cc75:	48 31 f2             	xor    %rsi,%rdx
    cc78:	48 89 10             	mov    %rdx,(%rax)
    cc7b:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    cc80:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cc84:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
    cc88:	0f 82 66 ff ff ff    	jb     cbf4 <keccak_inc_absorb+0x155>
    cc8e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cc92:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cc98:	48 8b 08             	mov    (%rax),%rcx
    cc9b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cc9f:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cca5:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    cca9:	48 01 ca             	add    %rcx,%rdx
    ccac:	48 89 10             	mov    %rdx,(%rax)
    ccaf:	90                   	nop
    ccb0:	c9                   	leave
    ccb1:	c3                   	ret

000000000000ccb2 <keccak_inc_finalize>:
    ccb2:	f3 0f 1e fa          	endbr64
    ccb6:	55                   	push   %rbp
    ccb7:	48 89 e5             	mov    %rsp,%rbp
    ccba:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    ccbe:	89 75 f4             	mov    %esi,-0xc(%rbp)
    ccc1:	89 d0                	mov    %edx,%eax
    ccc3:	88 45 f0             	mov    %al,-0x10(%rbp)
    ccc6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ccca:	48 05 c8 00 00 00    	add    $0xc8,%rax
    ccd0:	48 8b 00             	mov    (%rax),%rax
    ccd3:	48 c1 e8 03          	shr    $0x3,%rax
    ccd7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    ccde:	00 
    ccdf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cce3:	48 01 d0             	add    %rdx,%rax
    cce6:	48 8b 30             	mov    (%rax),%rsi
    cce9:	0f b6 55 f0          	movzbl -0x10(%rbp),%edx
    cced:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ccf1:	48 05 c8 00 00 00    	add    $0xc8,%rax
    ccf7:	48 8b 00             	mov    (%rax),%rax
    ccfa:	83 e0 07             	and    $0x7,%eax
    ccfd:	c1 e0 03             	shl    $0x3,%eax
    cd00:	89 c1                	mov    %eax,%ecx
    cd02:	48 d3 e2             	shl    %cl,%rdx
    cd05:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cd09:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cd0f:	48 8b 00             	mov    (%rax),%rax
    cd12:	48 c1 e8 03          	shr    $0x3,%rax
    cd16:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    cd1d:	00 
    cd1e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cd22:	48 01 c8             	add    %rcx,%rax
    cd25:	48 31 f2             	xor    %rsi,%rdx
    cd28:	48 89 10             	mov    %rdx,(%rax)
    cd2b:	8b 45 f4             	mov    -0xc(%rbp),%eax
    cd2e:	83 e8 01             	sub    $0x1,%eax
    cd31:	c1 e8 03             	shr    $0x3,%eax
    cd34:	89 c0                	mov    %eax,%eax
    cd36:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    cd3d:	00 
    cd3e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cd42:	48 01 d0             	add    %rdx,%rax
    cd45:	48 8b 30             	mov    (%rax),%rsi
    cd48:	8b 45 f4             	mov    -0xc(%rbp),%eax
    cd4b:	83 e8 01             	sub    $0x1,%eax
    cd4e:	83 e0 07             	and    $0x7,%eax
    cd51:	c1 e0 03             	shl    $0x3,%eax
    cd54:	ba 80 00 00 00       	mov    $0x80,%edx
    cd59:	89 c1                	mov    %eax,%ecx
    cd5b:	48 d3 e2             	shl    %cl,%rdx
    cd5e:	8b 45 f4             	mov    -0xc(%rbp),%eax
    cd61:	83 e8 01             	sub    $0x1,%eax
    cd64:	c1 e8 03             	shr    $0x3,%eax
    cd67:	89 c0                	mov    %eax,%eax
    cd69:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
    cd70:	00 
    cd71:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cd75:	48 01 c8             	add    %rcx,%rax
    cd78:	48 31 f2             	xor    %rsi,%rdx
    cd7b:	48 89 10             	mov    %rdx,(%rax)
    cd7e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cd82:	48 05 c8 00 00 00    	add    $0xc8,%rax
    cd88:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    cd8f:	90                   	nop
    cd90:	5d                   	pop    %rbp
    cd91:	c3                   	ret

000000000000cd92 <keccak_inc_squeeze>:
    cd92:	f3 0f 1e fa          	endbr64
    cd96:	55                   	push   %rbp
    cd97:	48 89 e5             	mov    %rsp,%rbp
    cd9a:	48 83 ec 30          	sub    $0x30,%rsp
    cd9e:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    cda2:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    cda6:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    cdaa:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
    cdad:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    cdb4:	00 
    cdb5:	eb 74                	jmp    ce2b <keccak_inc_squeeze+0x99>
    cdb7:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    cdba:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    cdbe:	48 81 c2 c8 00 00 00 	add    $0xc8,%rdx
    cdc5:	48 8b 12             	mov    (%rdx),%rdx
    cdc8:	48 29 d0             	sub    %rdx,%rax
    cdcb:	48 89 c2             	mov    %rax,%rdx
    cdce:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cdd2:	48 01 d0             	add    %rdx,%rax
    cdd5:	48 c1 e8 03          	shr    $0x3,%rax
    cdd9:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    cde0:	00 
    cde1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    cde5:	48 01 d0             	add    %rdx,%rax
    cde8:	48 8b 30             	mov    (%rax),%rsi
    cdeb:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    cdee:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    cdf2:	48 81 c2 c8 00 00 00 	add    $0xc8,%rdx
    cdf9:	48 8b 12             	mov    (%rdx),%rdx
    cdfc:	48 29 d0             	sub    %rdx,%rax
    cdff:	48 89 c2             	mov    %rax,%rdx
    ce02:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ce06:	48 01 d0             	add    %rdx,%rax
    ce09:	83 e0 07             	and    $0x7,%eax
    ce0c:	c1 e0 03             	shl    $0x3,%eax
    ce0f:	89 c1                	mov    %eax,%ecx
    ce11:	48 d3 ee             	shr    %cl,%rsi
    ce14:	48 89 f1             	mov    %rsi,%rcx
    ce17:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    ce1b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ce1f:	48 01 d0             	add    %rdx,%rax
    ce22:	89 ca                	mov    %ecx,%edx
    ce24:	88 10                	mov    %dl,(%rax)
    ce26:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    ce2b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ce2f:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    ce33:	73 17                	jae    ce4c <keccak_inc_squeeze+0xba>
    ce35:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ce39:	48 05 c8 00 00 00    	add    $0xc8,%rax
    ce3f:	48 8b 00             	mov    (%rax),%rax
    ce42:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    ce46:	0f 82 6b ff ff ff    	jb     cdb7 <keccak_inc_squeeze+0x25>
    ce4c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ce50:	48 01 45 e8          	add    %rax,-0x18(%rbp)
    ce54:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ce58:	48 29 45 e0          	sub    %rax,-0x20(%rbp)
    ce5c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ce60:	48 05 c8 00 00 00    	add    $0xc8,%rax
    ce66:	48 8b 00             	mov    (%rax),%rax
    ce69:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ce6d:	48 81 c2 c8 00 00 00 	add    $0xc8,%rdx
    ce74:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    ce78:	48 89 02             	mov    %rax,(%rdx)
    ce7b:	e9 8e 00 00 00       	jmp    cf0e <keccak_inc_squeeze+0x17c>
    ce80:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ce84:	48 89 c7             	mov    %rax,%rdi
    ce87:	e8 f7 e5 ff ff       	call   b483 <KeccakF1600_StatePermute>
    ce8c:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    ce93:	00 
    ce94:	eb 40                	jmp    ced6 <keccak_inc_squeeze+0x144>
    ce96:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ce9a:	48 c1 e8 03          	shr    $0x3,%rax
    ce9e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    cea5:	00 
    cea6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ceaa:	48 01 d0             	add    %rdx,%rax
    cead:	48 8b 10             	mov    (%rax),%rdx
    ceb0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ceb4:	83 e0 07             	and    $0x7,%eax
    ceb7:	c1 e0 03             	shl    $0x3,%eax
    ceba:	89 c1                	mov    %eax,%ecx
    cebc:	48 d3 ea             	shr    %cl,%rdx
    cebf:	48 89 d1             	mov    %rdx,%rcx
    cec2:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    cec6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ceca:	48 01 d0             	add    %rdx,%rax
    cecd:	89 ca                	mov    %ecx,%edx
    cecf:	88 10                	mov    %dl,(%rax)
    ced1:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
    ced6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ceda:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    cede:	73 09                	jae    cee9 <keccak_inc_squeeze+0x157>
    cee0:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    cee3:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    cee7:	72 ad                	jb     ce96 <keccak_inc_squeeze+0x104>
    cee9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ceed:	48 01 45 e8          	add    %rax,-0x18(%rbp)
    cef1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cef5:	48 29 45 e0          	sub    %rax,-0x20(%rbp)
    cef9:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    cefc:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    cf00:	48 81 c2 c8 00 00 00 	add    $0xc8,%rdx
    cf07:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    cf0b:	48 89 02             	mov    %rax,(%rdx)
    cf0e:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    cf13:	0f 85 67 ff ff ff    	jne    ce80 <keccak_inc_squeeze+0xee>
    cf19:	90                   	nop
    cf1a:	90                   	nop
    cf1b:	c9                   	leave
    cf1c:	c3                   	ret

000000000000cf1d <shake128_inc_init>:
    cf1d:	f3 0f 1e fa          	endbr64
    cf21:	55                   	push   %rbp
    cf22:	48 89 e5             	mov    %rsp,%rbp
    cf25:	48 83 ec 10          	sub    $0x10,%rsp
    cf29:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    cf2d:	bf d0 00 00 00       	mov    $0xd0,%edi
    cf32:	e8 09 43 ff ff       	call   1240 <malloc@plt>
    cf37:	48 89 c2             	mov    %rax,%rdx
    cf3a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cf3e:	48 89 10             	mov    %rdx,(%rax)
    cf41:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cf45:	48 8b 00             	mov    (%rax),%rax
    cf48:	48 85 c0             	test   %rax,%rax
    cf4b:	75 0a                	jne    cf57 <shake128_inc_init+0x3a>
    cf4d:	bf 6f 00 00 00       	mov    $0x6f,%edi
    cf52:	e8 19 43 ff ff       	call   1270 <exit@plt>
    cf57:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cf5b:	48 8b 00             	mov    (%rax),%rax
    cf5e:	48 89 c7             	mov    %rax,%rdi
    cf61:	e8 e9 fa ff ff       	call   ca4f <keccak_inc_init>
    cf66:	90                   	nop
    cf67:	c9                   	leave
    cf68:	c3                   	ret

000000000000cf69 <shake128_inc_absorb>:
    cf69:	f3 0f 1e fa          	endbr64
    cf6d:	55                   	push   %rbp
    cf6e:	48 89 e5             	mov    %rsp,%rbp
    cf71:	48 83 ec 18          	sub    $0x18,%rsp
    cf75:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    cf79:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    cf7d:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    cf81:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cf85:	48 8b 00             	mov    (%rax),%rax
    cf88:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    cf8c:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    cf90:	be a8 00 00 00       	mov    $0xa8,%esi
    cf95:	48 89 c7             	mov    %rax,%rdi
    cf98:	e8 02 fb ff ff       	call   ca9f <keccak_inc_absorb>
    cf9d:	90                   	nop
    cf9e:	c9                   	leave
    cf9f:	c3                   	ret

000000000000cfa0 <shake128_inc_finalize>:
    cfa0:	f3 0f 1e fa          	endbr64
    cfa4:	55                   	push   %rbp
    cfa5:	48 89 e5             	mov    %rsp,%rbp
    cfa8:	48 83 ec 08          	sub    $0x8,%rsp
    cfac:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    cfb0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cfb4:	48 8b 00             	mov    (%rax),%rax
    cfb7:	ba 1f 00 00 00       	mov    $0x1f,%edx
    cfbc:	be a8 00 00 00       	mov    $0xa8,%esi
    cfc1:	48 89 c7             	mov    %rax,%rdi
    cfc4:	e8 e9 fc ff ff       	call   ccb2 <keccak_inc_finalize>
    cfc9:	90                   	nop
    cfca:	c9                   	leave
    cfcb:	c3                   	ret

000000000000cfcc <shake128_inc_squeeze>:
    cfcc:	f3 0f 1e fa          	endbr64
    cfd0:	55                   	push   %rbp
    cfd1:	48 89 e5             	mov    %rsp,%rbp
    cfd4:	48 83 ec 18          	sub    $0x18,%rsp
    cfd8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    cfdc:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    cfe0:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    cfe4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    cfe8:	48 8b 10             	mov    (%rax),%rdx
    cfeb:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    cfef:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    cff3:	b9 a8 00 00 00       	mov    $0xa8,%ecx
    cff8:	48 89 c7             	mov    %rax,%rdi
    cffb:	e8 92 fd ff ff       	call   cd92 <keccak_inc_squeeze>
    d000:	90                   	nop
    d001:	c9                   	leave
    d002:	c3                   	ret

000000000000d003 <shake128_inc_ctx_clone>:
    d003:	f3 0f 1e fa          	endbr64
    d007:	55                   	push   %rbp
    d008:	48 89 e5             	mov    %rsp,%rbp
    d00b:	48 83 ec 10          	sub    $0x10,%rsp
    d00f:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d013:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d017:	bf d0 00 00 00       	mov    $0xd0,%edi
    d01c:	e8 1f 42 ff ff       	call   1240 <malloc@plt>
    d021:	48 89 c2             	mov    %rax,%rdx
    d024:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d028:	48 89 10             	mov    %rdx,(%rax)
    d02b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d02f:	48 8b 00             	mov    (%rax),%rax
    d032:	48 85 c0             	test   %rax,%rax
    d035:	75 0a                	jne    d041 <shake128_inc_ctx_clone+0x3e>
    d037:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d03c:	e8 2f 42 ff ff       	call   1270 <exit@plt>
    d041:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    d045:	48 8b 08             	mov    (%rax),%rcx
    d048:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d04c:	48 8b 00             	mov    (%rax),%rax
    d04f:	ba d0 00 00 00       	mov    $0xd0,%edx
    d054:	48 89 ce             	mov    %rcx,%rsi
    d057:	48 89 c7             	mov    %rax,%rdi
    d05a:	e8 d1 41 ff ff       	call   1230 <memcpy@plt>
    d05f:	90                   	nop
    d060:	c9                   	leave
    d061:	c3                   	ret

000000000000d062 <shake128_inc_ctx_release>:
    d062:	f3 0f 1e fa          	endbr64
    d066:	55                   	push   %rbp
    d067:	48 89 e5             	mov    %rsp,%rbp
    d06a:	48 83 ec 10          	sub    $0x10,%rsp
    d06e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d072:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d076:	48 8b 00             	mov    (%rax),%rax
    d079:	48 89 c7             	mov    %rax,%rdi
    d07c:	e8 ef 40 ff ff       	call   1170 <free@plt>
    d081:	90                   	nop
    d082:	c9                   	leave
    d083:	c3                   	ret

000000000000d084 <shake256_inc_init>:
    d084:	f3 0f 1e fa          	endbr64
    d088:	55                   	push   %rbp
    d089:	48 89 e5             	mov    %rsp,%rbp
    d08c:	48 83 ec 10          	sub    $0x10,%rsp
    d090:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d094:	bf d0 00 00 00       	mov    $0xd0,%edi
    d099:	e8 a2 41 ff ff       	call   1240 <malloc@plt>
    d09e:	48 89 c2             	mov    %rax,%rdx
    d0a1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d0a5:	48 89 10             	mov    %rdx,(%rax)
    d0a8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d0ac:	48 8b 00             	mov    (%rax),%rax
    d0af:	48 85 c0             	test   %rax,%rax
    d0b2:	75 0a                	jne    d0be <shake256_inc_init+0x3a>
    d0b4:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d0b9:	e8 b2 41 ff ff       	call   1270 <exit@plt>
    d0be:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d0c2:	48 8b 00             	mov    (%rax),%rax
    d0c5:	48 89 c7             	mov    %rax,%rdi
    d0c8:	e8 82 f9 ff ff       	call   ca4f <keccak_inc_init>
    d0cd:	90                   	nop
    d0ce:	c9                   	leave
    d0cf:	c3                   	ret

000000000000d0d0 <shake256_inc_absorb>:
    d0d0:	f3 0f 1e fa          	endbr64
    d0d4:	55                   	push   %rbp
    d0d5:	48 89 e5             	mov    %rsp,%rbp
    d0d8:	48 83 ec 18          	sub    $0x18,%rsp
    d0dc:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d0e0:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d0e4:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d0e8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d0ec:	48 8b 00             	mov    (%rax),%rax
    d0ef:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    d0f3:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    d0f7:	be 88 00 00 00       	mov    $0x88,%esi
    d0fc:	48 89 c7             	mov    %rax,%rdi
    d0ff:	e8 9b f9 ff ff       	call   ca9f <keccak_inc_absorb>
    d104:	90                   	nop
    d105:	c9                   	leave
    d106:	c3                   	ret

000000000000d107 <shake256_inc_finalize>:
    d107:	f3 0f 1e fa          	endbr64
    d10b:	55                   	push   %rbp
    d10c:	48 89 e5             	mov    %rsp,%rbp
    d10f:	48 83 ec 08          	sub    $0x8,%rsp
    d113:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d117:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d11b:	48 8b 00             	mov    (%rax),%rax
    d11e:	ba 1f 00 00 00       	mov    $0x1f,%edx
    d123:	be 88 00 00 00       	mov    $0x88,%esi
    d128:	48 89 c7             	mov    %rax,%rdi
    d12b:	e8 82 fb ff ff       	call   ccb2 <keccak_inc_finalize>
    d130:	90                   	nop
    d131:	c9                   	leave
    d132:	c3                   	ret

000000000000d133 <shake256_inc_squeeze>:
    d133:	f3 0f 1e fa          	endbr64
    d137:	55                   	push   %rbp
    d138:	48 89 e5             	mov    %rsp,%rbp
    d13b:	48 83 ec 18          	sub    $0x18,%rsp
    d13f:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d143:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d147:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d14b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    d14f:	48 8b 10             	mov    (%rax),%rdx
    d152:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    d156:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d15a:	b9 88 00 00 00       	mov    $0x88,%ecx
    d15f:	48 89 c7             	mov    %rax,%rdi
    d162:	e8 2b fc ff ff       	call   cd92 <keccak_inc_squeeze>
    d167:	90                   	nop
    d168:	c9                   	leave
    d169:	c3                   	ret

000000000000d16a <shake256_inc_ctx_clone>:
    d16a:	f3 0f 1e fa          	endbr64
    d16e:	55                   	push   %rbp
    d16f:	48 89 e5             	mov    %rsp,%rbp
    d172:	48 83 ec 10          	sub    $0x10,%rsp
    d176:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d17a:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d17e:	bf d0 00 00 00       	mov    $0xd0,%edi
    d183:	e8 b8 40 ff ff       	call   1240 <malloc@plt>
    d188:	48 89 c2             	mov    %rax,%rdx
    d18b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d18f:	48 89 10             	mov    %rdx,(%rax)
    d192:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d196:	48 8b 00             	mov    (%rax),%rax
    d199:	48 85 c0             	test   %rax,%rax
    d19c:	75 0a                	jne    d1a8 <shake256_inc_ctx_clone+0x3e>
    d19e:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d1a3:	e8 c8 40 ff ff       	call   1270 <exit@plt>
    d1a8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    d1ac:	48 8b 08             	mov    (%rax),%rcx
    d1af:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d1b3:	48 8b 00             	mov    (%rax),%rax
    d1b6:	ba d0 00 00 00       	mov    $0xd0,%edx
    d1bb:	48 89 ce             	mov    %rcx,%rsi
    d1be:	48 89 c7             	mov    %rax,%rdi
    d1c1:	e8 6a 40 ff ff       	call   1230 <memcpy@plt>
    d1c6:	90                   	nop
    d1c7:	c9                   	leave
    d1c8:	c3                   	ret

000000000000d1c9 <shake256_inc_ctx_release>:
    d1c9:	f3 0f 1e fa          	endbr64
    d1cd:	55                   	push   %rbp
    d1ce:	48 89 e5             	mov    %rsp,%rbp
    d1d1:	48 83 ec 10          	sub    $0x10,%rsp
    d1d5:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d1d9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d1dd:	48 8b 00             	mov    (%rax),%rax
    d1e0:	48 89 c7             	mov    %rax,%rdi
    d1e3:	e8 88 3f ff ff       	call   1170 <free@plt>
    d1e8:	90                   	nop
    d1e9:	c9                   	leave
    d1ea:	c3                   	ret

000000000000d1eb <shake128_absorb>:
    d1eb:	f3 0f 1e fa          	endbr64
    d1ef:	55                   	push   %rbp
    d1f0:	48 89 e5             	mov    %rsp,%rbp
    d1f3:	48 83 ec 20          	sub    $0x20,%rsp
    d1f7:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d1fb:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d1ff:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d203:	bf c8 00 00 00       	mov    $0xc8,%edi
    d208:	e8 33 40 ff ff       	call   1240 <malloc@plt>
    d20d:	48 89 c2             	mov    %rax,%rdx
    d210:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d214:	48 89 10             	mov    %rdx,(%rax)
    d217:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d21b:	48 8b 00             	mov    (%rax),%rax
    d21e:	48 85 c0             	test   %rax,%rax
    d221:	75 0a                	jne    d22d <shake128_absorb+0x42>
    d223:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d228:	e8 43 40 ff ff       	call   1270 <exit@plt>
    d22d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d231:	48 8b 00             	mov    (%rax),%rax
    d234:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    d238:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    d23c:	41 b8 1f 00 00 00    	mov    $0x1f,%r8d
    d242:	be a8 00 00 00       	mov    $0xa8,%esi
    d247:	48 89 c7             	mov    %rax,%rdi
    d24a:	e8 c4 f4 ff ff       	call   c713 <keccak_absorb>
    d24f:	90                   	nop
    d250:	c9                   	leave
    d251:	c3                   	ret

000000000000d252 <shake128_squeezeblocks>:
    d252:	f3 0f 1e fa          	endbr64
    d256:	55                   	push   %rbp
    d257:	48 89 e5             	mov    %rsp,%rbp
    d25a:	48 83 ec 18          	sub    $0x18,%rsp
    d25e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d262:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d266:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d26a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    d26e:	48 8b 10             	mov    (%rax),%rdx
    d271:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    d275:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d279:	b9 a8 00 00 00       	mov    $0xa8,%ecx
    d27e:	48 89 c7             	mov    %rax,%rdi
    d281:	e8 38 f7 ff ff       	call   c9be <keccak_squeezeblocks>
    d286:	90                   	nop
    d287:	c9                   	leave
    d288:	c3                   	ret

000000000000d289 <shake128_ctx_clone>:
    d289:	f3 0f 1e fa          	endbr64
    d28d:	55                   	push   %rbp
    d28e:	48 89 e5             	mov    %rsp,%rbp
    d291:	48 83 ec 10          	sub    $0x10,%rsp
    d295:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d299:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d29d:	bf c8 00 00 00       	mov    $0xc8,%edi
    d2a2:	e8 99 3f ff ff       	call   1240 <malloc@plt>
    d2a7:	48 89 c2             	mov    %rax,%rdx
    d2aa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d2ae:	48 89 10             	mov    %rdx,(%rax)
    d2b1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d2b5:	48 8b 00             	mov    (%rax),%rax
    d2b8:	48 85 c0             	test   %rax,%rax
    d2bb:	75 0a                	jne    d2c7 <shake128_ctx_clone+0x3e>
    d2bd:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d2c2:	e8 a9 3f ff ff       	call   1270 <exit@plt>
    d2c7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    d2cb:	48 8b 08             	mov    (%rax),%rcx
    d2ce:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d2d2:	48 8b 00             	mov    (%rax),%rax
    d2d5:	ba c8 00 00 00       	mov    $0xc8,%edx
    d2da:	48 89 ce             	mov    %rcx,%rsi
    d2dd:	48 89 c7             	mov    %rax,%rdi
    d2e0:	e8 4b 3f ff ff       	call   1230 <memcpy@plt>
    d2e5:	90                   	nop
    d2e6:	c9                   	leave
    d2e7:	c3                   	ret

000000000000d2e8 <shake128_ctx_release>:
    d2e8:	f3 0f 1e fa          	endbr64
    d2ec:	55                   	push   %rbp
    d2ed:	48 89 e5             	mov    %rsp,%rbp
    d2f0:	48 83 ec 10          	sub    $0x10,%rsp
    d2f4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d2f8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d2fc:	48 8b 00             	mov    (%rax),%rax
    d2ff:	48 89 c7             	mov    %rax,%rdi
    d302:	e8 69 3e ff ff       	call   1170 <free@plt>
    d307:	90                   	nop
    d308:	c9                   	leave
    d309:	c3                   	ret

000000000000d30a <shake256_absorb>:
    d30a:	f3 0f 1e fa          	endbr64
    d30e:	55                   	push   %rbp
    d30f:	48 89 e5             	mov    %rsp,%rbp
    d312:	48 83 ec 20          	sub    $0x20,%rsp
    d316:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d31a:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d31e:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d322:	bf c8 00 00 00       	mov    $0xc8,%edi
    d327:	e8 14 3f ff ff       	call   1240 <malloc@plt>
    d32c:	48 89 c2             	mov    %rax,%rdx
    d32f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d333:	48 89 10             	mov    %rdx,(%rax)
    d336:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d33a:	48 8b 00             	mov    (%rax),%rax
    d33d:	48 85 c0             	test   %rax,%rax
    d340:	75 0a                	jne    d34c <shake256_absorb+0x42>
    d342:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d347:	e8 24 3f ff ff       	call   1270 <exit@plt>
    d34c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d350:	48 8b 00             	mov    (%rax),%rax
    d353:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    d357:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    d35b:	41 b8 1f 00 00 00    	mov    $0x1f,%r8d
    d361:	be 88 00 00 00       	mov    $0x88,%esi
    d366:	48 89 c7             	mov    %rax,%rdi
    d369:	e8 a5 f3 ff ff       	call   c713 <keccak_absorb>
    d36e:	90                   	nop
    d36f:	c9                   	leave
    d370:	c3                   	ret

000000000000d371 <shake256_squeezeblocks>:
    d371:	f3 0f 1e fa          	endbr64
    d375:	55                   	push   %rbp
    d376:	48 89 e5             	mov    %rsp,%rbp
    d379:	48 83 ec 18          	sub    $0x18,%rsp
    d37d:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d381:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d385:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d389:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    d38d:	48 8b 10             	mov    (%rax),%rdx
    d390:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    d394:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d398:	b9 88 00 00 00       	mov    $0x88,%ecx
    d39d:	48 89 c7             	mov    %rax,%rdi
    d3a0:	e8 19 f6 ff ff       	call   c9be <keccak_squeezeblocks>
    d3a5:	90                   	nop
    d3a6:	c9                   	leave
    d3a7:	c3                   	ret

000000000000d3a8 <shake256_ctx_clone>:
    d3a8:	f3 0f 1e fa          	endbr64
    d3ac:	55                   	push   %rbp
    d3ad:	48 89 e5             	mov    %rsp,%rbp
    d3b0:	48 83 ec 10          	sub    $0x10,%rsp
    d3b4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d3b8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d3bc:	bf c8 00 00 00       	mov    $0xc8,%edi
    d3c1:	e8 7a 3e ff ff       	call   1240 <malloc@plt>
    d3c6:	48 89 c2             	mov    %rax,%rdx
    d3c9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d3cd:	48 89 10             	mov    %rdx,(%rax)
    d3d0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d3d4:	48 8b 00             	mov    (%rax),%rax
    d3d7:	48 85 c0             	test   %rax,%rax
    d3da:	75 0a                	jne    d3e6 <shake256_ctx_clone+0x3e>
    d3dc:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d3e1:	e8 8a 3e ff ff       	call   1270 <exit@plt>
    d3e6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    d3ea:	48 8b 08             	mov    (%rax),%rcx
    d3ed:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d3f1:	48 8b 00             	mov    (%rax),%rax
    d3f4:	ba c8 00 00 00       	mov    $0xc8,%edx
    d3f9:	48 89 ce             	mov    %rcx,%rsi
    d3fc:	48 89 c7             	mov    %rax,%rdi
    d3ff:	e8 2c 3e ff ff       	call   1230 <memcpy@plt>
    d404:	90                   	nop
    d405:	c9                   	leave
    d406:	c3                   	ret

000000000000d407 <shake256_ctx_release>:
    d407:	f3 0f 1e fa          	endbr64
    d40b:	55                   	push   %rbp
    d40c:	48 89 e5             	mov    %rsp,%rbp
    d40f:	48 83 ec 10          	sub    $0x10,%rsp
    d413:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d417:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d41b:	48 8b 00             	mov    (%rax),%rax
    d41e:	48 89 c7             	mov    %rax,%rdi
    d421:	e8 4a 3d ff ff       	call   1170 <free@plt>
    d426:	90                   	nop
    d427:	c9                   	leave
    d428:	c3                   	ret

000000000000d429 <shake128>:
    d429:	f3 0f 1e fa          	endbr64
    d42d:	55                   	push   %rbp
    d42e:	48 89 e5             	mov    %rsp,%rbp
    d431:	48 81 ec f0 00 00 00 	sub    $0xf0,%rsp
    d438:	48 89 bd 28 ff ff ff 	mov    %rdi,-0xd8(%rbp)
    d43f:	48 89 b5 20 ff ff ff 	mov    %rsi,-0xe0(%rbp)
    d446:	48 89 95 18 ff ff ff 	mov    %rdx,-0xe8(%rbp)
    d44d:	48 89 8d 10 ff ff ff 	mov    %rcx,-0xf0(%rbp)
    d454:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d45b:	00 00 
    d45d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    d461:	31 c0                	xor    %eax,%eax
    d463:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    d46a:	48 c1 e8 03          	shr    $0x3,%rax
    d46e:	48 ba 31 0c c3 30 0c 	movabs $0xc30c30c30c30c31,%rdx
    d475:	c3 30 0c 
    d478:	48 f7 e2             	mul    %rdx
    d47b:	48 89 95 48 ff ff ff 	mov    %rdx,-0xb8(%rbp)
    d482:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    d489:	48 8b 8d 18 ff ff ff 	mov    -0xe8(%rbp),%rcx
    d490:	48 8d 85 38 ff ff ff 	lea    -0xc8(%rbp),%rax
    d497:	48 89 ce             	mov    %rcx,%rsi
    d49a:	48 89 c7             	mov    %rax,%rdi
    d49d:	e8 49 fd ff ff       	call   d1eb <shake128_absorb>
    d4a2:	48 8d 85 38 ff ff ff 	lea    -0xc8(%rbp),%rax
    d4a9:	48 8b b5 48 ff ff ff 	mov    -0xb8(%rbp),%rsi
    d4b0:	48 8b 8d 28 ff ff ff 	mov    -0xd8(%rbp),%rcx
    d4b7:	48 89 c2             	mov    %rax,%rdx
    d4ba:	48 89 cf             	mov    %rcx,%rdi
    d4bd:	e8 90 fd ff ff       	call   d252 <shake128_squeezeblocks>
    d4c2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    d4c9:	48 69 c0 a8 00 00 00 	imul   $0xa8,%rax,%rax
    d4d0:	48 01 85 28 ff ff ff 	add    %rax,-0xd8(%rbp)
    d4d7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    d4de:	48 69 c0 a8 00 00 00 	imul   $0xa8,%rax,%rax
    d4e5:	48 29 85 20 ff ff ff 	sub    %rax,-0xe0(%rbp)
    d4ec:	48 83 bd 20 ff ff ff 	cmpq   $0x0,-0xe0(%rbp)
    d4f3:	00 
    d4f4:	74 67                	je     d55d <shake128+0x134>
    d4f6:	48 8d 95 38 ff ff ff 	lea    -0xc8(%rbp),%rdx
    d4fd:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    d504:	be 01 00 00 00       	mov    $0x1,%esi
    d509:	48 89 c7             	mov    %rax,%rdi
    d50c:	e8 41 fd ff ff       	call   d252 <shake128_squeezeblocks>
    d511:	48 c7 85 40 ff ff ff 	movq   $0x0,-0xc0(%rbp)
    d518:	00 00 00 00 
    d51c:	eb 2f                	jmp    d54d <shake128+0x124>
    d51e:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    d525:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    d52c:	48 01 c2             	add    %rax,%rdx
    d52f:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    d536:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    d53d:	48 01 c8             	add    %rcx,%rax
    d540:	0f b6 00             	movzbl (%rax),%eax
    d543:	88 02                	mov    %al,(%rdx)
    d545:	48 83 85 40 ff ff ff 	addq   $0x1,-0xc0(%rbp)
    d54c:	01 
    d54d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    d554:	48 3b 85 20 ff ff ff 	cmp    -0xe0(%rbp),%rax
    d55b:	72 c1                	jb     d51e <shake128+0xf5>
    d55d:	48 8d 85 38 ff ff ff 	lea    -0xc8(%rbp),%rax
    d564:	48 89 c7             	mov    %rax,%rdi
    d567:	e8 7c fd ff ff       	call   d2e8 <shake128_ctx_release>
    d56c:	90                   	nop
    d56d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d571:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d578:	00 00 
    d57a:	74 05                	je     d581 <shake128+0x158>
    d57c:	e8 4f 3c ff ff       	call   11d0 <__stack_chk_fail@plt>
    d581:	c9                   	leave
    d582:	c3                   	ret

000000000000d583 <shake256>:
    d583:	f3 0f 1e fa          	endbr64
    d587:	55                   	push   %rbp
    d588:	48 89 e5             	mov    %rsp,%rbp
    d58b:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
    d592:	48 89 bd 48 ff ff ff 	mov    %rdi,-0xb8(%rbp)
    d599:	48 89 b5 40 ff ff ff 	mov    %rsi,-0xc0(%rbp)
    d5a0:	48 89 95 38 ff ff ff 	mov    %rdx,-0xc8(%rbp)
    d5a7:	48 89 8d 30 ff ff ff 	mov    %rcx,-0xd0(%rbp)
    d5ae:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d5b5:	00 00 
    d5b7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    d5bb:	31 c0                	xor    %eax,%eax
    d5bd:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    d5c4:	48 ba f1 f0 f0 f0 f0 	movabs $0xf0f0f0f0f0f0f0f1,%rdx
    d5cb:	f0 f0 f0 
    d5ce:	48 f7 e2             	mul    %rdx
    d5d1:	48 89 d0             	mov    %rdx,%rax
    d5d4:	48 c1 e8 07          	shr    $0x7,%rax
    d5d8:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    d5df:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    d5e6:	48 8b 8d 38 ff ff ff 	mov    -0xc8(%rbp),%rcx
    d5ed:	48 8d 85 58 ff ff ff 	lea    -0xa8(%rbp),%rax
    d5f4:	48 89 ce             	mov    %rcx,%rsi
    d5f7:	48 89 c7             	mov    %rax,%rdi
    d5fa:	e8 0b fd ff ff       	call   d30a <shake256_absorb>
    d5ff:	48 8d 85 58 ff ff ff 	lea    -0xa8(%rbp),%rax
    d606:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    d60d:	48 8b 8d 48 ff ff ff 	mov    -0xb8(%rbp),%rcx
    d614:	48 89 c2             	mov    %rax,%rdx
    d617:	48 89 cf             	mov    %rcx,%rdi
    d61a:	e8 52 fd ff ff       	call   d371 <shake256_squeezeblocks>
    d61f:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    d626:	48 69 c0 88 00 00 00 	imul   $0x88,%rax,%rax
    d62d:	48 01 85 48 ff ff ff 	add    %rax,-0xb8(%rbp)
    d634:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    d63b:	48 69 c0 88 00 00 00 	imul   $0x88,%rax,%rax
    d642:	48 29 85 40 ff ff ff 	sub    %rax,-0xc0(%rbp)
    d649:	48 83 bd 40 ff ff ff 	cmpq   $0x0,-0xc0(%rbp)
    d650:	00 
    d651:	74 67                	je     d6ba <shake256+0x137>
    d653:	48 8d 95 58 ff ff ff 	lea    -0xa8(%rbp),%rdx
    d65a:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    d661:	be 01 00 00 00       	mov    $0x1,%esi
    d666:	48 89 c7             	mov    %rax,%rdi
    d669:	e8 03 fd ff ff       	call   d371 <shake256_squeezeblocks>
    d66e:	48 c7 85 60 ff ff ff 	movq   $0x0,-0xa0(%rbp)
    d675:	00 00 00 00 
    d679:	eb 2f                	jmp    d6aa <shake256+0x127>
    d67b:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    d682:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    d689:	48 01 c2             	add    %rax,%rdx
    d68c:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    d693:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    d69a:	48 01 c8             	add    %rcx,%rax
    d69d:	0f b6 00             	movzbl (%rax),%eax
    d6a0:	88 02                	mov    %al,(%rdx)
    d6a2:	48 83 85 60 ff ff ff 	addq   $0x1,-0xa0(%rbp)
    d6a9:	01 
    d6aa:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    d6b1:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    d6b8:	72 c1                	jb     d67b <shake256+0xf8>
    d6ba:	48 8d 85 58 ff ff ff 	lea    -0xa8(%rbp),%rax
    d6c1:	48 89 c7             	mov    %rax,%rdi
    d6c4:	e8 3e fd ff ff       	call   d407 <shake256_ctx_release>
    d6c9:	90                   	nop
    d6ca:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d6ce:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d6d5:	00 00 
    d6d7:	74 05                	je     d6de <shake256+0x15b>
    d6d9:	e8 f2 3a ff ff       	call   11d0 <__stack_chk_fail@plt>
    d6de:	c9                   	leave
    d6df:	c3                   	ret

000000000000d6e0 <sha3_256_inc_init>:
    d6e0:	f3 0f 1e fa          	endbr64
    d6e4:	55                   	push   %rbp
    d6e5:	48 89 e5             	mov    %rsp,%rbp
    d6e8:	48 83 ec 10          	sub    $0x10,%rsp
    d6ec:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d6f0:	bf d0 00 00 00       	mov    $0xd0,%edi
    d6f5:	e8 46 3b ff ff       	call   1240 <malloc@plt>
    d6fa:	48 89 c2             	mov    %rax,%rdx
    d6fd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d701:	48 89 10             	mov    %rdx,(%rax)
    d704:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d708:	48 8b 00             	mov    (%rax),%rax
    d70b:	48 85 c0             	test   %rax,%rax
    d70e:	75 0a                	jne    d71a <sha3_256_inc_init+0x3a>
    d710:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d715:	e8 56 3b ff ff       	call   1270 <exit@plt>
    d71a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d71e:	48 8b 00             	mov    (%rax),%rax
    d721:	48 89 c7             	mov    %rax,%rdi
    d724:	e8 26 f3 ff ff       	call   ca4f <keccak_inc_init>
    d729:	90                   	nop
    d72a:	c9                   	leave
    d72b:	c3                   	ret

000000000000d72c <sha3_256_inc_ctx_clone>:
    d72c:	f3 0f 1e fa          	endbr64
    d730:	55                   	push   %rbp
    d731:	48 89 e5             	mov    %rsp,%rbp
    d734:	48 83 ec 10          	sub    $0x10,%rsp
    d738:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d73c:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d740:	bf d0 00 00 00       	mov    $0xd0,%edi
    d745:	e8 f6 3a ff ff       	call   1240 <malloc@plt>
    d74a:	48 89 c2             	mov    %rax,%rdx
    d74d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d751:	48 89 10             	mov    %rdx,(%rax)
    d754:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d758:	48 8b 00             	mov    (%rax),%rax
    d75b:	48 85 c0             	test   %rax,%rax
    d75e:	75 0a                	jne    d76a <sha3_256_inc_ctx_clone+0x3e>
    d760:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d765:	e8 06 3b ff ff       	call   1270 <exit@plt>
    d76a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    d76e:	48 8b 08             	mov    (%rax),%rcx
    d771:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d775:	48 8b 00             	mov    (%rax),%rax
    d778:	ba d0 00 00 00       	mov    $0xd0,%edx
    d77d:	48 89 ce             	mov    %rcx,%rsi
    d780:	48 89 c7             	mov    %rax,%rdi
    d783:	e8 a8 3a ff ff       	call   1230 <memcpy@plt>
    d788:	90                   	nop
    d789:	c9                   	leave
    d78a:	c3                   	ret

000000000000d78b <sha3_256_inc_ctx_release>:
    d78b:	f3 0f 1e fa          	endbr64
    d78f:	55                   	push   %rbp
    d790:	48 89 e5             	mov    %rsp,%rbp
    d793:	48 83 ec 10          	sub    $0x10,%rsp
    d797:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d79b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d79f:	48 8b 00             	mov    (%rax),%rax
    d7a2:	48 89 c7             	mov    %rax,%rdi
    d7a5:	e8 c6 39 ff ff       	call   1170 <free@plt>
    d7aa:	90                   	nop
    d7ab:	c9                   	leave
    d7ac:	c3                   	ret

000000000000d7ad <sha3_256_inc_absorb>:
    d7ad:	f3 0f 1e fa          	endbr64
    d7b1:	55                   	push   %rbp
    d7b2:	48 89 e5             	mov    %rsp,%rbp
    d7b5:	48 83 ec 18          	sub    $0x18,%rsp
    d7b9:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d7bd:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d7c1:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    d7c5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d7c9:	48 8b 00             	mov    (%rax),%rax
    d7cc:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    d7d0:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    d7d4:	be 88 00 00 00       	mov    $0x88,%esi
    d7d9:	48 89 c7             	mov    %rax,%rdi
    d7dc:	e8 be f2 ff ff       	call   ca9f <keccak_inc_absorb>
    d7e1:	90                   	nop
    d7e2:	c9                   	leave
    d7e3:	c3                   	ret

000000000000d7e4 <sha3_256_inc_finalize>:
    d7e4:	f3 0f 1e fa          	endbr64
    d7e8:	55                   	push   %rbp
    d7e9:	48 89 e5             	mov    %rsp,%rbp
    d7ec:	48 81 ec b0 00 00 00 	sub    $0xb0,%rsp
    d7f3:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    d7fa:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
    d801:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d808:	00 00 
    d80a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    d80e:	31 c0                	xor    %eax,%eax
    d810:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    d817:	48 8b 00             	mov    (%rax),%rax
    d81a:	ba 06 00 00 00       	mov    $0x6,%edx
    d81f:	be 88 00 00 00       	mov    $0x88,%esi
    d824:	48 89 c7             	mov    %rax,%rdi
    d827:	e8 86 f4 ff ff       	call   ccb2 <keccak_inc_finalize>
    d82c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    d833:	48 8b 10             	mov    (%rax),%rdx
    d836:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    d83d:	b9 88 00 00 00       	mov    $0x88,%ecx
    d842:	be 01 00 00 00       	mov    $0x1,%esi
    d847:	48 89 c7             	mov    %rax,%rdi
    d84a:	e8 6f f1 ff ff       	call   c9be <keccak_squeezeblocks>
    d84f:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    d856:	48 89 c7             	mov    %rax,%rdi
    d859:	e8 2d ff ff ff       	call   d78b <sha3_256_inc_ctx_release>
    d85e:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
    d865:	00 00 00 00 
    d869:	eb 2f                	jmp    d89a <sha3_256_inc_finalize+0xb6>
    d86b:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    d872:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    d879:	48 01 c2             	add    %rax,%rdx
    d87c:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    d883:	48 8b 8d 68 ff ff ff 	mov    -0x98(%rbp),%rcx
    d88a:	48 01 c8             	add    %rcx,%rax
    d88d:	0f b6 00             	movzbl (%rax),%eax
    d890:	88 02                	mov    %al,(%rdx)
    d892:	48 83 85 68 ff ff ff 	addq   $0x1,-0x98(%rbp)
    d899:	01 
    d89a:	48 83 bd 68 ff ff ff 	cmpq   $0x1f,-0x98(%rbp)
    d8a1:	1f 
    d8a2:	76 c7                	jbe    d86b <sha3_256_inc_finalize+0x87>
    d8a4:	90                   	nop
    d8a5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d8a9:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d8b0:	00 00 
    d8b2:	74 05                	je     d8b9 <sha3_256_inc_finalize+0xd5>
    d8b4:	e8 17 39 ff ff       	call   11d0 <__stack_chk_fail@plt>
    d8b9:	c9                   	leave
    d8ba:	c3                   	ret

000000000000d8bb <sha3_256>:
    d8bb:	f3 0f 1e fa          	endbr64
    d8bf:	55                   	push   %rbp
    d8c0:	48 89 e5             	mov    %rsp,%rbp
    d8c3:	48 81 ec 90 01 00 00 	sub    $0x190,%rsp
    d8ca:	48 89 bd 88 fe ff ff 	mov    %rdi,-0x178(%rbp)
    d8d1:	48 89 b5 80 fe ff ff 	mov    %rsi,-0x180(%rbp)
    d8d8:	48 89 95 78 fe ff ff 	mov    %rdx,-0x188(%rbp)
    d8df:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d8e6:	00 00 
    d8e8:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    d8ec:	31 c0                	xor    %eax,%eax
    d8ee:	48 8b 8d 78 fe ff ff 	mov    -0x188(%rbp),%rcx
    d8f5:	48 8b 95 80 fe ff ff 	mov    -0x180(%rbp),%rdx
    d8fc:	48 8d 85 a0 fe ff ff 	lea    -0x160(%rbp),%rax
    d903:	41 b8 06 00 00 00    	mov    $0x6,%r8d
    d909:	be 88 00 00 00       	mov    $0x88,%esi
    d90e:	48 89 c7             	mov    %rax,%rdi
    d911:	e8 fd ed ff ff       	call   c713 <keccak_absorb>
    d916:	48 8d 95 a0 fe ff ff 	lea    -0x160(%rbp),%rdx
    d91d:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    d924:	b9 88 00 00 00       	mov    $0x88,%ecx
    d929:	be 01 00 00 00       	mov    $0x1,%esi
    d92e:	48 89 c7             	mov    %rax,%rdi
    d931:	e8 88 f0 ff ff       	call   c9be <keccak_squeezeblocks>
    d936:	48 c7 85 98 fe ff ff 	movq   $0x0,-0x168(%rbp)
    d93d:	00 00 00 00 
    d941:	eb 2f                	jmp    d972 <sha3_256+0xb7>
    d943:	48 8b 95 88 fe ff ff 	mov    -0x178(%rbp),%rdx
    d94a:	48 8b 85 98 fe ff ff 	mov    -0x168(%rbp),%rax
    d951:	48 01 c2             	add    %rax,%rdx
    d954:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax
    d95b:	48 8b 8d 98 fe ff ff 	mov    -0x168(%rbp),%rcx
    d962:	48 01 c8             	add    %rcx,%rax
    d965:	0f b6 00             	movzbl (%rax),%eax
    d968:	88 02                	mov    %al,(%rdx)
    d96a:	48 83 85 98 fe ff ff 	addq   $0x1,-0x168(%rbp)
    d971:	01 
    d972:	48 83 bd 98 fe ff ff 	cmpq   $0x1f,-0x168(%rbp)
    d979:	1f 
    d97a:	76 c7                	jbe    d943 <sha3_256+0x88>
    d97c:	90                   	nop
    d97d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d981:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d988:	00 00 
    d98a:	74 05                	je     d991 <sha3_256+0xd6>
    d98c:	e8 3f 38 ff ff       	call   11d0 <__stack_chk_fail@plt>
    d991:	c9                   	leave
    d992:	c3                   	ret

000000000000d993 <sha3_384_inc_init>:
    d993:	f3 0f 1e fa          	endbr64
    d997:	55                   	push   %rbp
    d998:	48 89 e5             	mov    %rsp,%rbp
    d99b:	48 83 ec 10          	sub    $0x10,%rsp
    d99f:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d9a3:	bf d0 00 00 00       	mov    $0xd0,%edi
    d9a8:	e8 93 38 ff ff       	call   1240 <malloc@plt>
    d9ad:	48 89 c2             	mov    %rax,%rdx
    d9b0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d9b4:	48 89 10             	mov    %rdx,(%rax)
    d9b7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d9bb:	48 8b 00             	mov    (%rax),%rax
    d9be:	48 85 c0             	test   %rax,%rax
    d9c1:	75 0a                	jne    d9cd <sha3_384_inc_init+0x3a>
    d9c3:	bf 6f 00 00 00       	mov    $0x6f,%edi
    d9c8:	e8 a3 38 ff ff       	call   1270 <exit@plt>
    d9cd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    d9d1:	48 8b 00             	mov    (%rax),%rax
    d9d4:	48 89 c7             	mov    %rax,%rdi
    d9d7:	e8 73 f0 ff ff       	call   ca4f <keccak_inc_init>
    d9dc:	90                   	nop
    d9dd:	c9                   	leave
    d9de:	c3                   	ret

000000000000d9df <sha3_384_inc_ctx_clone>:
    d9df:	f3 0f 1e fa          	endbr64
    d9e3:	55                   	push   %rbp
    d9e4:	48 89 e5             	mov    %rsp,%rbp
    d9e7:	48 83 ec 10          	sub    $0x10,%rsp
    d9eb:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    d9ef:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    d9f3:	bf d0 00 00 00       	mov    $0xd0,%edi
    d9f8:	e8 43 38 ff ff       	call   1240 <malloc@plt>
    d9fd:	48 89 c2             	mov    %rax,%rdx
    da00:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    da04:	48 89 10             	mov    %rdx,(%rax)
    da07:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    da0b:	48 8b 00             	mov    (%rax),%rax
    da0e:	48 85 c0             	test   %rax,%rax
    da11:	75 0a                	jne    da1d <sha3_384_inc_ctx_clone+0x3e>
    da13:	bf 6f 00 00 00       	mov    $0x6f,%edi
    da18:	e8 53 38 ff ff       	call   1270 <exit@plt>
    da1d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    da21:	48 8b 08             	mov    (%rax),%rcx
    da24:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    da28:	48 8b 00             	mov    (%rax),%rax
    da2b:	ba d0 00 00 00       	mov    $0xd0,%edx
    da30:	48 89 ce             	mov    %rcx,%rsi
    da33:	48 89 c7             	mov    %rax,%rdi
    da36:	e8 f5 37 ff ff       	call   1230 <memcpy@plt>
    da3b:	90                   	nop
    da3c:	c9                   	leave
    da3d:	c3                   	ret

000000000000da3e <sha3_384_inc_absorb>:
    da3e:	f3 0f 1e fa          	endbr64
    da42:	55                   	push   %rbp
    da43:	48 89 e5             	mov    %rsp,%rbp
    da46:	48 83 ec 18          	sub    $0x18,%rsp
    da4a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    da4e:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    da52:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    da56:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    da5a:	48 8b 00             	mov    (%rax),%rax
    da5d:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    da61:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    da65:	be 68 00 00 00       	mov    $0x68,%esi
    da6a:	48 89 c7             	mov    %rax,%rdi
    da6d:	e8 2d f0 ff ff       	call   ca9f <keccak_inc_absorb>
    da72:	90                   	nop
    da73:	c9                   	leave
    da74:	c3                   	ret

000000000000da75 <sha3_384_inc_ctx_release>:
    da75:	f3 0f 1e fa          	endbr64
    da79:	55                   	push   %rbp
    da7a:	48 89 e5             	mov    %rsp,%rbp
    da7d:	48 83 ec 10          	sub    $0x10,%rsp
    da81:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    da85:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    da89:	48 8b 00             	mov    (%rax),%rax
    da8c:	48 89 c7             	mov    %rax,%rdi
    da8f:	e8 dc 36 ff ff       	call   1170 <free@plt>
    da94:	90                   	nop
    da95:	c9                   	leave
    da96:	c3                   	ret

000000000000da97 <sha3_384_inc_finalize>:
    da97:	f3 0f 1e fa          	endbr64
    da9b:	55                   	push   %rbp
    da9c:	48 89 e5             	mov    %rsp,%rbp
    da9f:	48 81 ec 90 00 00 00 	sub    $0x90,%rsp
    daa6:	48 89 bd 78 ff ff ff 	mov    %rdi,-0x88(%rbp)
    daad:	48 89 b5 70 ff ff ff 	mov    %rsi,-0x90(%rbp)
    dab4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    dabb:	00 00 
    dabd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    dac1:	31 c0                	xor    %eax,%eax
    dac3:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    daca:	48 8b 00             	mov    (%rax),%rax
    dacd:	ba 06 00 00 00       	mov    $0x6,%edx
    dad2:	be 68 00 00 00       	mov    $0x68,%esi
    dad7:	48 89 c7             	mov    %rax,%rdi
    dada:	e8 d3 f1 ff ff       	call   ccb2 <keccak_inc_finalize>
    dadf:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    dae6:	48 8b 10             	mov    (%rax),%rdx
    dae9:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    daed:	b9 68 00 00 00       	mov    $0x68,%ecx
    daf2:	be 01 00 00 00       	mov    $0x1,%esi
    daf7:	48 89 c7             	mov    %rax,%rdi
    dafa:	e8 bf ee ff ff       	call   c9be <keccak_squeezeblocks>
    daff:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    db06:	48 89 c7             	mov    %rax,%rdi
    db09:	e8 67 ff ff ff       	call   da75 <sha3_384_inc_ctx_release>
    db0e:	48 c7 45 88 00 00 00 	movq   $0x0,-0x78(%rbp)
    db15:	00 
    db16:	eb 23                	jmp    db3b <sha3_384_inc_finalize+0xa4>
    db18:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    db1f:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    db23:	48 01 c2             	add    %rax,%rdx
    db26:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    db2a:	48 8b 4d 88          	mov    -0x78(%rbp),%rcx
    db2e:	48 01 c8             	add    %rcx,%rax
    db31:	0f b6 00             	movzbl (%rax),%eax
    db34:	88 02                	mov    %al,(%rdx)
    db36:	48 83 45 88 01       	addq   $0x1,-0x78(%rbp)
    db3b:	48 83 7d 88 2f       	cmpq   $0x2f,-0x78(%rbp)
    db40:	76 d6                	jbe    db18 <sha3_384_inc_finalize+0x81>
    db42:	90                   	nop
    db43:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    db47:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    db4e:	00 00 
    db50:	74 05                	je     db57 <sha3_384_inc_finalize+0xc0>
    db52:	e8 79 36 ff ff       	call   11d0 <__stack_chk_fail@plt>
    db57:	c9                   	leave
    db58:	c3                   	ret

000000000000db59 <sha3_384>:
    db59:	f3 0f 1e fa          	endbr64
    db5d:	55                   	push   %rbp
    db5e:	48 89 e5             	mov    %rsp,%rbp
    db61:	48 81 ec 70 01 00 00 	sub    $0x170,%rsp
    db68:	48 89 bd a8 fe ff ff 	mov    %rdi,-0x158(%rbp)
    db6f:	48 89 b5 a0 fe ff ff 	mov    %rsi,-0x160(%rbp)
    db76:	48 89 95 98 fe ff ff 	mov    %rdx,-0x168(%rbp)
    db7d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    db84:	00 00 
    db86:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    db8a:	31 c0                	xor    %eax,%eax
    db8c:	48 8b 8d 98 fe ff ff 	mov    -0x168(%rbp),%rcx
    db93:	48 8b 95 a0 fe ff ff 	mov    -0x160(%rbp),%rdx
    db9a:	48 8d 85 c0 fe ff ff 	lea    -0x140(%rbp),%rax
    dba1:	41 b8 06 00 00 00    	mov    $0x6,%r8d
    dba7:	be 68 00 00 00       	mov    $0x68,%esi
    dbac:	48 89 c7             	mov    %rax,%rdi
    dbaf:	e8 5f eb ff ff       	call   c713 <keccak_absorb>
    dbb4:	48 8d 95 c0 fe ff ff 	lea    -0x140(%rbp),%rdx
    dbbb:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    dbbf:	b9 68 00 00 00       	mov    $0x68,%ecx
    dbc4:	be 01 00 00 00       	mov    $0x1,%esi
    dbc9:	48 89 c7             	mov    %rax,%rdi
    dbcc:	e8 ed ed ff ff       	call   c9be <keccak_squeezeblocks>
    dbd1:	48 c7 85 b8 fe ff ff 	movq   $0x0,-0x148(%rbp)
    dbd8:	00 00 00 00 
    dbdc:	eb 2c                	jmp    dc0a <sha3_384+0xb1>
    dbde:	48 8b 95 a8 fe ff ff 	mov    -0x158(%rbp),%rdx
    dbe5:	48 8b 85 b8 fe ff ff 	mov    -0x148(%rbp),%rax
    dbec:	48 01 c2             	add    %rax,%rdx
    dbef:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    dbf3:	48 8b 8d b8 fe ff ff 	mov    -0x148(%rbp),%rcx
    dbfa:	48 01 c8             	add    %rcx,%rax
    dbfd:	0f b6 00             	movzbl (%rax),%eax
    dc00:	88 02                	mov    %al,(%rdx)
    dc02:	48 83 85 b8 fe ff ff 	addq   $0x1,-0x148(%rbp)
    dc09:	01 
    dc0a:	48 83 bd b8 fe ff ff 	cmpq   $0x2f,-0x148(%rbp)
    dc11:	2f 
    dc12:	76 ca                	jbe    dbde <sha3_384+0x85>
    dc14:	90                   	nop
    dc15:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dc19:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    dc20:	00 00 
    dc22:	74 05                	je     dc29 <sha3_384+0xd0>
    dc24:	e8 a7 35 ff ff       	call   11d0 <__stack_chk_fail@plt>
    dc29:	c9                   	leave
    dc2a:	c3                   	ret

000000000000dc2b <sha3_512_inc_init>:
    dc2b:	f3 0f 1e fa          	endbr64
    dc2f:	55                   	push   %rbp
    dc30:	48 89 e5             	mov    %rsp,%rbp
    dc33:	48 83 ec 10          	sub    $0x10,%rsp
    dc37:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    dc3b:	bf d0 00 00 00       	mov    $0xd0,%edi
    dc40:	e8 fb 35 ff ff       	call   1240 <malloc@plt>
    dc45:	48 89 c2             	mov    %rax,%rdx
    dc48:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dc4c:	48 89 10             	mov    %rdx,(%rax)
    dc4f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dc53:	48 8b 00             	mov    (%rax),%rax
    dc56:	48 85 c0             	test   %rax,%rax
    dc59:	75 0a                	jne    dc65 <sha3_512_inc_init+0x3a>
    dc5b:	bf 6f 00 00 00       	mov    $0x6f,%edi
    dc60:	e8 0b 36 ff ff       	call   1270 <exit@plt>
    dc65:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dc69:	48 8b 00             	mov    (%rax),%rax
    dc6c:	48 89 c7             	mov    %rax,%rdi
    dc6f:	e8 db ed ff ff       	call   ca4f <keccak_inc_init>
    dc74:	90                   	nop
    dc75:	c9                   	leave
    dc76:	c3                   	ret

000000000000dc77 <sha3_512_inc_ctx_clone>:
    dc77:	f3 0f 1e fa          	endbr64
    dc7b:	55                   	push   %rbp
    dc7c:	48 89 e5             	mov    %rsp,%rbp
    dc7f:	48 83 ec 10          	sub    $0x10,%rsp
    dc83:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    dc87:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    dc8b:	bf d0 00 00 00       	mov    $0xd0,%edi
    dc90:	e8 ab 35 ff ff       	call   1240 <malloc@plt>
    dc95:	48 89 c2             	mov    %rax,%rdx
    dc98:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dc9c:	48 89 10             	mov    %rdx,(%rax)
    dc9f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dca3:	48 8b 00             	mov    (%rax),%rax
    dca6:	48 85 c0             	test   %rax,%rax
    dca9:	75 0a                	jne    dcb5 <sha3_512_inc_ctx_clone+0x3e>
    dcab:	bf 6f 00 00 00       	mov    $0x6f,%edi
    dcb0:	e8 bb 35 ff ff       	call   1270 <exit@plt>
    dcb5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    dcb9:	48 8b 08             	mov    (%rax),%rcx
    dcbc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dcc0:	48 8b 00             	mov    (%rax),%rax
    dcc3:	ba d0 00 00 00       	mov    $0xd0,%edx
    dcc8:	48 89 ce             	mov    %rcx,%rsi
    dccb:	48 89 c7             	mov    %rax,%rdi
    dcce:	e8 5d 35 ff ff       	call   1230 <memcpy@plt>
    dcd3:	90                   	nop
    dcd4:	c9                   	leave
    dcd5:	c3                   	ret

000000000000dcd6 <sha3_512_inc_absorb>:
    dcd6:	f3 0f 1e fa          	endbr64
    dcda:	55                   	push   %rbp
    dcdb:	48 89 e5             	mov    %rsp,%rbp
    dcde:	48 83 ec 18          	sub    $0x18,%rsp
    dce2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    dce6:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    dcea:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    dcee:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dcf2:	48 8b 00             	mov    (%rax),%rax
    dcf5:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    dcf9:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    dcfd:	be 48 00 00 00       	mov    $0x48,%esi
    dd02:	48 89 c7             	mov    %rax,%rdi
    dd05:	e8 95 ed ff ff       	call   ca9f <keccak_inc_absorb>
    dd0a:	90                   	nop
    dd0b:	c9                   	leave
    dd0c:	c3                   	ret

000000000000dd0d <sha3_512_inc_ctx_release>:
    dd0d:	f3 0f 1e fa          	endbr64
    dd11:	55                   	push   %rbp
    dd12:	48 89 e5             	mov    %rsp,%rbp
    dd15:	48 83 ec 10          	sub    $0x10,%rsp
    dd19:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    dd1d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dd21:	48 8b 00             	mov    (%rax),%rax
    dd24:	48 89 c7             	mov    %rax,%rdi
    dd27:	e8 44 34 ff ff       	call   1170 <free@plt>
    dd2c:	90                   	nop
    dd2d:	c9                   	leave
    dd2e:	c3                   	ret

000000000000dd2f <sha3_512_inc_finalize>:
    dd2f:	f3 0f 1e fa          	endbr64
    dd33:	55                   	push   %rbp
    dd34:	48 89 e5             	mov    %rsp,%rbp
    dd37:	48 83 ec 70          	sub    $0x70,%rsp
    dd3b:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    dd3f:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    dd43:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    dd4a:	00 00 
    dd4c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    dd50:	31 c0                	xor    %eax,%eax
    dd52:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    dd56:	48 8b 00             	mov    (%rax),%rax
    dd59:	ba 06 00 00 00       	mov    $0x6,%edx
    dd5e:	be 48 00 00 00       	mov    $0x48,%esi
    dd63:	48 89 c7             	mov    %rax,%rdi
    dd66:	e8 47 ef ff ff       	call   ccb2 <keccak_inc_finalize>
    dd6b:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    dd6f:	48 8b 10             	mov    (%rax),%rdx
    dd72:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    dd76:	b9 48 00 00 00       	mov    $0x48,%ecx
    dd7b:	be 01 00 00 00       	mov    $0x1,%esi
    dd80:	48 89 c7             	mov    %rax,%rdi
    dd83:	e8 36 ec ff ff       	call   c9be <keccak_squeezeblocks>
    dd88:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    dd8c:	48 89 c7             	mov    %rax,%rdi
    dd8f:	e8 79 ff ff ff       	call   dd0d <sha3_512_inc_ctx_release>
    dd94:	48 c7 45 a8 00 00 00 	movq   $0x0,-0x58(%rbp)
    dd9b:	00 
    dd9c:	eb 20                	jmp    ddbe <sha3_512_inc_finalize+0x8f>
    dd9e:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    dda2:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    dda6:	48 01 c2             	add    %rax,%rdx
    dda9:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    ddad:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    ddb1:	48 01 c8             	add    %rcx,%rax
    ddb4:	0f b6 00             	movzbl (%rax),%eax
    ddb7:	88 02                	mov    %al,(%rdx)
    ddb9:	48 83 45 a8 01       	addq   $0x1,-0x58(%rbp)
    ddbe:	48 83 7d a8 3f       	cmpq   $0x3f,-0x58(%rbp)
    ddc3:	76 d9                	jbe    dd9e <sha3_512_inc_finalize+0x6f>
    ddc5:	90                   	nop
    ddc6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ddca:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    ddd1:	00 00 
    ddd3:	74 05                	je     ddda <sha3_512_inc_finalize+0xab>
    ddd5:	e8 f6 33 ff ff       	call   11d0 <__stack_chk_fail@plt>
    ddda:	c9                   	leave
    dddb:	c3                   	ret

000000000000dddc <sha3_512>:
    dddc:	f3 0f 1e fa          	endbr64
    dde0:	55                   	push   %rbp
    dde1:	48 89 e5             	mov    %rsp,%rbp
    dde4:	48 81 ec 50 01 00 00 	sub    $0x150,%rsp
    ddeb:	48 89 bd c8 fe ff ff 	mov    %rdi,-0x138(%rbp)
    ddf2:	48 89 b5 c0 fe ff ff 	mov    %rsi,-0x140(%rbp)
    ddf9:	48 89 95 b8 fe ff ff 	mov    %rdx,-0x148(%rbp)
    de00:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    de07:	00 00 
    de09:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    de0d:	31 c0                	xor    %eax,%eax
    de0f:	48 8b 8d b8 fe ff ff 	mov    -0x148(%rbp),%rcx
    de16:	48 8b 95 c0 fe ff ff 	mov    -0x140(%rbp),%rdx
    de1d:	48 8d 85 e0 fe ff ff 	lea    -0x120(%rbp),%rax
    de24:	41 b8 06 00 00 00    	mov    $0x6,%r8d
    de2a:	be 48 00 00 00       	mov    $0x48,%esi
    de2f:	48 89 c7             	mov    %rax,%rdi
    de32:	e8 dc e8 ff ff       	call   c713 <keccak_absorb>
    de37:	48 8d 95 e0 fe ff ff 	lea    -0x120(%rbp),%rdx
    de3e:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    de42:	b9 48 00 00 00       	mov    $0x48,%ecx
    de47:	be 01 00 00 00       	mov    $0x1,%esi
    de4c:	48 89 c7             	mov    %rax,%rdi
    de4f:	e8 6a eb ff ff       	call   c9be <keccak_squeezeblocks>
    de54:	48 c7 85 d8 fe ff ff 	movq   $0x0,-0x128(%rbp)
    de5b:	00 00 00 00 
    de5f:	eb 2c                	jmp    de8d <sha3_512+0xb1>
    de61:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    de68:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    de6f:	48 01 c2             	add    %rax,%rdx
    de72:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    de76:	48 8b 8d d8 fe ff ff 	mov    -0x128(%rbp),%rcx
    de7d:	48 01 c8             	add    %rcx,%rax
    de80:	0f b6 00             	movzbl (%rax),%eax
    de83:	88 02                	mov    %al,(%rdx)
    de85:	48 83 85 d8 fe ff ff 	addq   $0x1,-0x128(%rbp)
    de8c:	01 
    de8d:	48 83 bd d8 fe ff ff 	cmpq   $0x3f,-0x128(%rbp)
    de94:	3f 
    de95:	76 ca                	jbe    de61 <sha3_512+0x85>
    de97:	90                   	nop
    de98:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    de9c:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    dea3:	00 00 
    dea5:	74 05                	je     deac <sha3_512+0xd0>
    dea7:	e8 24 33 ff ff       	call   11d0 <__stack_chk_fail@plt>
    deac:	c9                   	leave
    dead:	c3                   	ret

000000000000deae <mayo_secure_free>:
    deae:	f3 0f 1e fa          	endbr64
    deb2:	55                   	push   %rbp
    deb3:	48 89 e5             	mov    %rsp,%rbp
    deb6:	48 83 ec 10          	sub    $0x10,%rsp
    deba:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    debe:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    dec2:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    dec7:	74 25                	je     deee <mayo_secure_free+0x40>
    dec9:	48 8b 0d 40 41 00 00 	mov    0x4140(%rip),%rcx        # 12010 <memset@GLIBC_2.2.5>
    ded0:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    ded4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ded8:	be 00 00 00 00       	mov    $0x0,%esi
    dedd:	48 89 c7             	mov    %rax,%rdi
    dee0:	ff d1                	call   *%rcx
    dee2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    dee6:	48 89 c7             	mov    %rax,%rdi
    dee9:	e8 82 32 ff ff       	call   1170 <free@plt>
    deee:	90                   	nop
    deef:	c9                   	leave
    def0:	c3                   	ret

000000000000def1 <mayo_secure_clear>:
    def1:	f3 0f 1e fa          	endbr64
    def5:	55                   	push   %rbp
    def6:	48 89 e5             	mov    %rsp,%rbp
    def9:	48 83 ec 10          	sub    $0x10,%rsp
    defd:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    df01:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    df05:	48 8b 0d 0c 41 00 00 	mov    0x410c(%rip),%rcx        # 12018 <memset@GLIBC_2.2.5>
    df0c:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    df10:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    df14:	be 00 00 00 00       	mov    $0x0,%esi
    df19:	48 89 c7             	mov    %rax,%rdi
    df1c:	ff d1                	call   *%rcx
    df1e:	90                   	nop
    df1f:	c9                   	leave
    df20:	c3                   	ret
    df21:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    df28:	00 00 00 
    df2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000df30 <__libc_csu_init>:
    df30:	f3 0f 1e fa          	endbr64
    df34:	41 57                	push   %r15
    df36:	4c 8d 3d f3 3b 00 00 	lea    0x3bf3(%rip),%r15        # 11b30 <__frame_dummy_init_array_entry>
    df3d:	41 56                	push   %r14
    df3f:	49 89 d6             	mov    %rdx,%r14
    df42:	41 55                	push   %r13
    df44:	49 89 f5             	mov    %rsi,%r13
    df47:	41 54                	push   %r12
    df49:	41 89 fc             	mov    %edi,%r12d
    df4c:	55                   	push   %rbp
    df4d:	48 8d 2d e4 3b 00 00 	lea    0x3be4(%rip),%rbp        # 11b38 <__do_global_dtors_aux_fini_array_entry>
    df54:	53                   	push   %rbx
    df55:	4c 29 fd             	sub    %r15,%rbp
    df58:	48 83 ec 08          	sub    $0x8,%rsp
    df5c:	e8 9f 30 ff ff       	call   1000 <_init>
    df61:	48 c1 fd 03          	sar    $0x3,%rbp
    df65:	74 1f                	je     df86 <__libc_csu_init+0x56>
    df67:	31 db                	xor    %ebx,%ebx
    df69:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    df70:	4c 89 f2             	mov    %r14,%rdx
    df73:	4c 89 ee             	mov    %r13,%rsi
    df76:	44 89 e7             	mov    %r12d,%edi
    df79:	41 ff 14 df          	call   *(%r15,%rbx,8)
    df7d:	48 83 c3 01          	add    $0x1,%rbx
    df81:	48 39 dd             	cmp    %rbx,%rbp
    df84:	75 ea                	jne    df70 <__libc_csu_init+0x40>
    df86:	48 83 c4 08          	add    $0x8,%rsp
    df8a:	5b                   	pop    %rbx
    df8b:	5d                   	pop    %rbp
    df8c:	41 5c                	pop    %r12
    df8e:	41 5d                	pop    %r13
    df90:	41 5e                	pop    %r14
    df92:	41 5f                	pop    %r15
    df94:	c3                   	ret
    df95:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    df9c:	00 00 00 00 

000000000000dfa0 <__libc_csu_fini>:
    dfa0:	f3 0f 1e fa          	endbr64
    dfa4:	c3                   	ret

Disassembly of section .fini:

000000000000dfa8 <_fini>:
    dfa8:	f3 0f 1e fa          	endbr64
    dfac:	48 83 ec 08          	sub    $0x8,%rsp
    dfb0:	48 83 c4 08          	add    $0x8,%rsp
    dfb4:	c3                   	ret
