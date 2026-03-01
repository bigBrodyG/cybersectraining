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
