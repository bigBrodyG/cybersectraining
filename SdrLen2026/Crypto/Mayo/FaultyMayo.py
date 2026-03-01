"""
Faulty Mayo
17 17 454
crypto
guaddu

MAYO is completely secure, so even with a small fault it won't matter...

source code for MAYO is taken straight from here, I only changed some compilation flags

This is a remote challenge, you can connect to the service with: nc mayo.challs.srdnlen.it 1340
Attachments
@chall.py, @server.py
"""
"""
solve this crypto challenge /home/giordi/Repos/cybersectraining/SdrLen2026/Crypto/FaultyMayo.py

Thought for 1s


Analyzed

FaultyMayo.py#L1-15

Thought for 1s


Analyzed
SdrLen2026/Crypto

Thought for <1s


Analyzed

server.py#L1-79

Thought for 12s








Analyzing Faulty Mayo Challenge
Cloned the MAYO-C repository. Now looking for the mayo_sign_signature function to analyze its internals.

Files Edited
Task
Progress Updates
1
Setting up workspace and planning the attack

2
Examining the symbols in the target memory range (0x5a84 - 0x687a) to identify the vulnerable MAYO function

3
Identifying the function covering 0x5a84-0x687a to understand where the fault occurs

4
Searching for the MAYO signature scheme source code to understand the implementation and where the fault could be useful

5
Cloning the PQCMayo/MAYO-C repository to analyze the implementation of mayo_sign_signature

6
Identifying the mayo_sign_signature function in the MAYO-C source code and analyzing its operations

Analyzing chall binary assembly and writing exploit
Read MAYO-C source and determined we need to recover the secret matrix sk.O. Faulting the mat_add step or the assignment of vi could leak sk.O * x in the signature.

Progress Updates
1
Locating the mat_add call or its associated operations in the objdump output to see if it can be faulted



Model
Gemini 3.1 Pro (High)

Task
13 hrs ago

Faulty Mayo Challenge
Objective
Exploit the chall binary by injecting a fault during execution to leak the MAYO private key, then sign a server-provided message to get the flag.

Checklist
 Analyze the server script and the fault mechanism.
 Reverse-engineer or inspect the 

chall
 binary to find what is stored between 0x5a84 and 0x687a.
Understand the MAYO signature scheme and where a fault attack would apply.
 Find the exact offset to fault.
 Develop an exploit script to collect faulted signatures.
 Recover the private key.
 Sign the target message.
 Get the flag!
"""