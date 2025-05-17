#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import *
import re

# Legge il file di output
with open("output.txt", "r") as f:
    lines = f.readlines()

# Variabili per salvare i parametri
alice_n = None
bob_n = None
binary_search_responses = []  # Le cifrature inviate da sendToBob durante la ricerca

# Funzione di supporto per cercare un intero in una stringa (in base 10 o 16)
def parse_int(s):
    s = s.strip()
    try:
        return int(s)
    except:
        # Se inizia con "0x" prova in esadecimale
        if s.startswith("0x"):
            return int(s, 16)
        else:
            raise

# --- Parsing dei parametri pubblici ---
# Il file di output contiene linee tipo:
# "hi, i'm Alice, my public parameters are:"
# "n=<alice_n>"
# "e=65537"
# e poi:
# "hi Alice! i'm Bob, my public parameters are:"
# "n=<bob_n>"
# "e=65537"

for i, line in enumerate(lines):
    if "i'm Alice, my public parameters are:" in line:
        # Cerca la riga con n=
        m = re.search(r"n\s*=\s*([0-9]+)", lines[i+1])
        if m:
            alice_n = int(m.group(1))
    if "i'm Bob, my public parameters are:" in line:
        m = re.search(r"n\s*=\s*([0-9]+)", lines[i+1])
        if m:
            bob_n = int(m.group(1))

if alice_n is None or bob_n is None:
    print("Impossibile estrarre i parametri RSA pubblici dal file di output.")
    exit(1)

print("[+] Parametri estratti:")
print("    Alice n =", alice_n)
print("    Bob   n =", bob_n)

# --- Raccogliamo le risposte della ricerca binaria ---
# Il gioco inizia con la riga:
# sendToBob("let's play a game, you have to guess my favourite number")
# Dopo di che, durante il loop, per ogni iterazione vengono stampate:
#   - Una riga "bob: <ct>" (la domanda: "Is your number greater than {mid}?") inviata con sendToAlice
#   - Una riga "alice: <ct>" (la risposta, che è o "Yes!, my number is greater than {mid}" oppure "No!, my number is lower or equal to {mid}") inviata con sendToBob
#
# Noi ci interessa, per ricostruire la ricerca binaria, la serie di cifrature generate da sendToBob (cioè le righe che iniziano con "alice:"),
# escluse eventuali messaggi fuori dal loop (tipo il messaggio iniziale della partita e il "yes it is!" finale).
#
# Notate che il loop effettua circa 501 iterazioni (range [0, 2**501] con precisione 1).
# Possiamo individuare le risposte cercando le righe "alice:" che contengono un intero (la cifra RSA).
#
# Per semplicità, raccogliamo tutte le righe che iniziano con "alice:" e poi scartiamo la prima (che corrisponde al messaggio iniziale) e l'ultima (il "yes it is!").
alice_lines = [line for line in lines if line.startswith("alice:")]
if not alice_lines:
    print("Nessuna linea 'alice:' trovata.")
    exit(1)

# La prima riga "alice:" è il messaggio "let's play a game, ..." criptato, e l'ultima probabilmente è il messaggio finale.
# Il loop binario ha quindi le risposte intermedie.
binary_search_responses = alice_lines[1:-1]

print(f"[+] Trovate {len(binary_search_responses)} risposte nel loop binario.")

# --- Simulazione della ricerca binaria ---
# Inizialmente:
lowerbound = 0
upperbound = 2**501
e = 65537

# Per ogni risposta, ricostruiamo il valore di mid usato e simula entrambe le possibili cifrature
# Per ogni iterazione:
#   mid = (lowerbound + upperbound) // 2
#   Se la risposta è "Yes!, my number is greater than {mid}", allora alice_favourite_number > mid e lowerbound = mid.
#   Altrimenti, se è "No!, my number is lower or equal to {mid}", allora upperbound = mid.
#
# Siccome la cifratura RSA è deterministica, possiamo calcolare:
#   ct_yes = pow(bytes_to_long(f"Yes!, my number is greater than {mid}".encode()), e, bob_n)
#   ct_no  = pow(bytes_to_long(f"No!, my number is lower or equal to {mid}".encode()), e, bob_n)
#
# E confrontare con la risposta corrente (convertita in intero).
# Se corrisponde a ct_yes, allora prendiamo il ramo yes, altrimenti il ramo no.

rounds = len(binary_search_responses)
print("[*] Inizio simulazione della ricerca binaria...")
for i in range(rounds):
    mid = (lowerbound + upperbound) // 2
    # Costruiamo le due possibili risposte in chiaro
    msg_yes = f"Yes!, my number is greater than {mid}"
    msg_no  = f"No!, my number is lower or equal to {mid}"
    # Convertiamo in numero
    pt_yes = bytes_to_long(msg_yes.encode())
    pt_no  = bytes_to_long(msg_no.encode())
    # Calcoliamo la cifratura (RSA senza padding, esponente e=65537)
    ct_yes = pow(pt_yes, e, bob_n)
    ct_no  = pow(pt_no, e, bob_n)
    
    # Prendiamo la risposta dalla riga (rimuovendo il prefisso "alice:" e eventuali spazi)
    ct_line = binary_search_responses[i].split("alice:")[-1].strip()
    ct_given = int(ct_line)
    
    # Confronta con i due possibili
    if ct_given == ct_yes:
        lowerbound = mid
    elif ct_given == ct_no:
        upperbound = mid
    else:
        print(f"[!] Iterazione {i}: risposta non riconosciuta!")
        print(f"    mid = {mid}")
        print(f"    ct_yes = {ct_yes}")
        print(f"    ct_no  = {ct_no}")
        print(f"    ct_given = {ct_given}")
        exit(1)

# Al termine del loop, dovrebbe valere: upperbound - lowerbound == 1 e upperbound == alice_favourite_number.
if upperbound - lowerbound != 1:
    print("La ricerca binaria non ha convergito come previsto.")
    exit(1)

alice_fav_number = upperbound
print("[+] Ricostruito alice_favourite_number =", alice_fav_number)

# Convertiamo il numero in bytes e decodifichiamo la flag
flag = long_to_bytes(alice_fav_number).decode()
print("\n🏴 Flag trovata:", flag)