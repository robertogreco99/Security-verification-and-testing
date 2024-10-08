# Riprodurre gli esperimenti sul protocollo di handshake
## Parte 1 : file handshake1cie.pv
### Il file
Faccio girare proverif sul file `handshake1cie.pv`,che include la descrizione del protocollo e 3 query. L'assunzione è che l'attaccante conosca solo il canale pubblico c e le chiavi pubbliche
```bash
 (*
   Sample handshake protocol (typed version)
 *)
# tipo chiave per rappresentare una chiave crittografica (
type pkey.	(* public key *) # tipo per la chiave pubblica
type skey.	(* private key *) #tipo per la chiave privata
type keymat.	(* key material *) 
type result.	(* result of check signature *) #dove salvo il risultato del check della firma

free c:channel.			(* the public channel *) #canale di comunicazione pubblico
free s:bitstring [private]. 	(* the secret *) #il segreto

(* Public-key Encryption *) #crittografia a chiave pubblica
fun penc(bitstring, pkey): bitstring. # prende in ingresso il messaggio di tipo bistring e restituisce un messaggio crittograftato con la chiave pubblica pkey
fun pk(keymat): pkey. # genera una chiave pubblica a partire dal keymat
fun sk(keymat): skey. #genera una chiave privata a partire dal keymat
reduc forall x:bitstring, y:keymat; pdec(penc(x,pk(y)),sk(y)) = x.
# per ogni messaggio x di tipo bistring e per ogni materiale della chiave y di tipo keymat se si cifra x con la chiave publicata generata da y (pk(y)) e poi di decifra con la chiave privata generata da y (sk(y) si ottiene il messaggio originale

# in breve : chiave pubblicata usata per cifrare e privata per decriptare


(* Signatures *)
fun ok():result. #funzione restituisce ok come risultato della verifica
fun sign(bitstring, skey): bitstring. # prende in ingresso un messaggio e una chiave privata skey e resituisce una firma di tipo bistring
reduc forall m:bitstring, y:keymat; getmess(sign(m,sk(y))) = m.
# dato un messaggio firmato con la chiave privata (sk(y)) la funzione getmess restituisce il risultato originale
reduc forall m:bitstring, y:keymat; checksign(sign(m,sk(y)), pk(y)) = ok().
# la firma sign(m,sk(y)) può essere verificata usando la chiave pubblica pk(y) corrispondente. Se la firma è valida, la funzione checksign restituisce il messaggio ok

# in breve : chiave privata firma il messaggio, chiave pubblica verifica autenticità della firma. Solo chi possiede chiave privata può firmare il messaggio. Solo chi ha chiave pubblica può verificare validità della firma

(* Shared-key cryptography *)
fun senc(bitstring, bitstring): bitstring.
#prende un messaggio di tipo bistring e ???
reduc forall x: bitstring, y: bitstring; sdec(senc(x,y),y) = x.
#???

(* Test whether s is secret *)
query attacker(s).

(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).

(* Test authentication *)
event bA(pkey,pkey,bitstring).
event eB(pkey,pkey,bitstring).
query x:pkey,y:pkey,z:bitstring; inj-event(eB(x,y,z)) ==> inj-event(bA(x,y,z)).

(* The process *)

let pA(kpA: keymat, pkB: pkey) =
         new k:bitstring; # genera una chiave
	 event bA(pk(kpA),pkB,k); # parte evento ba
         out(c, penc(sign(k, sk(kpA)), pkB)); 
         # 1.firma la chiave  casuale con la propria chiave privata kpa 
         # 2.cifra con la chiave pubblica di b
         # 3.manda a b sul canale c
 	 in(c,x:bitstring); #9. riceve la rispsota di b
         let xs=sdec(x, k) in #10. decripta il messaggio x ricevuto con la chiave k
         event endA(); 0.  #11. termina

let pB(kpB: keymat, pkA: pkey) =
         in(c, y:bitstring);  # 4.riceve il messaggio di
         let y1=pdec(y, sk(kpB)) in # 5.decifra il messaggio ricevuto y con la propria chiave privata sk
         if checksign(y1, pkA)=ok() then #6.verifica se la firma di a è valida con la chiave pubblica di a
         let xk=getmess(y1) in #7.se è valida estrae la chiave casuale k (xk)
	 event eB(pkA,pk(kpB),xk); #evento pb
         out(c, senc(s, xk)); # 8.cifra il segreto  con la chiave xk e lo manda su c 
	 event endB(); 0.  # finisce evento

process 
         new kpA:keymat; new kpB:keymat;
         (!out(c, pk(kpA)); 0 | !out(c, pk(kpB)); 0 |
          !pA(kpA, pk(kpB))  | !pB(kpB, pk(kpA))
         )
#1. new kpA:keymat; new kpB:keymat;:
#Questa parte del codice genera due nuove chiavi private, kpA e kpB, rispettivamente per i partecipanti pA e pB.
#keymat è il tipo della chiave privata (potrebbe essere definito in precedenza nel modello). Queste chiavi verranno utilizzate per derivare le chiavi pubbliche corrispondenti.

#2. out(c, pk(kpA)); e out(c, pk(kpB));:
# out(c, pk(kpA)): Questo comando manda sul canale pubblico c la chiave pubblica derivata da kpA (pk(kpA)).
# llo stesso modo, out(c, pk(kpB)) manda sul canale c la chiave pubblica derivata da kpB (pk(kpB)).
# Queste chiavi pubbliche sono condivise tramite il canale pubblico, rendendole disponibili a qualsiasi partecipante, incluso un eventuale attaccante.

#3. ! (bang operator):
# Il simbolo ! (bang) davanti a un processo indica che esso può essere eseguito in maniera parallela e ripetuta (quindi indefinitamente).
# In questo caso, significa che l'invio delle chiavi pubbliche (pk(kpA) e pk(kpB)) uò essere ripetuto, e che i processi pA e pB possono essere eseguiti più volte.

#4. !out(c, pk(kpA)); 0 | !out(c, pk(kpB)); 0:
# Queste due righe indicano che:
# out(c, pk(kpA)); 0: La chiave pubblica di pA (pk(kpA)) viene inviata sul canale c e il processo si ferma dopo (0 indica il termine del processo).
#out(c, pk(kpB)); 0: Lo stesso avviene per la chiave pubblica di pB (pk(kpB)).
#Questi processi sono separati da |, che in ProVerif denota l'esecuzione in parallelo, quindi le chiavi pubbliche di entrambi i partecipanti vengono inviate simultaneamente.

#5. !pA(kpA, pk(kpB)):
# Questo è un processo che rappresenta pA (il partecipante A) che usa la propria chiave privata kpA e la chiave pubblica di pB (pk(kpB)).
#  Il processo pA può fare qualsiasi operazione definita successivamente con queste chiavi, come cifrare messaggi, firmarli o avviare una comunicazione sicura con pB.

#6. !pB(kpB, pk(kpA)):
#   Allo stesso modo, questo processo rappresenta pB (il partecipante B), che usa la propria chiave privata kpB e la chiave pubblica di pA (pk(kpA)).
#  Il processo pB può anche eseguire operazioni crittografiche o avviare comunicazioni con pA, utilizzando le chiavi fornite.


(* EXPECTPV
Query not attacker(s[]) is true. # mi attendo che l'attaccante non riesca a ottenere il segreto
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_1,z)) ==> inj-event(bA(x_1,y_1,z)) is false.
END *)
```
### Query 
1. Secrecy di s
```bash
(* Test whether s is secret *)
query attacker(s).
## risultato atteso  :  
Query not attacker(s[]) is true. # mi attendo che l'attaccante non riesca a ottenere il segreto
```
2. Raggiungibilità della fine di ogni processo : si verifica che ogni processo possa raggiungere la fine
```bash
(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).
## risultato atteso --> raggiungono la fine
Query not event(endA) is false. 
Query not event(endB) is false.
```

3. Autenticazione da A a B :  se un processo B con chiave pubblica y riceve correttamente la chiave z, apparentemente proveniente da un processo A con chiave pubblica x, allora un processo A con chiave pubblica x ha realmente inviato la chiave z allo stesso processo e ogni operazione di ricezione corrisponde a un'operazione di invio distinta (iniettività).

```bash
(* Test authentication *)
event bA(pkey,pkey,bitstring).
event eB(pkey,pkey,bitstring).
query x:pkey,y:pkey,z:bitstring; inj-event(eB(x,y,z)) ==> inj-event(bA(x,y,z)).
##risultato atteso 
Query inj-event(eB(x_1,y_1,z)) ==> inj-event(bA(x_1,y_1,z)) is false.
#Questa query esprime una correspondence property tra due eventi, ovvero che se l'evento eB con parametri (x_1, y_1, z) avviene, allora dovrebbe avvenire anche l'evento bA con gli stessi parametri.
#L'uso di inj-event significa che si richiede che ogni occorrenza di eB corrisponda a un'unica occorrenza di bA, in una relazione di iniettività.
#Il risultato "false" implica che questa corrispondenza non è verificata correttamente: potrebbe accadere che eB avvenga senza che bA avvenga, oppure che ci sia una violazione dell'iniettività (ad esempio, più occorrenze di eB senza corrispondenti occorrenze di bA).
```
## Parte 2 : esecuzione dello script
Faccio girare `proverif handshake1cie.pv` e ottengo questo report : 
- Query "not attacker(s[])": Il risultato è true, il che significa che il messaggio segreto s[] non è vulnerabile agli attacchi e l'attaccante non può ottenere il valore di s[].
- Query "not event(endA)": Il risultato è false, indicando che l'evento endA è raggiungibile. In particolare, l'attaccante può ottenere il messaggio senc(s[], k_1) inviato in {24}, decodificarlo e quindi permettere l'esecuzione dell'evento endA.
- Query "not event(endB)": Anche questa query restituisce false, il che significa che l'evento endB è anch'esso raggiungibile. L'attaccante può ottenere il messaggio crittografato e completare la parte del protocollo legata a endB.
- Query "inj-event(eB(x_1,y_1,z)) ==> inj-event(bA(x_1,y_1,z))": Il risultato mostra che l'evento eB è condizionatamente associato all'evento bA, indicando che il protocollo non garantisce l'iniettività completa. Ovvero, esistono situazioni in cui un evento eB può avvenire senza che ci sia stato l'evento corrispondente bA, causando possibili ambiguità nella corrispondenza degli eventi.
Le proprietà 1 e 2 sono soddisfatte, la 3 no
## Parte 3 : esecuzione dello script in modalità grafica
Faccio girare `proverif -graph . handshake1cie.pv`. Viene prodotta una rappresentazione grafica della attack trace trovata da proverif. Qual è il comportamento dell'attaccante nella traccia?

![alt text](<Schermata del 2024-10-07 16-45-03.png>)

Come si può vedere nella traccia d'attacco ricostruita da ProVerif (traceHandshake1cie3.pdf), l'attaccante rimanda il primo messaggio inviato da pA a un'altra istanza di pB.

Nel diagramma della traccia d'attacco  vediamo un'interazione tra processi onesti e l'attaccante. La traccia mostra vari passaggi che si verificano quando un attaccante cerca di riprodurre un messaggio inviato da un processo all'altro. La sezione di interesse è il comportamento evidenziato in questo modo:

1. **Processo pA** (Processo Onesto) invia un messaggio firmato da pk(kpA) al processo pB.
2. **Processo pB** riceve questo messaggio come parte della normale esecuzione.
3. L'**attaccante** interviene replicando un messaggio simile, sfruttando le informazioni già inviate da pA a un'altra istanza di pB. Questo comportamento è indicato da frecce che rappresentano il flusso del messaggio (puoi vedere l'attaccante che inietta il messaggio "event eB" nel punto in cui dovrebbe trovarsi una risposta legittima).
   
   La ripetizione del messaggio è chiaramente visibile nel fatto che l'attaccante utilizza lo stesso messaggio inviato prima da pA, ma lo ripete più avanti nella traccia.

In sintesi, il comportamento evidenziato è che l'attaccante sta sfruttando un replay del messaggio "event eB(pk(kpA), pk(kpB), k)" per ingannare il sistema, simulando una comunicazione valida. Puoi identificare questo comportamento dalle frecce parallele che attraversano i processi pA e pB, collegate al messaggio "event eB" generato due volte.
## Parte 4 : correggere lo script
Se desideriamo l'iniettività, dobbiamo correggere il protocollo. Un modo per farlo è aggiungere una fase preliminare, in cui pB invia per primo un valore generato casualmente (un nonce, che funge da ID di sessione) a pA per richiedere la chiave, e pA risponde a questa richiesta inviando lo stesso nonce insieme alla chiave. In questo modo, l'attaccante non dovrebbe essere in grado di ripetere il messaggio con la chiave in una sessione diversa. Scrivi uno script Proverif che descriva la versione corretta del protocollo (puoi partire dalla versione in handshake1cie.pv e modificarla). Nota che gli eventi della corrispondenza devono essere cambiati di conseguenza, includendo anche il nonce, altrimenti non è possibile distinguere gli eventi appartenenti a sessioni diverse.  
Dopo aver descritto la versione corretta, verifica che essa soddisfi la versione iniettiva della proprietà di autenticazione (e che tutti i processi arrivino alla fine). In caso di problemi, puoi usare il simulatore per capire il motivo.  
Riportiamo  lo script Proverif `handshake1cie_fixed.pv`con la versione corretta del protocollo:

```bash
  (*
   Sample handshake protocol (typed version)
 *)

type pkey.	(* public key *)
type skey.	(* private key *)
type keymat.	(* key material *)
type result.	(* result of check signature *)

free c:channel.			(* the public channel *)
free s:bitstring [private]. 	(* the secret *)

(* Public-key Encryption *)
fun penc(bitstring, pkey): bitstring.
fun pk(keymat): pkey.
fun sk(keymat): skey.
reduc forall x:bitstring, y:keymat; pdec(penc(x,pk(y)),sk(y)) = x.

(* Signatures *)
fun ok():result.
fun sign(bitstring, skey): bitstring.
reduc forall m:bitstring, y:keymat; getmess(sign(m,sk(y))) = m.
reduc forall m:bitstring, y:keymat; checksign(sign(m,sk(y)), pk(y)) = ok().

(* Shared-key cryptography *)
fun senc(bitstring, bitstring): bitstring.
reduc forall x: bitstring, y: bitstring; sdec(senc(x,y),y) = x.


(* Test whether s is secret *)
query attacker(s).

(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).

(* Test authentication *)
#Nota che gli eventi della corrispondenza devono essere cambiati di conseguenza, includendo anche il nonce, altrimenti non è possibile distinguere gli eventi appartenenti a sessioni diverse.  
event bA(pkey,pkey,bitstring,bitstring).
event eB(pkey,pkey,bitstring,bitstring).
query x:pkey,y:pkey,z:bitstring,w:bitstring; inj-event(eB(x,y,z,w)) ==> inj-event(bA(x,y,z,w)).

(* The process *)

let pA(kpA: keymat, pkB: pkey) =
	 in(c, yn: bitstring); #ricevo il nonce
         new k:bitstring;
    #e pA risponde a questa richiesta inviando lo stesso nonce insieme alla chiave
	 event bA(pk(kpA),pkB,k,yn); #aggiungo il nonce
         out(c, penc(sign((yn,k), sk(kpA)), pkB));
         # 1.firma la chiave  asuale e il nonce con la propria chiave privata kpa 
         # 2.cifra con la chiave pubblica di b
         # 3.manda a b sul canale c
 	 in(c,x:bitstring);
         let xs=sdec(x, k) in 
         event endA(); 0. 

let pB(kpB: keymat, pkA: pkey) =
	 new n: bitstring; #creo il nonce
   #pB invia per primo un valore generato casualmente (un nonce, che funge da ID di sessione) a pA per richiedere la chiave
	 out(c, n); #lo mando sul canale
         in(c, y:bitstring); # 4.riceve il messaggio 
         let y1=pdec(y, sk(kpB)) in # 5.decifra il messaggio ricevuto y con la propria chiave privata sk
         if checksign(y1, pkA)=ok() then #6.verifica se la firma di a è valida con la chiave pubblica di a
         let (=n,xk: bitstring)=getmess(y1) in #7.se è valida estrae n e  la chiave casuale k (xk)
	 event eB(pkA,pk(kpB),xk,n);
         out(c, senc(s, xk));  # 8.cifra il segreto con la chiave xk e lo manda su c 
	 event endB(); 0. 

process 
         new kpA:keymat; new kpB:keymat;
         (!out(c, pk(kpA)); 0 | !out(c, pk(kpB)); 0 |
          !pA(kpA, pk(kpB))  | !pB(kpB, pk(kpA))
         )


(* EXPECTPV
Query not attacker(s[]) is true.
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_1,z,w)) ==> inj-event(bA(x_1,y_1,z,w)) is true.
END *)

```
Il report ora mi da :
```bash
Verification summary:
Query not attacker(s[]) is true.
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_1,z,w)) ==> inj-event(bA(x_1,y_1,z,w)) is true.
```
E' verificata quindi anche la terza proprietà
## Parte 5 verifica dell'autenticità e integrità del segreto**

Ora che il protocollo è stato corretto, possiamo tentare di verificare che il segreto inviato da pB a pA sia autentico e che ne venga mantenuta l'integrità, cioè, ogni volta che pA riceve il segreto, effettivamente il segreto è stato inviato da pB, e che la corrispondenza sia iniettiva, cioè ogni ricezione del segreto è preceduta da un invio distinto del segreto. Si noti che, per esprimere questa proprietà, dobbiamo introdurre altri eventi nella descrizione del protocollo.
Verifichiamo con lo script `handshake2cie.pv`
```bash
 (*
   Sample handshake protocol (typed version)
 *)

type pkey.	(* public key *)
type skey.	(* private key *)
type keymat.	(* key material *)
type result.	(* result of check signature *)

free c:channel.			(* the public channel *)
free s:bitstring [private]. 	(* the secret *)

(* Public-key Encryption *)
fun penc(bitstring, pkey): bitstring.
fun pk(keymat): pkey.
fun sk(keymat): skey.
reduc forall x:bitstring, y:keymat; pdec(penc(x,pk(y)),sk(y)) = x.

(* Signatures *)
fun ok():result.
fun sign(bitstring, skey): bitstring.
reduc forall m:bitstring, y:keymat; getmess(sign(m,sk(y))) = m.
reduc forall m:bitstring, y:keymat; checksign(sign(m,sk(y)), pk(y)) = ok().

(* Shared-key cryptography *)
fun senc(bitstring, bitstring): bitstring.
reduc forall x: bitstring, y: bitstring; sdec(senc(x,y),y) = x.


(* Test whether s is secret *)
query attacker(s).

(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).

(* Test authentication *)
event bA(pkey,pkey,bitstring,bitstring).
event eB(pkey,pkey,bitstring,bitstring).
#aggiungiamo due nuovi eventi : ricezione e invio del messaggio 
event srecv(pkey,pkey,bitstring).
event ssend(pkey,pkey,bitstring).

query x:pkey,y:pkey,z:bitstring,w:bitstring; inj-event(eB(x,y,z,w)) ==> inj-event(bA(x,y,z,w)).
#aggiungiamo una query
query x:pkey,y:pkey,z:bitstring; inj-event(srecv(x,y,z)) ==> inj-event(ssend(x,y,z)).

(* The process *)

let pA(kpA: keymat, pkB: pkey) =
	 in(c, yn: bitstring); # 1. Riceve un nonce (yn) dal canale c
         new k:bitstring; # 2. Genera una nuova chiave casuale k
	 event bA(pk(kpA),pkB,k,yn);  # 3. Registra l'evento bAs
         out(c, penc(sign((yn,k), sk(kpA)), pkB)); # 4. Cifra e invia un messaggio
 	 in(c,x:bitstring);  # 5. Riceve un messaggio dal canale c
         let xs=sdec(x, k) in   # 6. Decripta il messaggio ricevuto
	 event srecv(pk(kpA),pkB,xs); # 7. Registra l'evento di ricezione
   #ssend(pkey, pkey, bitstring): Rappresenta un evento che indica l'invio di un messaggio. Viene tracciato l'invio di un segreto (di tipo bitstring) da un partecipante con una chiave pubblica pkey a un altro partecipante con una chiave pubblica pkey.
   #Il primo parametro (pkey) rappresenta la chiave pubblica del mittente.
   #Il secondo parametro (pkey) rappresenta la chiave pubblica del destinatario.
   #Il terzo parametro (bitstring) rappresenta il messaggio inviato (ad esempio, un segreto).
         event endA(); 0. # 8. Termina il processo

let pB(kpB: keymat, pkA: pkey) = 
	 new n: bitstring;  # 1. Genera un nuovo nonce
	 out(c, n); # 2. Invia il nonce a pA
         in(c, y:bitstring);  # 3. Riceve un messaggio da pA
         let y1=pdec(y, sk(kpB)) in # 4. Decifra il messaggio ricevuto usando la chiave privata
         if checksign(y1, pkA)=ok() then # 5. Verifica la firma del messaggio
         let (=n,xk: bitstring)=getmess(y1) in # 6. Estrae il nonce e la chiave casuale dal messaggio
	 event eB(pkA,pk(kpB),xk,n); # 7. Registra l'evento di invio
	 event ssend(pkA,pk(kpB),s);   # 8. Registra l'evento di ricezione del segreto
   #srecv(pkey, pkey, bitstring): Rappresenta l'evento corrispondente che indica la ricezione del messaggio. Traccia quando un partecipante riceve un messaggio con gli stessi parametri:
   #Il primo parametro rappresenta la chiave pubblica del destinatario.
   #Il secondo parametro rappresenta la chiave pubblica del mittente.
   # Il terzo parametro rappresenta il messaggio (segreto) ricevuto.
         out(c, senc(s, xk));    # 9. Invia il segreto cifrato
	 event endB(); 0.   # 9. Invia il segreto cifrato

process 
         new kpA:keymat; new kpB:keymat;
         (!out(c, pk(kpA)); 0 | !out(c, pk(kpB)); 0 |
          !pA(kpA, pk(kpB))  | !pB(kpB, pk(kpA))
         )


(* EXPECTPV
Query not attacker(s[]) is true.
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_1,z,w)) ==> inj-event(bA(x_1,y_1,z,w)) is true.
Query inj-event(srecv(x_1,y_1,z)) ==> inj-event(ssend(x_1,y_1,z)) is true.
#Questa è una query che verifica una proprietà di sicurezza del protocollo. In particolare, vuole assicurarsi che ogni ricezione di un messaggio (srecv) corrisponda a un invio unico del messaggio (ssend). 
#Analizziamo la query:
#x:pkey, y:pkey, z:bitstring: Dichiarazione di variabili per la query. x e y rappresentano chiavi pubbliche, mentre z rappresenta un messaggio (un segreto) di tipo bitstring.

#inj-event(srecv(x, y, z)) ==> inj-event(ssend(x, y, z)):
#inj-event(srecv(x, y, z)): Questo indica che c'è un evento di ricezione (srecv) per il segreto z, inviato da y (chiave pubblica del mittente) e ricevuto da x (chiave pubblica del destinatario).
#==>: Questo operatore logico significa "implica." Quindi, stiamo dicendo che l'evento di ricezione deve implicare un evento di invio.
#inj-event(ssend(x, y, z)): Indica che ci deve essere un evento di invio (ssend) corrispondente, dove il segreto z è stato inviato da y a x.
#L'uso del prefisso inj- davanti a event specifica che la corrispondenza è iniettiva, cioè ogni ricezione di un messaggio deve essere preceduta da un invio distinto. In altre parole:
#Non possono esserci ripetizioni o "replay" dello stesso messaggio. Se pA riceve un messaggio, ci deve essere un unico invio corrispondente da parte di pB, e questo invio non può essere riutilizzato o ripetuto in un'altra sessione.
END *)
```

Cosa stiamo verificando con questa nuova  query?

Questa query serve per verificare due proprietà fondamentali:

  - Autenticità: Ogni volta che un messaggio viene ricevuto (srecv), possiamo essere sicuri che esso sia stato effettivamente inviato (ssend) dal mittente legittimo, garantendo che il messaggio provenga dalla fonte corretta.
  - Iniettività: Ogni ricezione del messaggio deve corrispondere a un invio unico e distinto, evitando che un attaccante possa intercettare e ripetere lo stesso messaggio in un'altra sessione (attacco di ripetizione).

Esempio pratico:

Supponiamo che pB (con chiave pubblica pkB) invii un segreto z a pA (con chiave pubblica pkA):

   - L'evento di invio sarà ssend(pkA, pkB, z), che traccia che pB ha inviato il segreto z a pA.
   -  Quando pA riceve questo segreto, verrà tracciato l'evento srecv(pkA, pkB, z).

La query iniettiva verifica che ogni volta che pA riceve il segreto z tramite srecv, ci sia un evento ssend corrispondente, e che non vi siano eventi duplicati o riutilizzati

Risultato lanciando proverif : 
```bash
Verification summary:
Query not attacker(s[]) is true.
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_1,z,w)) ==> inj-event(bA(x_1,y_1,z,w)) is true.
Query inj-event(srecv(x_1,y_1,z)) ==> inj-event(ssend(x_1,y_1,z)) is true.
```
Il risultato è che la proprietà è soddisfatta e non deve essere modificato il protocollo.
## 6 Verifica dell'integrità del segreto quando segreti diversi possono essere inviati
Proviamo a verificare che il segreto non possa essere modificato durante il transito, anche quando non è sempre lo stesso. Per verificare questa proprietà, possiamo modificare la descrizione dei processi, in modo che non ci sia più un unico segreto, ma due segreti diversi, s1 e s2. Possiamo quindi avere alcune sessioni di pB che inviano s1 e altre che inviano s2. Infine, verifichiamo che ciò che viene ricevuto corrisponda (iniettivamente) a ciò che è stato inviato.
Verifichiamo con lo script `handshakecie3.pv`
```bash
 (*
   Sample handshake protocol (typed version)
 *)

type pkey.	(* public key *)
type skey.	(* private key *)
type keymat.	(* key material *)
type result.	(* result of check signature *)

free c:channel.			(* the public channel *)
free s1:bitstring [private]. 	(* one secret *)  # ora ho due segreti
free s2:bitstring [private]. 	(* another secret *) #segreto 2

(* Public-key Encryption *)
fun penc(bitstring, pkey): bitstring.
fun pk(keymat): pkey.
fun sk(keymat): skey.
reduc forall x:bitstring, y:keymat; pdec(penc(x,pk(y)),sk(y)) = x.

(* Signatures *)
fun ok():result.
fun sign(bitstring, skey): bitstring.
reduc forall m:bitstring, y:keymat; getmess(sign(m,sk(y))) = m.
reduc forall m:bitstring, y:keymat; checksign(sign(m,sk(y)), pk(y)) = ok().

(* Shared-key cryptography *)
fun senc(bitstring, bitstring): bitstring.
reduc forall x: bitstring, y: bitstring; sdec(senc(x,y),y) = x.


(* Test whether s1 and s2 are secret *)
#ora testo se entrambi sono segreti e non attaccabili
query attacker(s1).
query attacker(s2).

(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).

(* Test authentication *)
event bA(pkey,pkey,bitstring,bitstring).
event eB(pkey,pkey,bitstring,bitstring).
event srecv(pkey,pkey,bitstring).
event ssend(pkey,pkey,bitstring).

query x:pkey,y:pkey,z:bitstring,w:bitstring; inj-event(eB(x,y,z,w)) ==> inj-event(bA(x,y,z,w)).
query x:pkey,y:pkey,z:bitstring; inj-event(srecv(x,y,z)) ==> inj-event(ssend(x,y,z)).

(* The process *)

let pA(kpA: keymat, pkB: pkey) =
	 in(c, yn: bitstring);
         new k:bitstring;
	 event bA(pk(kpA),pkB,k,yn);
         out(c, penc(sign((yn,k), sk(kpA)), pkB));
 	 in(c,x:bitstring);
         let xs=sdec(x, k) in 
	 event srecv(pk(kpA),pkB,xs);
         event endA(); 0. 

let pB(kpB: keymat, pkA: pkey, s: bitstring) = #parametro in piu per il segreto
#segreti diversi per sessioni distinte
	 new n: bitstring;
	 out(c, n);
         in(c, y:bitstring); 
         let y1=pdec(y, sk(kpB)) in
         if checksign(y1, pkA)=ok() then
         let (=n,xk: bitstring)=getmess(y1) in
	 event eB(pkA,pk(kpB),xk,n);
	 event ssend(pkA,pk(kpB),s);
         out(c, senc(s, xk)); 
	 event endB(); 0. 

process 
         new kpA:keymat; new kpB:keymat; #dichiaro le nuove chiavi
         (!out(c, pk(kpA)); 0 | !out(c, pk(kpB)); 0 | #invio le chiavi pubbliche
          !pA(kpA, pk(kpB)) #resta uguale
          | !pB(kpB, pk(kpA), s1) | !pB(kpB, pk(kpA), s2)
          #!pB(kpB, pk(kpA), s1): Qui viene avviato il processo di pB, passando come argomenti kpB, la chiave pubblica di pA e il primo segreto s1. Questo rappresenta una sessione in cui pB invia il segreto s1.
          #!pB(kpB, pk(kpA), s2): In modo simile, viene avviato un secondo processo di pB, che invia il secondo segreto s2. Ciò significa che pB ha sessioni distinte che possono inviare segreti diversi.
          #Si noti che pB ha la possibilità di inviare due segreti distinti (s1 e #s2) in sessioni separate, il che è utile per verificare l'integrità e #l'autenticità della comunicazione anche quando i segreti possono variare
         )


(* EXPECTPV
Query not attacker(s1[]) is true.
Query not attacker(s2[]) is true.
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_2,z,w)) ==> inj-event(bA(x_1,y_2,z,w)) is true.
Query inj-event(srecv(x_1,y_2,z)) ==> inj-event(ssend(x_1,y_2,z)) is true.
END *)
```

Risultato lanciando proverif : 
```bash
Verification summary:
Query not attacker(s1[]) is true.
Query not attacker(s2[]) is true.
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_2,z,w)) ==> inj-event(bA(x_1,y_2,z,w)) is true.
Query inj-event(srecv(x_1,y_2,z)) ==> inj-event(ssend(x_1,y_2,z)) is true.
```
Il risultato è che la proprietà è soddisfatta e non deve essere modificato il protocollo.
# Verifica e correzione del protocollo di hash di esempio
## Parte 1 : analisi dello script
In questa parte del laboratorio, facciamo alcuni esperimenti con il protocollo di hash di esempio che è stato discusso nelle lezioni (l'hash di un segreto ss viene trasferito da un mittente a un destinatario).
Per prima cosa, al fine di riprodurre gli stessi risultati mostrati nelle lezioni, eseguiamo Proverif sul file `hash.pv`, che include la descrizione del protocollo (il processo mittente è chiamato `pS` e il ricevitore `pR`) e le sue proprietà di segretezza:

1. segretezza di \( s \)
2. raggiungibilità della fine di ciascun processo (questi non sono interrogativi di sicurezza, ma controlli di sanità per verificare che ogni processo possa davvero raggiungere la fine).
3. resistenza a tentativi di indovinare \( s \) offline.

Lo script `hash.pv`: 
```bash
(* 
   Example of weak secret 
   Questo è un esempio che dimostra un segreto debole.
*)

free c:channel.			(* the public channel *)
(* Definisce un canale pubblico "c" che può essere utilizzato per la comunicazione tra i processi. *)

free s:bitstring [private]. 	(* the secret *)
(* Definisce una variabile "s" di tipo bitstring, contrassegnata come privata, che rappresenta un segreto. *)

(* Cryptographic Hash *)
fun hash(bitstring): bitstring.
(* Definisce una funzione "hash" che prende in input una bitstring e restituisce una bitstring. Questa funzione rappresenta una funzione di hash crittografica. *)

(* Test whether s is secret *)
query attacker(s).
(* Questa query verifica se "s" è accessibile all'attaccante, cioè se l'attaccante può conoscere il segreto. *)

(* Test whether s is subject to offline guessing attacks *)
weaksecret s.
(* Questa riga esegue un test per determinare se "s" è un segreto debole, che significa che potrebbe essere vulnerabile ad attacchi di indovinamento offline. *)

(* Test reachability *)
event endS().
event endR().
(* Definisce due eventi, "endS" e "endR", che possono essere utilizzati per monitorare la conclusione dei processi. *)

query event(endS()).
query event(endR()).
(* Queste query controllano se gli eventi "endS" e "endR" sono stati raggiunti durante l'esecuzione del protocollo. *)

(* The process *)

let pS() =
         out(c, hash(s));
         event endS(); 0. 
(* Definisce il processo "pS" che invia l'hash del segreto "s" sul canale pubblico "c", quindi segnala l'evento "endS" prima di terminare con il valore 0. *)

let pR() =
         in(c, y:bitstring); 
	 event endR(); 0. 
(* Definisce il processo "pR" che riceve una bitstring "y" dal canale pubblico "c", quindi segnala l'evento "endR" prima di terminare con il valore 0. *)

process 
         (
          !pS()  | !pR()
         )
(* Avvia i processi "pS" e "pR" in parallelo, usando l'operatore di parallelismo. L'operatore "!" indica che i processi possono essere eseguiti ripetutamente. *)

(* EXPECTPV
Query not attacker(s[]) is true.
Weak secret s is false.
Query not event(endS) is false.
Query not event(endR) is false.
END *)
(* Questo blocco di commento rappresenta l'aspettativa dei risultati delle query eseguite:
   - "not attacker(s[])" è vero: significa che l'attaccante non ha accesso al segreto "s".
   - "Weak secret s" è falso: indica che "s" non è considerato un segreto debole.
   - "not event(endS)" è falso: significa che l'evento "endS" è stato raggiunto.
   - "not event(endR)" è falso: significa che l'evento "endR" è stato raggiunto.
   La sezione termina con "END". *)

```
Risultati lanciando proverif : 
```bash
Verification summary:
Query not attacker(s[]) is true.
Weak secret s is false.
# "Weak secret s is false": Questo significa che la proprietà di segreto debole non #è soddisfatta. In altre parole, ss non è considerato un segreto sicuro, poiché #esistono attacchi offline che consentirebbero all'attaccante di indovinarlo.

Query not event(endS) is false.
Query not event(endR) is false.
```

Dallo report di verifica di ProVerif, puoi vedere che le proprietà 1 e 2 sono soddisfatte (nota che la raggiungibilità è soddisfatta se le query restituiscono false), mentre la 3 non lo è. Questo significa che, se si assume che ss sia un segreto con bassa entropia (cioè, uno con pochi valori possibili diversi), potrebbe essere ottenuto dall'attaccante tramite un attacco di indovinamento offline.


## Parte due: esecuzione in modalità grafica 
Esegui nuovamente ProVerif con l'opzione −graph−graph, che produce una vista grafica della traccia dell'attacco trovata da ProVerif e guarda la traccia. Qual è il comportamento dell'attaccante nella traccia dell'attacco?
![alt text](<Schermata del 2024-10-08 11-08-28.png>)

Come si può vedere dalla traccia dell'attacco ricostruita da ProVerif (traceHash1.pdf), l'attaccante registra il messaggio \( hash(s) \) e poi esegue un confronto offline tra \( hash(s) \) e \( hash(g) \), dove \( g \) è il guess . Se sono uguali, il guess è corretto.

## Parte 3 : fixare il protocollo : Una possibile soluzione è fare l'hash del segreto abbinato al segreto ad alta entropia.

Se assumiamo che i due processi pSpS (mittente) e pRpR (ricevente) condividano un altro segreto ad alta entropia (ad esempio, un lungo numero scelto casualmente), esiste una semplice correzione per questo protocollo, affinché resista agli attacchi di indovinamento offline su ss. Puoi trovarla e verificare che la soluzione sia corretta?
Lo script `hash_fixed.pv`: 
```bash
(*
   Example of weak secret fixed
 *)

free c:channel.			(* Definisce il canale pubblico per la comunicazione *)
free s:bitstring [private]. 	(* Dichiara il segreto s come bitstring privata *)
free shes:bitstring [private]. 	(* Dichiara un segreto condiviso ad alta entropia shes come bitstring privata *)

(* Funzione di hash crittografico *)
fun hash(bitstring): bitstring.

(* Test se s è un segreto *)
query attacker(s).

(* Test se s è soggetto ad attacchi di indovinamento offline *)
weaksecret s.

(* Test di raggiungibilità *)
event endS().  (* Evento per indicare la fine del processo di invio *)
event endR().  (* Evento per indicare la fine del processo di ricezione *)
query event(endS()).  (* Interroga se l'evento endS è raggiungibile *)
query event(endR()).  (* Interroga se l'evento endR è raggiungibile *)

(* Definizione del processo *)

let pS() =  (* Definisce il processo del mittente *)
	out(c, hash((s,shes)));  (* Invia il valore hash della tupla (s, shes) attraverso il canale c *)
    event endS();  (* Esegui l'evento endS per indicare la fine dell'invio *)
    0.  (* Termina il processo *)

let pR() =  (* Definisce il processo del ricevente *)
    in(c, y:bitstring);  (* Ricevi un bitstring y dal canale c *)
	event endR();  (* Esegui l'evento endR per indicare la fine della ricezione *)
    0.  (* Termina il processo *)

process 
         (
          !pS()  | !pR()  (* Esegui i processi pS e pR in parallelo *)
         )

(* Aspettative sui risultati della verifica *)
(* EXPECTPV
Query not attacker(s[]) is true.  (* L'attaccante non ha accesso a s *)
Weak secret s is true.  (* s è considerato un segreto debole *)
Query not event(endS) is false.  (* L'evento endS è stato raggiunto *)
Query not event(endR) is false.  (* L'evento endR è stato raggiunto *)
END *
```


Principali cambiamenti e loro significato

  - Introduzione di shes:
        Originale: Solo il segreto s è presente.
        Corretto: È stato introdotto un secondo segreto shes ad alta entropia, che viene utilizzato per rafforzare la sicurezza.

  - Hashing combinato:
        Originale: Il mittente invia solo l'hash di s (out(c, hash(s));).
        Corretto: Il mittente invia l'hash della combinazione di s e shes (out(c, hash((s,shes)));). Questo rende più difficile per un attaccante indovinare s, poiché ora deve anche conoscere shes.

  - Risultati delle query di aspettativa:
        Originale: "Weak secret s is false." indica che s non è considerato un segreto debole, ma ciò è probabilmente dovuto alla mancanza di un attacco di indovinamento esplicito.
        Corretto: "Weak secret s is true." indica che, sebbene s sia stato reso meno vulnerabile, continua a essere considerato un segreto debole, ma in modo diverso, suggerendo che l'implementazione ha mitigato i rischi associati.

Conclusione

La modifica principale consiste nell'includere un segreto ad alta entropia e nel combinare i segreti nell'hash, che rende più difficile per un attaccante eseguire attacchi di indovinamento offline. Questo approccio migliora notevolmente la sicurezza del protocollo. 

Risultato lanciando proverif : 
```bash
Verification summary:
Query not attacker(s[]) is true.
Weak secret s is true.
Query not event(endS) is false.
Query not event(endR) is false.
```
# Definire e verificare un protocollo di firma semplice per aggiornamenti software.