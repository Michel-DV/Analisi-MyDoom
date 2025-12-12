# 🦠 Analisi Forense: MyDoom (Win32.Mydoom)

> **Status:** Analisi Completata  
> **Classificazione:** Traffic Light Protocol TLP:WHITE  
> **Oggetto:** Analisi Forense Approfondita, Impatto Storico e Persistenza Operativa della Famiglia di Malware MyDoom

## 📄 Introduzione
Questo repository contiene un'analisi tecnica dettagliata (**[Scarica il Report PDF Completo](./Analisi%20Tecnica%20del%20Malware%20MyDoom.pdf)**) su **Win32.Mydoom**, storicamente noto come il worm a più rapida diffusione via email della storia.

Nonostante sia emerso nel gennaio 2004, MyDoom rappresenta ancora oggi un caso di studio fondamentale per comprendere l'evoluzione dal malware "vandalico" alle moderne botnet a scopo di lucro.

## 🔍 Punti Chiave dell'Analisi

Il report allegato copre i seguenti aspetti tecnici:

### 1. Vettori di Infezione Multipli
MyDoom ha introdotto una strategia ibrida devastante:
* **Motore SMTP Autonomo:** Bypassava i client di posta locali inviando email direttamente ai server MX dei destinatari.
* **Propagazione P2P (Kazaa):** Si copiava nelle cartelle condivise con nomi ingannevoli (es. `winamp5`, `activation_crack`) sfruttando la popolarità del file sharing dell'epoca.

### 2. Architettura e Offuscamento
* **Packing:** Utilizzo di UPX per comprimere l'eseguibile[cite: 241].
* **Offuscamento Stringhe:** Implementazione dell'algoritmo **ROT13** per nascondere domini target e chiavi di registro agli analisti.
* **Persistenza:** Creazione della chiave di registro `TaskMon` o `Traybar` e utilizzo della DLL `shimgapi.dll` (camuffata da libreria di sistema) per mantenere l'accesso.

### 3. La Backdoor (Porta 3127)
L'analisi del codice rivela un loop che apre un listener sulla porta **TCP 3127** (fino alla 3198). Questa backdoor trasformava i computer infetti in proxy SOCKS, permettendo agli spammer di instradare traffico anonimo attraverso macchine innocenti.

### 4. Il Messaggio Nascosto
Nel codice è stata isolata la celebre stringa lasciata dall'autore:
> *"Andy; I'm just doing my job, nothing personal, sorry"*.

## 📊 Impatto e Statistiche
* **Danni Stimati:** ~38,5 Miliardi di dollari.
* **Saturazione:** Al picco, ha generato 1 email infetta su 5 a livello globale.
* **Stato Attuale (2025):** MyDoom rappresenta ancora circa l'**1,1%** di tutti gli allegati email malevoli intercettati, persistendo su sistemi legacy.

## 🛡️ Indicatori di Compromissione (IOC)

| Tipo | Valore | Descrizione |
| :--- | :--- | :--- |
| **Hash (SHA-256)** | `fff0ccf5feaf5d46b295f770ad398b6d572909b00e2b8bcd1b1c286c70cd9151` | Campione MyDoom |
| **Network** | Porta TCP **3127** (Listening) | Attività Backdoor tipica |
| **Filesystem** | `%SysDir%\shimgapi.dll` | Libreria Backdoor mascherata |
| **Registry** | `HKLM\...\Run\TaskMon` | Chiave di persistenza |

---

## ⚠️ Disclaimer
*Questa analisi è stata condotta a scopo puramente educativo e di ricerca sulla sicurezza informatica. L'autore non è responsabile per l'uso improprio delle informazioni contenute in questo repository.*

