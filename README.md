# RSAencryption

Platformë Mesazhimi e Enkriptuar me RSA në Modelin Klient-Server


Ky projekt realizon një aplikacion të thjeshtë në Java për komunikim të sigurt midis një serveri dhe klienti,
duke përdorur algoritmin RSA për enkriptim dhe dekriptim të mesazheve. Aplikacioni funksionon në konsolë dhe siguron 
që çdo mesazh i dërguar është i mbrojtur nga leximi i palëve të treta.


1. Lidhjet me klientët
2. Serveri dërgon: SERVER_PUBKEY
3. Klienti dërgon: CLIENT_PUBKEY
4. Serveri dërgon: ASSIGNED_NAME
    - Klienti dërgon: ENCRYPTED_MESSAGE
    - Proceson dhe përgjigjet serveri

### Përshkrimi i Komponentëve të Projektit
Projekti përbëhet nga klasat e mëposhtme:

1. RSAEncryption.java
   Klasa kryesore që realizon: 
    - Gjenerimin e çelësave RSA
    - Enkriptimin e një mesazhi me çelës publik
    - Dekriptimin me çelës privat
    - Shfaqjen e rezultateve për testim lokal

2. RSAKeyUtil.java
   Përgjegjëse për:
    - Gjenerimin e çelësave publik dhe privat
    - Ruajtjen dhe rikuperimin e tyre si objekte

3. KeyConverter.java
    - Konverton çelësat RSA në dhe nga formati String (Base64)
    - Mundëson dërgimin e çelësave përmes rrjetit në mënyrë të lexueshme

4. Server.java
   Klasa e cila:
    - Inicializon çiftin e çelësave RSA të serverit (ngarkon nga fajlli ose gjeneron të ri)
    - Pranon lidhje nga klientët në portin 1234 dhe i trajton në thread të veçantë (për 10 klientë paralelisht)
    - Shkëmben çelësa publikë me klientin dhe verifikon fingerprint-in për siguri#
    - Merr mesazhe të enkriptuara nga klienti, i dekripton me çelësin privat dhe i shfaq në konzolë
    - Menaxhon pastrimin e klientëve të shkëputur dhe mbylljen e lidhjeve në mënyrë të sigurt

6. Client.java
   Klasa e cila:
    - Gjeneron çiftin e çelësave RSA dhe krijon lidhjen me serverin në portin 1234
    - Shkëmben dhe verifikon çelësat publikë me serverin përmes fingerprint-it të besuar
    - Merr dhe dekripton mesazhet e serverit në thread të veçantë
    - Lexon mesazhet nga përdoruesi, i enkripton dhe i dërgon tek serveri
