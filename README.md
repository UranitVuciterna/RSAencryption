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