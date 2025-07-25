# Secure-Chat-Application

A Java-based command-line chat system that ensures authentication, message confidentiality, and message integrity between two users. The application uses cryptographic techniques to prevent unauthorized access, tampering, and replay attacks.

## Features
- User Authentication with public/private key pairs

- End-to-End Encrypted Communication using AES

- Mutual Authentication using digital signatures

- Replay Attack Prevention using message counters

- Logging of authentication events

- Forward Secrecy: Past messages remain safe even if credentials are later compromised


<!-- telnet 127.0.0.1 5000 -->
<!-- del *.class
javac -cp ".;lib/bcprov-jdk18on-1.81.jar" *.java
java -cp ".;lib/bcprov-jdk18on-1.81.jar" server  -->
