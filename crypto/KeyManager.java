package crypto;

import java.security.*;

public class KeyManager {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public void generateKeyPair() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    public PublicKey getPublicKey(){
        return publicKey;
    }
}