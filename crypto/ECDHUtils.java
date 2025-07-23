package crypto;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class ECDHUtils {
    public static KeyPair generate() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey derive(PrivateKey privateKey, PublicKey peerPublicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] rawSharedScretKey = keyAgreement.generateSecret();

        byte[] aesKeyBytes = MessageDigest.getInstance("SHA-256").digest(rawSharedScretKey);
        return new SecretKeySpec(aesKeyBytes, 0, 16, "AES");
    }
}
