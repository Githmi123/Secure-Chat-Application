package crypto;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyExchangeManager {
    public static byte[] encryptAESKey(SecretKey aesKey, PublicKey receiverPublicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    public static SecretKey decryptAESKey(byte[] encryptedKey, PrivateKey receiverPrivateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] decodedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
