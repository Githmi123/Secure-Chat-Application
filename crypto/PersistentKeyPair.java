package crypto;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class PersistentKeyPair {

    private static String PUB_PATH = null;
    private static String PRIV_PATH = null;

    public PersistentKeyPair(String username){
        this.PUB_PATH = "keys/" + username + "_pub.key";
        this.PRIV_PATH = "keys/" + username + "_priv.key";
    }

    public KeyPair loadOrCreate() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File pubFile = new File(PUB_PATH);
        File privFile = new File(PRIV_PATH);

        KeyManager keyManager = new KeyManager();

        if(Files.exists(Paths.get("keys")) && Files.isDirectory(Paths.get("keys"))){ // directory exists
            if(pubFile.exists() && privFile.exists()){ // files exists
                PublicKey pub = KeyExchangeManager.createPublicKey(Files.readString(pubFile.toPath()));
                PrivateKey priv = KeyExchangeManager.createPrivateKey(Files.readString(privFile.toPath()));
                return new KeyPair(pub, priv);
            }
        }
        else {
            Files.createDirectory(Paths.get("keys"));
        }

        keyManager.generateKeyPair();
        writeBase64(pubFile, keyManager.getPublicKey().getEncoded());
        writeBase64(privFile, keyManager.getPrivateKey().getEncoded());

        return new KeyPair(keyManager.getPublicKey(), keyManager.getPrivateKey());
        
    }

    private static void writeBase64(File file, byte[] encoded) throws IOException {
        Files.write(file.toPath(),
                Base64.getEncoder().encode(encoded),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
    }
}
