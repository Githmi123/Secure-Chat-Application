package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class PersistentKeyPair {

    private static String KEYSTORE_PATH = null;
    private final String username;


    public PersistentKeyPair(String username){
        KEYSTORE_PATH = "keys/" + username + "keystore.jks";
        this.username = username;

    }

    public KeyPair loadOrCreate(char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        File ksFile = new File(KEYSTORE_PATH);

        Path keys = Paths.get("keys");
        if(Files.exists(keys) && Files.isDirectory(keys)) { // directory exists
            if(ksFile.exists()){
                try (FileInputStream fis = new FileInputStream(ksFile)) {
                    keyStore.load(fis, password);
                }

                Key key = keyStore.getKey(username, password);
                if (key instanceof PrivateKey) {
                    Certificate cert = keyStore.getCertificate(username);
                    PublicKey pubKey = cert.getPublicKey();
                    return new KeyPair(pubKey, (PrivateKey) key);
                }
            }
        }
        else {
            Files.createDirectory(keys);
        }

        KeyManager keyManager = new KeyManager();
        keyManager.generateKeyPair();
        KeyPair keyPair = new KeyPair(keyManager.getPublicKey(), keyManager.getPrivateKey());
        String dn = "CN=" + username + ", OU=IT, O=MyCompany, L=City, ST=State, C=CountryCode";
        Certificate[] chain = { SelfSignedCertificateGenerator.generate(dn, keyPair) };

        // Create new keystore and store keys
        keyStore.load(null, password); // initialize new keystore
        keyStore.setKeyEntry(username, keyPair.getPrivate(), password, chain);

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keyStore.store(fos, password);
        }

        return keyPair;
        
    }

}
