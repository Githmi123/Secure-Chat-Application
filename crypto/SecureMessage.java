package crypto;

public class SecureMessage {
    public String encryptedPayload;
    public byte[] signature;
    public String sender;
    public String nonce;
    public long timestamp;

    public SecureMessage(String encryptedPayload, byte[] signature, String sender, String nonce, long timestamp){
        this.encryptedPayload = encryptedPayload;
        this.signature = signature;
        this.sender = sender;
        this.nonce = nonce;
        this.timestamp = timestamp;
    }
}
