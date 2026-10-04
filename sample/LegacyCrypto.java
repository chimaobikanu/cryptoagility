import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;

public class LegacyCrypto {

    public void generateKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();                       // quantum-vulnerable

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.generateKeyPair();                     // quantum-vulnerable
    }

    public byte[] weakDigest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");   // broken
        return md.digest(data);
    }

    public byte[] legacyDigest(byte[] data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1"); // broken
        return sha1.digest(data);
    }

    public byte[] sign(byte[] data, java.security.PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");  // broken signature suite
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    public Cipher modernCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");        // adequate
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");  // broken
    }
}
