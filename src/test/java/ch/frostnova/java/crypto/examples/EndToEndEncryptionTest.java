package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.ByteSequence;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

/**
 * End-2-End encryption using AES and key agreement using ECDSA
 *
 * @author pwalser
 * @since 11.04.2018
 */
public class EndToEndEncryptionTest {

    @Test
    public void testEndToEndEncryption() throws Exception {

        Party p1 = new Party();
        Party p2 = new Party();

        byte[] secret1 = p1.generateSecret(p2.getPublicKey());
        byte[] secret2 = p2.generateSecret(p1.getPublicKey());

        SecretKey secretKey1 = new SecretKeySpec(secret1, 0, secret1.length, "AES");
        SecretKey secretKey2 = new SecretKeySpec(secret2, 0, secret2.length, "AES");

        String message = "Nobody expects the Spanish Inquisition!";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        // Party 1 sends message to Party 2
        byte[] encrypted = CryptoUtil.encrypt(secretKey1, data);

        // Party 2 decrypts message from Party 1
        byte[] decrypted = CryptoUtil.decrypt(secretKey2, encrypted);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("Message Data: " + ByteSequence.toString(data));
        System.out.println("Encrypted Data: " + ByteSequence.toString(encrypted));
        System.out.println("Decrypted Data: " + ByteSequence.toString(decrypted));
        System.out.println("Decrypted Message: " + decryptedMessage);

        Assert.assertArrayEquals(data, decrypted);
        Assert.assertEquals(message, decryptedMessage);
    }

    public static class Party {

        private final KeyPair keyPair;

        public Party() throws GeneralSecurityException {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            keyPair = keyGen.generateKeyPair();
        }

        public PublicKey getPublicKey() {
            return keyPair.getPublic();
        }

        public byte[] generateSecret(PublicKey otherPublicKey) throws GeneralSecurityException {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(otherPublicKey, true);
            return keyAgreement.generateSecret();
        }
    }
}
