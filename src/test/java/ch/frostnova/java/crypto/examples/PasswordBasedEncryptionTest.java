package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.ByteSequence;
import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Tests for symmetric cryptography with passwords (PBE)
 *
 * @author pwalser
 * @since 10.04.2018
 */
public class PasswordBasedEncryptionTest {

    @Test
    public void testEncryptText() throws Exception {

        String password = "$3crEt-0O7";
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        String message = "Nobody expects the Spanish Inquisition!";

        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        int iterations = 10000;
        byte[] encrypted = CryptoUtil.encrypt(password, salt, iterations, data);
        byte[] decrypted = CryptoUtil.decrypt(password, salt, iterations, encrypted);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("Password: " + password);
        System.out.println("Salt: " + ByteSequence.toString(salt));
        System.out.println("Message Data: " + ByteSequence.toString(data));
        System.out.println("Encrypted Data: " + ByteSequence.toString(encrypted));
        System.out.println("Decrypted Data: " + ByteSequence.toString(decrypted));
        System.out.println("Decrypted Message: " + decryptedMessage);
        Assert.assertArrayEquals(data, decrypted);
    }

    @Test
    public void testEncryptRandomData() throws Exception {

        String password = "$3crEt-0O7";
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] data = RandomUtil.randomData(1, 10000);

        int iterations = 10000;
        byte[] encrypted = CryptoUtil.encrypt(password, salt, iterations, data);
        byte[] decrypted = CryptoUtil.decrypt(password, salt, iterations, encrypted);
        Assert.assertArrayEquals(data, decrypted);
    }
}
