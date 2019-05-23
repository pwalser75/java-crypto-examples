package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.ByteSequence;
import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Tests for symmetric cryptography
 *
 * @author pwalser
 * @since 10.04.2018
 */
public class EncryptionTest {

    @Test
    public void testEncryptText() throws Exception {

        String message = "Nobody expects the Spanish Inquisition!";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        byte[] encrypted = CryptoUtil.encrypt(secretKey, data);
        byte[] decrypted = CryptoUtil.decrypt(secretKey, encrypted);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("Message Data: " + ByteSequence.toString(data));
        System.out.println("Encrypted Data: " + ByteSequence.toString(encrypted));
        System.out.println("Decrypted Data: " + ByteSequence.toString(decrypted));
        System.out.println("Decrypted Message: " + decryptedMessage);

        Assert.assertArrayEquals(data, decrypted);
        Assert.assertEquals(message, decryptedMessage);
    }

    @Test
    public void testEncryptRandomData() throws Exception {

        byte[] data = RandomUtil.randomData(1, 10000);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        byte[] encrypted = CryptoUtil.encrypt(secretKey, data);
        byte[] decrypted = CryptoUtil.decrypt(secretKey, encrypted);

        Assert.assertArrayEquals(data, decrypted);
    }
}
