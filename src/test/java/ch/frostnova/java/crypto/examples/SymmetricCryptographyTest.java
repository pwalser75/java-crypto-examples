package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Tests for symmetric cryptography
 *
 * @author pwalser
 * @since 10.04.2018
 */
public class SymmetricCryptographyTest {

    @Test
    public void testEncryptText() throws Exception {

        String message = "Nobody expects the Spanish Inquisition!";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        SecretKey secretKey = randomKey();
        byte[] encrypted = encrypt(secretKey, data);
        byte[] decrypted = decrypt(secretKey, encrypted);
        Assert.assertArrayEquals(data, decrypted);
    }

    @Test
    public void testEncryptRandomData() throws Exception {

        byte[] data = RandomUtil.randomData(1, 1000000);
        SecretKey secretKey = randomKey();
        byte[] encrypted = encrypt(secretKey, data);
        byte[] decrypted = decrypt(secretKey, encrypted);
        Assert.assertArrayEquals(data, decrypted);
    }

    private static SecretKey randomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    private static byte[] encrypt(SecretKey secretKey, byte[] message) throws Exception {

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(message);

        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + encrypted.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return byteBuffer.array();
    }

    private static byte[] decrypt(SecretKey secretKey, byte[] encrypted) throws Exception {

        ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
        int ivLength = byteBuffer.getInt();
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }
}
