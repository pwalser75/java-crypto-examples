package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Tests for symmetric cryptography
 *
 * @author wap
 * @since 10.04.2018
 */
public class SymmetricCryptograhyWithPasswordTest {

    @Test
    public void testEncryptText() throws Exception {

        String password = "$3crEt-0O7";
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        String message = "Nobody expects the Spanish Inquisition!";

        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = encrypt(password, salt, data);
        byte[] decrypted = decrypt(password, salt, encrypted);
        Assert.assertArrayEquals(data, decrypted);
    }

    @Test
    public void testEncryptRandomData() throws Exception {

        String password = "$3crEt-0O7";
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] data = RandomUtil.randomData(1, 1000000);
        byte[] encrypted = encrypt(password, salt, data);
        byte[] decrypted = decrypt(password, salt, encrypted);
        Assert.assertArrayEquals(data, decrypted);
    }

    private static byte[] encrypt(String password, byte[] salt, byte[] message) throws Exception {

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        final int iterations = 10000;

        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterations, ivParamSpec);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = kf.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParamSpec);
        byte[] encrypted = cipher.doFinal(message);

        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + encrypted.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return byteBuffer.array();
    }

    private static byte[] decrypt(String password, byte[] salt, byte[] encrypted) throws Exception {

        ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
        int ivLength = byteBuffer.getInt();
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        final int iterations = 10000;

        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterations, ivParamSpec);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = kf.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamSpec);
        return cipher.doFinal(cipherText);
    }
}
