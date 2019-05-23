package ch.frostnova.java.crypto.examples;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Crypto utility functions
 *
 * @author pwalser
 * @since 23.05.2019
 */
public final class CryptoUtil {

    private CryptoUtil() {

    }

    /**
     * Symmetric encryption.
     *
     * @param secretKey secret key, required
     * @param message   message, required
     * @return encrypted data
     * @throws Exception ex
     */
    public static byte[] encrypt(SecretKey secretKey, byte[] message) throws Exception {

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

    /**
     * Symmetric decryption.
     *
     * @param secretKey secret key, required
     * @param encrypted encrypted data, required
     * @return decrypted message
     * @throws Exception ex
     */
    public static byte[] decrypt(SecretKey secretKey, byte[] encrypted) throws Exception {

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

    /**
     * Password-based encryption
     *
     * @param password   password, required
     * @param salt       salt, required
     * @param iterations number of iterations, required, must be positive
     * @param message    message to encrypt, required
     * @return encrypted message
     * @throws Exception ex
     */
    public static byte[] encrypt(String password, byte[] salt, int iterations, byte[] message) throws Exception {

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

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

    /**
     * Password-based decryption
     *
     * @param password   password, required
     * @param salt       salt, required
     * @param iterations number of iterations, required, must be positive
     * @param encrypted  encrypted message, required
     * @return decrypted message
     * @throws Exception ex
     */
    public static byte[] decrypt(String password, byte[] salt, int iterations, byte[] encrypted) throws Exception {

        ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
        int ivLength = byteBuffer.getInt();
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterations, ivParamSpec);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());

        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = kf.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamSpec);
        return cipher.doFinal(cipherText);
    }

    /**
     * Sign data using private key.
     *
     * @param privateKey    private key, required
     * @param signatureSpec signature spec to use, required
     * @param data          data to sign, required
     * @return signature
     * @throws Exception ex
     */
    public static byte[] sign(PrivateKey privateKey, String signatureSpec, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(signatureSpec);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verify a signature using public key.
     *
     * @param publicKey      public key, required
     * @param signatureSpec  signature spec used for signing, required
     * @param data           data that was signed, required
     * @param signatureBytes signature
     * @return true if verified, false if not.
     * @throws Exception ex
     */
    public static boolean verify(PublicKey publicKey, String signatureSpec, byte[] data, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance(signatureSpec);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
