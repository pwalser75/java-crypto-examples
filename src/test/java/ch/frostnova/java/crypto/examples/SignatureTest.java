package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import java.security.*;

/**
 * Tests for signing/verification using assymmetric cryptography
 *
 * @author pwalser
 * @since 10.04.2018
 */
public class SignatureTest {

    @Test
    public void testSignVerifyRSA() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        String signatureSpec = "SHA256withRSA";

        testSignVerify(keyPair, signatureSpec);
    }

    @Test
    public void testSignVerifyDSA() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        String signatureSpec = "SHA256withDSA";

        testSignVerify(keyPair, signatureSpec);
    }

    @Test
    public void testSignVerifyEC() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        String signatureSpec = "SHA256withECDSA";

        testSignVerify(keyPair, signatureSpec);
    }

    private static void testSignVerify(KeyPair keyPair, String signatureSpec) throws Exception {

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] data = RandomUtil.randomData(1, 1000000);
        byte[] signature = sign(privateKey, signatureSpec, data);
        boolean verified = verify(publicKey, signatureSpec, data, signature);
        Assert.assertTrue(verified);
    }


    private static byte[] encrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] sign(PrivateKey privateKey, String signatureSpec, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(signatureSpec);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verify(PublicKey publicKey, String signatureSpec, byte[] data, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance(signatureSpec);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}