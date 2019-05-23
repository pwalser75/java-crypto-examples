package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Tests for signing/verification using asymmetric cryptography
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

        byte[] data = RandomUtil.randomData(1, 10000);
        byte[] signature = CryptoUtil.sign(privateKey, signatureSpec, data);
        boolean verified = CryptoUtil.verify(publicKey, signatureSpec, data, signature);
        Assert.assertTrue(verified);
    }
}
