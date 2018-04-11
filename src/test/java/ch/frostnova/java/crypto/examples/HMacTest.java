package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.RandomUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Tests for HMac signatures
 *
 * @author pwalser
 * @since 10.04.2018
 */
public class HMacTest {

    @Test
    public void testSign() throws Exception {

        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        byte[] data = RandomUtil.randomData(1, 1000000);

        Assert.assertArrayEquals(sign(key, data), sign(key, data));
    }

    public static byte[] sign(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, mac.getAlgorithm());

        mac.init(secretKey);
        byte[] signature = mac.doFinal(data);
        return signature;
    }
}
