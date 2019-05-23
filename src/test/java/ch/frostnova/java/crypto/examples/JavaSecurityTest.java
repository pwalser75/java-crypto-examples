package ch.frostnova.java.crypto.examples;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Tests for Java Security
 *
 * @author pwalser
 * @since 10.04.2018
 */
public class JavaSecurityTest {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Test
    public void testAvailableProviders() {

        Map<String, Set<String>> securityAlgorithms = Stream.of(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                .collect(Collectors.groupingBy(
                        Service::getType,
                        Collectors.mapping(
                                Service::getAlgorithm,
                                Collectors.toSet())));

        securityAlgorithms.keySet().stream().sorted().forEach(type ->
                System.out.println(type + " :\n   " + securityAlgorithms.get(type).stream().sorted().collect(Collectors.joining(", ")))
        );

        Assert.assertTrue(securityAlgorithms.get("SSLContext").containsAll(Arrays.asList("TLSv1", "TLSv1.1", "TLSv1.2")));
        Assert.assertTrue(securityAlgorithms.get("KeyGenerator").containsAll(Arrays.asList("AES", "Blowfish", "HmacSHA256", "HmacSHA384", "HmacSHA512")));
        Assert.assertTrue(securityAlgorithms.get("KeyPairGenerator").containsAll(Arrays.asList("DSA", "DiffieHellman", "EC", "RSA")));
        Assert.assertTrue(securityAlgorithms.get("MessageDigest").containsAll(Arrays.asList("MD5", "SHA-224", "SHA-256", "SHA-384", "SHA-512")));
        Assert.assertTrue(securityAlgorithms.get("Mac").containsAll(Arrays.asList("HmacMD5", "HmacSHA256", "HmacSHA384", "HmacSHA512")));
    }

    @Test
    public void testUnlimitedCryptographyEnabled() throws Exception {

        int rsaMax = Cipher.getMaxAllowedKeyLength("RSA");
        int ecMax = Cipher.getMaxAllowedKeyLength("EC");
        int aesMax = Cipher.getMaxAllowedKeyLength("AES");

        log.info("Java RT version: " + System.getProperty("java.runtime.version"));
        log.info("Max. RSA key length: " + rsaMax);
        log.info("Max. RSA key length: " + rsaMax);
        log.info("Max. EC key length: " + ecMax);
        log.info("Max. AES key length: " + aesMax);

        String fail = "JCE unlimited strength cryptography not enabled";
        Assert.assertTrue(fail, rsaMax == Integer.MAX_VALUE);
        Assert.assertTrue(fail, ecMax == Integer.MAX_VALUE);
        Assert.assertTrue(fail, aesMax == Integer.MAX_VALUE);

    }
}
