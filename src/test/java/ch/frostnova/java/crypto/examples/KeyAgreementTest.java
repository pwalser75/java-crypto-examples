package ch.frostnova.java.crypto.examples;

import ch.frostnova.java.crypto.examples.util.ByteSequence;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

/**
 * Key agreement using ECDSA
 *
 * @author pwalser
 * @since 11.04.2018
 */
public class KeyAgreementTest {

    @Test
    public void testKeyAgreement() throws Exception {

        Party p1 = new Party();
        Party p2 = new Party();

        byte[] secret1 = p1.generateSecret(p2.getPublicKey());
        byte[] secret2 = p2.generateSecret(p1.getPublicKey());

        System.out.println("Secret 1: " + ByteSequence.toString(secret1));
        System.out.println("Secret 2: " + ByteSequence.toString(secret2));
        Assert.assertArrayEquals(secret1, secret2);
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
