package ch.frostnova.java.crypto.examples;

import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Test for cipher suites
 *
 * @author pwalser
 * @since 13.04.2018
 */
public class CipherSuitesTest {

    @Test
    public void listSupportedCipherSuites() throws Exception {
        SSLContext context = SSLContext.getDefault();
        SSLSocketFactory socketFactory = context.getSocketFactory();

        System.out.println("# Supported cipher suites:");
        Stream.of(socketFactory.getSupportedCipherSuites()).sorted().forEach(System.out::println);
    }

    @Test
    public void listDefaultCipherSuites() throws Exception {
        SSLContext context = SSLContext.getDefault();
        SSLSocketFactory socketFactory = context.getSocketFactory();

        System.out.println("# Default cipher suites:");
        Stream.of(socketFactory.getDefaultCipherSuites()).sorted().forEach(System.out::println);
    }

    @Test
    public void recommendedCipherSuites() throws Exception {

        Pattern recommendedCipherSuites = Pattern.compile("TLS_(ECDHE|DHE)_(ECDSA|RSA)_WITH_AES_(128|256)_(GCM|CBC)_SHA(|256|384|512)");
        Predicate<String> recommended = s -> recommendedCipherSuites.matcher(s).matches();

        SSLContext context = SSLContext.getDefault();
        SSLSocketFactory socketFactory = context.getSocketFactory();

        System.out.println("# Recommended cipher suites:");
        Stream.of(socketFactory.getDefaultCipherSuites()).filter(recommended).sorted().forEach(System.out::println);

        System.out.println("# Not recommended:");
        Stream.of(socketFactory.getDefaultCipherSuites()).filter(recommended.negate()).sorted().forEach(System.out::println);
    }
}
