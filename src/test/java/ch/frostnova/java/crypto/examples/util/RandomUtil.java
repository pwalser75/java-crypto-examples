package ch.frostnova.java.crypto.examples.util;

import ch.frostnova.util.check.Check;
import ch.frostnova.util.check.CheckNumber;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Random utility functions.
 *
 * @author wap
 * @since 10.04.2018
 */
public final class RandomUtil {

    private RandomUtil() {

    }

    public static byte[] randomData(int min, int max) {
        Check.required(min, "min", CheckNumber.min(1));
        Check.required(max, "max", CheckNumber.min(min));

        int size = min + (int) ((max - min + 1) * Math.random());
        byte[] data = new byte[size];
        ThreadLocalRandom.current().nextBytes(data);
        return data;
    }
}
