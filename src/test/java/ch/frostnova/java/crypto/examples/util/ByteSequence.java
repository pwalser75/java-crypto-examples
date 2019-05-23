package ch.frostnova.java.crypto.examples.util;

import ch.frostnova.util.check.Check;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A sequence of bytes, or rather a wrapper around a byte array
 *
 * @author pwalser
 * @since 23.05.2019
 */
public class ByteSequence {

    /**
     * LUT (look-up table) for string representations (hex uppercase) of bytes
     */
    private final static String[] HEX_LUT;

    static {
        HEX_LUT = new String[0x100];
        for (int i = 0; i < 0x100; i++) {
            String hex = Integer.toHexString(i).toUpperCase();
            if (hex.length() < 2) {
                hex = '0' + hex;
            }
            HEX_LUT[i] = hex;
        }
    }

    private byte[] data;

    public ByteSequence(byte[] data) {
        Check.required(data, "data");
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(data.length);
        builder.append(" bytes ");
        builder.append('[');
        builder.append(
                IntStream.range(0, data.length)
                        .map(idx -> data[idx])
                        .map(b -> (b + 256) & 0xFF)
                        .mapToObj(b -> HEX_LUT[b])
                        .collect(Collectors.joining(":")));
        builder.append(']');
        return builder.toString();
    }

    public static String toString(byte[] data) {
        return new ByteSequence(data).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ByteSequence that = (ByteSequence) o;
        return Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
