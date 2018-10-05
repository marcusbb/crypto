package org.marcusbb.crypto.commons;

import org.apache.commons.codec.binary.Base64;

/**
 *
 * This class represents stripped down version of ByteUtils from commons.
 *
 * Used in this way to ensure compliance with JDK 1.6
 *
 * FIXME remove once commons is added as dependency
 */
public class ByteUtils {

    /**
     * Convert bytes to url safe base64 encoded string
     * @param bytes
     */
	public static String base64Encode(final byte[] bytes) {
		return base64Encode(bytes, true);
    }

    /**
     * Convert bytes to base64 encoded string
     *
     * @param bytes
     * @param urlSafe indicates if URL safe encoding is required
     * @return
     */
    public static String base64Encode(final byte[] bytes, boolean urlSafe) {
    	if (urlSafe) {
    		return Base64.encodeBase64URLSafeString(bytes);
    	}
		return Base64.encodeBase64String(bytes);
    }

    /**
     * Convert base64 encoded string to bytes
     * @param encoded
     */
    public static byte[] base64Decode(final String encoded) {
    	return Base64.decodeBase64(encoded);
    }
}
