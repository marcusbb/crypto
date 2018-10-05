package org.marcusbb.crypto.commons;

import java.nio.charset.Charset;

public class StringUtils {

	public static final Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * Private constructor to prevent from constructing an instance of {@code StringUtils}.
	 */
	private StringUtils() {
	}

	/**
	 * Delegates to {@link String#getBytes(java.nio.charset.Charset)}
	 *
	 * @param string the string to encode or null, if string is null
	 * @param charset the encoding {@link java.nio.charset.Charset}
	 * 
	 * @return the encoded bytes
	 */
    private static byte[] getBytes(String string, Charset charset) {
    	return (string == null) ? null : string.getBytes(charset);
    }

    public static byte[] getBytesUtf8(final String string) {
    	return getBytes(string, UTF8);
    }
}
