package org.marcusbb.crypto.exception;

/**
 * 
 * Implementations will throw these exception if the contract of
 * {@link org.marcusbb.crypto.VersionedKeyBuilder#buildKey(String, String)} is violated
 * in some way.
 * For instance the key may not be found in the corresponding store
 * or the IV vector is not found.
 *
 */
public class UnknownKeyVersion extends RuntimeException {

	public UnknownKeyVersion(String message) {
		super(message);
	}
}
