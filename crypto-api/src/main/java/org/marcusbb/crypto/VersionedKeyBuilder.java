package org.marcusbb.crypto;

import java.security.KeyStore;

import org.marcusbb.crypto.exception.UnknownKeyVersion;
import org.marcusbb.crypto.key.VersionedKeySpec;

/**
 * Abstracts some {@link KeyStore} functionality.
 * <p/>
 * Formalizes notion  of building/getting {@link org.marcusbb.crypto.VersionedKey} from a key alias that ultimately tied to a
 * key store implementation - {@link KeyStoreManager} 
 * 
 * 
 */
public interface VersionedKeyBuilder {

	/**
	 * Consumers will know 2 parts to define a VersionedKey
	 *
	 * @param name       - the alias of the key
	 * @param ivSpecName - alias to the initialization vector
	 * @return
	 * @throws org.marcusbb.crypto.exception.UnknownKeyVersion
	 */
	VersionedKey buildKey(String name, String ivSpecName) throws UnknownKeyVersion;

	VersionedKey buildKey(String name, byte[] iv) throws UnknownKeyVersion;

	VersionedKey buildKey(String keyAlias, String ivSpecName, byte[] versionedCipherText) throws UnknownKeyVersion;

	VersionedKey buildKey(String keyAlias, byte[] iv, byte[] versionedCipherText) throws UnknownKeyVersion;

	VersionedKey buildPrivateKey(String keyAlias, byte[] versionedCipherText);
	
	VersionedKey buildPublicKey(String keyAlias);
	
	int getVersion();

}
