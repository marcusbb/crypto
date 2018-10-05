package org.marcusbb.crypto;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * 
 * Supports retrieval of keys via simple alias reference
 *
 */
public interface KeyStoreManager {

	PrivateKey getPrivateKey(String alias);
	
	PublicKey getPublicKey(String alias);
	
	SecretKey getSecretKey(String alias);
	
	byte[] getIvParameter(String alias);
	
	/**
	 * Loads keys from a known keystore provided by an implementation.
	 * This may be a necessary by-product of key building {@link #buildKey(String, String)}
	 * above.  Implementations may decided to load lazily.
	 * 
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	void load() throws IOException,KeyStoreException;
	
	/**
	 * Even though not typically retrieved from
	 * KeyStore, it's built from a Secret Key.
	 * 
	 * @param secretkeyAlias
	 * @return
	 */
	Mac getMac(String secretkeyAlias);
}
