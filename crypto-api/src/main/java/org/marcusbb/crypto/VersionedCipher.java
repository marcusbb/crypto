package org.marcusbb.crypto;


/**
 * 
 * Abstraction of {@link javax.crypto.Cipher} with particular {@link org.marcusbb.crypto.key.VersionedKeySpec}
 *
 */
public interface VersionedCipher  {

	public byte[] encrypt(VersionedKey version, byte[] payload);
	
	public byte[] decrypt(VersionedKey version, byte[] payload);
	
	
}
