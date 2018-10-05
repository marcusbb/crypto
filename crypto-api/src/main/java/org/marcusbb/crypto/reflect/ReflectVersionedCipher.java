package org.marcusbb.crypto.reflect;

/**
 * 
 * A field level encrypted cipher.
 * Those data fields with corresponding {@link EncryptedField}
 *
 */
public interface ReflectVersionedCipher {


	public ByteShadow encrypt(CipherCloneable obj) throws NotCloneable;
	
	public void decrypt(CipherCloneable obj, ByteShadow shadow) throws NotCloneable;
	
}
