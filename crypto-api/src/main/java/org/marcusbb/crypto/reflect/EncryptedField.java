package org.marcusbb.crypto.reflect;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.policy.Policy;


/**
 * An encrypted field is one that is encrypted according to the contract of an encrypted
 * symmetric cipher algorithm.  Practically, it's made of a 256 big AES key with a
 * 16 bit initialization vector.
 * 
 * {@link VersionedCipher} of encrypt and decrypt during phases described 
 * {@link ReflectedVersionedCipher#encrypt()}
 * 
 * Uses "toString" to put into default UTF8 encoding of byte array.
 *
 * Other encoding options are possible - by default the string version is chosen.
 * No intelligent mechanism exists to discover the type of field, and must be explicitly
 * specified by {@link #encodable()}. 
 * 
 * If the field represents a {@link CipherCloneable} then it will be followed and
 * corresponding fields in that class with be encrypted as well.  It does
 * this recursion infinitely (Possible acyclic check).
 * 
 * 
 *  
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface EncryptedField {

	String iv();
	
	String alias();
	
	Class<? extends ByteEncodable> encodable() default ByteEncodable.StringEncodable.class;
	
	Class<? extends Policy> policy() default Policy.NoPolicy.class;
}
