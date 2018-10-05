package org.marcusbb.crypto.reflect;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.crypto.Mac;

import org.marcusbb.crypto.KeyStoreManager;

/**
 * 
 * A field that represents a one way encrypted field, practially
 * of the form that takes a secret {@link Mac}
 *
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface HashedField {

	
	/**
	 * A reference to the secret material in the a keystore
	 * that can be accessed via {@link KeyStoreManager#getMac(String)}
	 * If this field is null it will be default no-key encrypted SHA1.
	 * 
	 */
	String alias();
	
	Class<? extends ByteEncodable> encodable() default ByteEncodable.StringEncodable.class;
	
	
}
