package org.marcusbb.crypto.commons;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class KeyedVectoredSymmetricCipher  {

	public static final String fullName = "AES/CBC/PKCS5Padding";
	private byte[] initVector;
	private java.security.Key key;

	private KeyedVectoredSymmetricCipher(byte[] initVector, java.security.Key key) {
		this.initVector = initVector;
		this.key = key;
	}

	public static KeyedVectoredSymmetricCipher getInstance(byte[] initVector, java.security.Key key) {
		return new KeyedVectoredSymmetricCipher(initVector, key);
	}

	public byte[] encrypt(byte[] data) {
		checkNotNull(data);
		try {
			Cipher cipher = Cipher.getInstance(fullName);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initVector));
			return cipher.doFinal(data);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] decrypt(byte[] data)  {
		checkNotNull(data);
		try {
			Cipher cipher = Cipher.getInstance(fullName);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initVector));
			return cipher.doFinal(data);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
	public Cipher getPrimedCipher(int mode) {
		try {
			Cipher cipher = Cipher.getInstance(fullName);
			cipher.init(mode, key, new IvParameterSpec(initVector));
			return cipher;
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
}
