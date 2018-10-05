package org.marcusbb.crypto.spi.stub;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

import org.marcusbb.crypto.KeyStoreManager;
import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.VersionedKey;
import org.marcusbb.crypto.exception.EncryptException;
import org.marcusbb.crypto.key.VersionedKeySpec;
import org.marcusbb.crypto.key.KeySigningUtils;

public class AsymmetricVersionedCipher implements VersionedCipher {

	private static String ALG = "RSA";
	private KeyStoreManager ks = null;

	@Override
	public byte[] encrypt(VersionedKey version, byte[] payload) {
		// potentially fragile cast

		try {
			VersionedKeySpec materialized = (VersionedKeySpec)version;
			final Cipher cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.ENCRYPT_MODE, materialized.getKey());
			byte[] encryptedMaterial = cipher.doFinal(payload);
			// Sign cipher text with version
			return KeySigningUtils.sighWithKeyVersion(encryptedMaterial, version.getVersion());
		} catch (GeneralSecurityException e) {
			throw new EncryptException(e);
		}

	}

	@Override
	public byte[] decrypt(VersionedKey version, byte[] payload) {
		byte[] dataload = KeySigningUtils.stripKeyVersion(payload);
		try {
			VersionedKeySpec materialized = (VersionedKeySpec)version;
			final Cipher cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.DECRYPT_MODE, materialized.getKey());
			return cipher.doFinal(dataload);
			
		} catch (GeneralSecurityException e) {
			throw new EncryptException(e);
		}
	}

	//May support this in future, but arguably doesn't make sense given performance
	//@Override
	public void encrypt(VersionedKey version, InputStream in, OutputStream out) throws IOException {
		throw new UnsupportedOperationException("Unsupported: Use symmetric secret key encryption");
		
	}

	//@Override
	public void decrypt(VersionedKey version, InputStream in, OutputStream out) throws IOException {
		throw new UnsupportedOperationException("Unsupported: Use symmetric secret key encryption");
		
	}
	

}
