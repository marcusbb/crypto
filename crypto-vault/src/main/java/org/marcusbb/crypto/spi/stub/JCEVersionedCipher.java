package org.marcusbb.crypto.spi.stub;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.VersionedKey;
import org.marcusbb.crypto.VersionedStreamCipher;
import org.marcusbb.crypto.commons.KeyedVectoredSymmetricCipher;
import org.marcusbb.crypto.key.VersionedKeySpec;
import org.marcusbb.crypto.key.KeySigningUtils;


public class JCEVersionedCipher implements VersionedCipher,VersionedStreamCipher {

	private int STREAM_BLOCK_SIZE = 1024;
	
	public JCEVersionedCipher() {}

	public JCEVersionedCipher(int streamBlockSize) {
		this.STREAM_BLOCK_SIZE = streamBlockSize;
	}

	public byte[] encrypt(VersionedKey version, byte[] payload) {

		
		VersionedKeySpec materialized = (VersionedKeySpec)version;
		final KeyedVectoredSymmetricCipher cipher =
				KeyedVectoredSymmetricCipher
					.getInstance(materialized.getIvParameterSpec().getIV(), materialized.getKey());

		byte[] encryptedMaterial = cipher.encrypt(payload);

		// Sign cipher text with version
		return KeySigningUtils.sighWithKeyVersion(encryptedMaterial, version.getVersion());
	}

	/**
	 * Passed in version will be ignored in favor of the version extracted from payload.
	 */
	public byte[] decrypt(VersionedKey version, byte[] payload) {

		
		byte[] dataload = KeySigningUtils.stripKeyVersion(payload);
		//potentially fragile cast
		VersionedKeySpec materialized = (VersionedKeySpec)version;
		final KeyedVectoredSymmetricCipher cipher = KeyedVectoredSymmetricCipher.getInstance(materialized.getIvParameterSpec().getIV(), materialized.getKey());
		
		return cipher.decrypt(dataload);
		
	}

	
	public void encrypt(VersionedKey version, InputStream in,OutputStream out) throws IOException {
		
		VersionedKeySpec materialized = (VersionedKeySpec)version;
		
		final KeyedVectoredSymmetricCipher cipher = 
				KeyedVectoredSymmetricCipher
						.getInstance(materialized.getIvParameterSpec().getIV(), materialized.getKey());
		
		//stamp the version in the outputstream
		out.write(version.header());
		//write the rest of the input stream into the cipher output stream
		CipherOutputStream cos = new CipherOutputStream(out, cipher.getPrimedCipher(Cipher.ENCRYPT_MODE));
		inout(in,cos);
		cos.close();
	}

	/**
	 * possibly examine the stream prior to read, where the marker must be past the header blocks.
	 * 
	 */
	public void decrypt(VersionedKey version, InputStream in, OutputStream out) throws IOException {
		VersionedKeySpec materialized = (VersionedKeySpec)version;
		
			
		final KeyedVectoredSymmetricCipher cipher =
				KeyedVectoredSymmetricCipher
						.getInstance(materialized.getIvParameterSpec().getIV(), materialized.getKey());
		
		CipherInputStream cin = new CipherInputStream(in, cipher.getPrimedCipher(Cipher.DECRYPT_MODE));
		inout(cin,out);
		cin.close();
	}
	
	private void inout(InputStream in,OutputStream out) throws IOException {
		byte []b = new byte[STREAM_BLOCK_SIZE];
		int read = 0;
		while((read = in.read(b)) > 0) {
			out.write(b,0,read);
			b = new byte[STREAM_BLOCK_SIZE];
			out.flush();
		}
	}
}
