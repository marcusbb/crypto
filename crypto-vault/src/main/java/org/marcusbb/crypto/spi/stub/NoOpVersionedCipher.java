package org.marcusbb.crypto.spi.stub;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.VersionedKey;

public class NoOpVersionedCipher implements VersionedCipher {

	
	public NoOpVersionedCipher(String keyStorePath, String password) {
		
	}
	public byte[] encrypt(VersionedKey version, byte[] payload) {
		return payload;
	}

	public byte[] decrypt(VersionedKey version, byte[] payload) {
		return payload;
	}
	
	
	//@Override
	public void encrypt(VersionedKey version, InputStream in, OutputStream out) throws IOException {
		inout(in,out);
		
	}
	//@Override
	public void decrypt(VersionedKey version, InputStream in, OutputStream out) throws IOException {
		inout(in,out);
		
	}
	private void inout(InputStream in,OutputStream out) {
		
		byte []b = new byte[1024];
		try {
			while (in.read(b) > 0 ) {
				out.write(b);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
	}

	
}
