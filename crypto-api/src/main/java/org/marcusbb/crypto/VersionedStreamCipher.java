package org.marcusbb.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface VersionedStreamCipher {

	//Streaming operations - JCE/Vault only supported
		public void encrypt(VersionedKey version, InputStream in,OutputStream out) throws IOException;
		
		public void decrypt(VersionedKey version, InputStream in,OutputStream out) throws IOException;
}
