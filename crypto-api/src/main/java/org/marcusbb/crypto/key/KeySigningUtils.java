package org.marcusbb.crypto.key;


import org.marcusbb.crypto.exception.EncryptException;
import org.marcusbb.crypto.exception.UnknownKeyVersion;

public class KeySigningUtils {

	public static byte[] sighWithKeyVersion(byte[] ciphertext, int ingKeyVersion) {
		byte[] tagged_ciphertext = new byte[3 + ciphertext.length];
		System.arraycopy(ciphertext, 0, tagged_ciphertext, 3, ciphertext.length);
		tagged_ciphertext[0] = 16;
		tagged_ciphertext[1] = (byte) (ingKeyVersion / 16);
		tagged_ciphertext[2] = (byte) ((ingKeyVersion % 16) << 4);

		return tagged_ciphertext;
	}

	public static byte[] stripKeyVersion(byte[] payload) {
		byte[] dataload = null;
		if (payload.length % 16 == 3) {
			//check it was written by Ingrian
			if (payload[0] == 16) {

				dataload = new byte[payload.length - 3];
				System.arraycopy(payload, 3, dataload, 0, payload.length - 3);

			} else {
				throw new EncryptException("Unknown format version of Crypto Tag");
			}
		}
		return dataload;
	}
	public static VersionedCipherText extractVersion(byte[] ciphertext) {

		int version = -1;

		if (ciphertext.length % 16 == 3) {
			// decode crypto tag and extract key version
			if (ciphertext[0] == 16) {
				version = ((ciphertext[1] & 0x000000ff) * 16) + ((ciphertext[2] & 0x000000f0) >>> 4);
				byte[] dataload = new byte[ciphertext.length - 3];
				System.arraycopy(ciphertext, 3, dataload, 0, ciphertext.length - 3);
				ciphertext = dataload;
			} else {
				throw new UnknownKeyVersion("Unknown format version of Crypto Tag");
			}
		}
		return new VersionedCipherText(ciphertext, version);
	}

	public static class VersionedCipherText {
		private byte[] ciphertext;
		private int version;

		public VersionedCipherText(byte[] ciphertext, int version) {
			this.ciphertext = ciphertext;
			this.version = version;
		}

		public byte[] getCiphertext() {
			return ciphertext;
		}

		public int getVersion() {
			return version;
		}
	}

}
