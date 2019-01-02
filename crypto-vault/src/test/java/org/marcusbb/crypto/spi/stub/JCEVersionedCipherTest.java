package org.marcusbb.crypto.spi.stub;

import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;
import org.marcusbb.crypto.VersionedKey;
import org.marcusbb.crypto.commons.StringUtils;
import org.marcusbb.crypto.spi.stub.FileBasedKeyStoreManager;
import org.marcusbb.crypto.spi.stub.FileBasedVersionedKeyBuilder;
import org.marcusbb.crypto.spi.stub.JCEVersionedCipher;


@Ignore
public class JCEVersionedCipherTest  {

	private final FileBasedVersionedKeyBuilder fileBasedVersionedKeyBuilder = new FileBasedVersionedKeyBuilder(new FileBasedKeyStoreManager());
	private final JCEVersionedCipher jceVersionedCipher = new JCEVersionedCipher();

	private final String stringToEncrypt = "String to encrypt";
	private final String KeyMoniker = "User_phone";
	private final String ivMoniker = "IV_User_phone";

	@Test
	public void testEncryptDecrypt_ok() {

		byte[] signedCipherText = encrypt(stringToEncrypt);
		byte[] decryptedMaterial = decrypt(signedCipherText);

		assertEquals(stringToEncrypt, new String(decryptedMaterial, StringUtils.UTF8));
	}

	private byte[] decrypt(byte[] signedCipherText) {

		VersionedKey decryptionKey = fileBasedVersionedKeyBuilder
				.buildKey(KeyMoniker, ivMoniker, signedCipherText);

		return jceVersionedCipher.decrypt(decryptionKey, signedCipherText);
	}

	private byte[] encrypt(String stringToEncrypt) {
		VersionedKey versionedKey = fileBasedVersionedKeyBuilder.buildKey(KeyMoniker, ivMoniker);
		return jceVersionedCipher.encrypt(versionedKey, StringUtils.getBytesUtf8(stringToEncrypt));
	}
}
