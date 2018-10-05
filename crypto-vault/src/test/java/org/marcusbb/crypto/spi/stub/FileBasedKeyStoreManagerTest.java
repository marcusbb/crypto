package org.marcusbb.crypto.spi.stub;

import static org.junit.Assert.assertEquals;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.marcusbb.crypto.spi.stub.FileBasedKeyStoreManager;

public class FileBasedKeyStoreManagerTest {

	@Test
	public void testGetSecretKey() {
		FileBasedKeyStoreManager fileBasedKeyStoreManager = new FileBasedKeyStoreManager();
		SecretKey iv_user_phone = fileBasedKeyStoreManager.getSecretKey("IV_User_phone");

		assertEquals(iv_user_phone.getAlgorithm(), "AES");
	}
}
