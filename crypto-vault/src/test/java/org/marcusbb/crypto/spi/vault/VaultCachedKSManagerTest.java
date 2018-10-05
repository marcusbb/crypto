package org.marcusbb.crypto.spi.vault;

import static org.junit.Assert.*;

import java.util.concurrent.TimeUnit;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Test;
import org.marcusbb.crypto.spi.vault.VaultCachedKSManager;

public class VaultCachedKSManagerTest extends VaultTestBase {

	@Test
	public void testCached() throws Exception {
		
		SecretKey aes1 = KeyGenerator.getInstance("AES").generateKey();
		VaultCachedKSManager store = new VaultCachedKSManager(getConfig(), 100, TimeUnit.MILLISECONDS, 100);
		store.postSecret("aes1", aes1);
		
		assertEquals(0,store.keyCache.size());
		
		store.getSecretKey("aes1");
		
		assertEquals(1,store.keyCache.size());
		
		
		
	}

}
