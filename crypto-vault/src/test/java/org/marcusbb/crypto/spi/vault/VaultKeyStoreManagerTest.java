package org.marcusbb.crypto.spi.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.marcusbb.crypto.commons.StringUtils;
import org.marcusbb.crypto.spi.vault.AsymetricKeyMaterializer;
import org.marcusbb.crypto.spi.vault.VaultHttpClient;
import org.marcusbb.crypto.spi.vault.VaultKeyStoreManager;
import org.marcusbb.crypto.spi.vault.AsymetricKeyMaterializer.KeyPairMaterializer;




public class VaultKeyStoreManagerTest extends VaultTestBase {

	@Test
	public void testSecret() throws Exception {
		SecretKey aes1 = KeyGenerator.getInstance("AES").generateKey();
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		store.postSecret("aes1", aes1);
		
		Key aesComp = store.getSecretKey("aes1");

		assertArrayEquals(aes1.getEncoded(), aesComp.getEncoded());
		
		//can use to encrypt?
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, aesComp);
		assertNotNull(cipher);
		assertNotNull(cipher.doFinal("hello_worlld".getBytes()) );
	}
	@Test
	public void testAsymmetricKey() throws Exception {
		KeyPairMaterializer rsakey = new KeyPairMaterializer(2048);
		
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		
		store.postAsymmetricKey(VaultKeyStoreManager.PRIV_KEY_PREFIX + "/" + "rsa1",VaultKeyStoreManager.PUB_KEY_PREFIX + "/" + "rsa1", rsakey);
		PrivateKey key = store.getPrivateKey("rsa1");
		assertNotNull(key);
		assertNotNull(store.getPublicKey("rsa1"));
		
		PrivateKey key2 = store.getPrivateKey("rsa1");
		assertEquals(key,key2);
	}
	@Test
	public void testBackwardCompatibleAsyncKey() throws Exception {
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		
		//construct backward compatible key in vault
		AsymetricKeyMaterializer materializer = new KeyPairMaterializer();
		VaultHttpClient client = new VaultHttpClient(getConfig());
		String keyname = "old_rsa";
		String vKeyName = "v1_" + keyname;
		try {
			// private
			Map<String, byte[]> map = materializer.privatePortion();
			client.post(VaultKeyStoreManager.PRIV_KEY_PREFIX + "/" + vKeyName, map);
			// public
			map = materializer.publicPortion();
			client.post(VaultKeyStoreManager.PUB_KEY_PREFIX + "/" + vKeyName, map);
		} catch (Exception e) {
			throw new KeyStoreException(e);
		}
		
		PrivateKey key = store.getPrivateKey(vKeyName);
		assertNotNull(key);
		assertNotNull(store.getPublicKey(vKeyName));
		
		PrivateKey key2 = store.getPrivateKey(vKeyName);
		assertEquals(key,key2);
		
	}
	
	@Test
	public void testUpdateAsymmetric() throws Exception {
		
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		
		//new pair
		store.createOrUpdateKeyPair("RSA","incr");
		Integer[]versions = store.getVersions("incr", VaultKeyStoreManager.PRIV_KEY_PREFIX);
		assertEquals(1,(int)versions[0]);
		
		//update
		store.createOrUpdateKeyPair("RSA","incr");
		versions = store.getVersions("incr", VaultKeyStoreManager.PRIV_KEY_PREFIX);
		assertEquals(2,versions.length);
		
		
		
	}

	@Test
	public void listKeysTest() throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		SecretKey key = kg.generateKey();
		final byte[] keyMaterial = StringUtils.getBytesUtf8("credit_card__key");
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		int num_keys = 10;
		store.postKey(VaultKeyStoreManager.IV_PREFIX + "/aes1", new SecretKeySpec(keyMaterial,"AES"));
		for (int i=1;i<=num_keys;i++) {
			store.postKey(VaultKeyStoreManager.SECR_KEY_PREFIX + "/v" +i+ "_incr", key , key.getAlgorithm());
			
		}
		String []names = store.getKeyNames(VaultKeyStoreManager.SECR_KEY_PREFIX );
		System.out.println(names);
		assertNotNull(names);
		assertTrue( names.length >= num_keys);
		
		//add more keys to ensure we prune appropriately
		for (int i=1;i<=num_keys;i++) {
			store.postKey(VaultKeyStoreManager.SECR_KEY_PREFIX + "/v" +i+ "_incrPostFixed", key , key.getAlgorithm());
			
		}
		assertTrue(store.getKeyNames(VaultKeyStoreManager.SECR_KEY_PREFIX ).length >= (num_keys*2));
		//list versions
		
		Integer []versions = store.getVersions("incr",VaultKeyStoreManager.SECR_KEY_PREFIX);
		assertEquals(num_keys,versions.length);
	}
	
	@Test
	public void updateKeyTest() throws Exception {
			
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		int num_keys = 10;
		
		store.createOrUpdateSecretVersion("myNewSecret");
		Integer []versions = store.getVersions("myNewSecret",VaultKeyStoreManager.SECR_KEY_PREFIX);
		assertEquals(1,(int)versions[0]);
		
		for (int i=1;i<=num_keys;i++) {
			store.createOrUpdateSecretVersion("myNewSecret");
			
		}
		//we have invoked 11 times, 11 keys
		versions = store.getVersions("myNewSecret",VaultKeyStoreManager.SECR_KEY_PREFIX);
		assertEquals(11,versions.length);
		Arrays.sort(versions);
		assertEquals(1,(int)versions[0]);
		assertEquals(11,(int)versions[10]);
		
		//Due to limitations in implementation keys must be retrieved by fully versioned name
		assertNotNull(store.getSecretKey("v1_myNewSecret") );
		assertNotNull(store.getSecretKey("v2_myNewSecret") );
		
	}
	
	@Test
	public void testPublicKeyRetrieval() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Create the public and private keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        String publicKeyName = "PUB_KEY_NAME_RETRIEVAL_TEST";

        SecureRandom random = new SecureRandom();
        generator.initialize(1024, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		store.postKey(VaultKeyStoreManager.PUB_KEY_PREFIX+ "/" + publicKeyName, pubKey);
		
		Key retrievedPublicKey = store.getPublicKey(publicKeyName);
		
		assertNotNull(retrievedPublicKey);
		assertEquals(pubKey.getAlgorithm(), retrievedPublicKey.getAlgorithm());
		assertEquals(pubKey.getFormat(), retrievedPublicKey.getFormat());
		assertArrayEquals(pubKey.getEncoded(), retrievedPublicKey.getEncoded());
		

	}

	@Test
	public void testPrivateKeyRetrieval() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Create the public and private keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        String privKeyName = "PRIV_KEY_NAME_RETRIEVAL_TEST";

        SecureRandom random = new SecureRandom();
        generator.initialize(1024, random);

        KeyPair pair = generator.generateKeyPair();
        Key privKey = pair.getPrivate();
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		store.postKey(VaultKeyStoreManager.PRIV_KEY_PREFIX+ "/" + privKeyName, privKey);
		
		Key retrievedPrivKey = store.getPrivateKey(privKeyName);
		
		assertNotNull(retrievedPrivKey);
		assertEquals(privKey.getAlgorithm(), retrievedPrivKey.getAlgorithm());
		assertEquals(privKey.getFormat(), retrievedPrivKey.getFormat());
		assertArrayEquals(privKey.getEncoded(), retrievedPrivKey.getEncoded());
		

	}

	
}
