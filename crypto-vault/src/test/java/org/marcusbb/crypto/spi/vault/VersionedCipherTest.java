package org.marcusbb.crypto.spi.vault;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.key.VersionedKeySpec;
import org.marcusbb.crypto.spi.stub.AsymmetricVersionedCipher;
import org.marcusbb.crypto.spi.stub.JCEVersionedCipher;
import org.marcusbb.crypto.spi.vault.VaultKeyStoreManager;
import org.marcusbb.crypto.spi.vault.VaultVersionedKeyBuilder;
import org.marcusbb.crypto.spi.vault.AsymetricKeyMaterializer.KeyPairMaterializer;

public class VersionedCipherTest extends VaultTestBase {

	@Test
	public void testAsymmetricCipher() throws Exception {
		KeyPairMaterializer rsakey = new KeyPairMaterializer(1024);
		
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		
		store.postAsymmetricKey(VaultKeyStoreManager.PRIV_KEY_PREFIX + "/" + "v1_rsa1",VaultKeyStoreManager.PUB_KEY_PREFIX + "/" + "v1_rsa1", rsakey);
		
		VersionedCipher vCipher = new AsymmetricVersionedCipher();
		VaultVersionedKeyBuilder keyBuilder = new VaultVersionedKeyBuilder(store);
		
		byte []encrypted = vCipher.encrypt(keyBuilder.buildPublicKey("rsa1"), "helloworld".getBytes());
		
		byte []decrypted = vCipher.decrypt(keyBuilder.buildPrivateKey("rsa1", encrypted),encrypted);
		
				
		Assert.assertEquals("helloworld",new String(decrypted));
		
	}
	
	@Test
	public void testAsymmetricCipherSeamless() throws Exception {
		KeyPairMaterializer rsakey = new KeyPairMaterializer(1024);
		
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		
		store.postAsymmetricKey(VaultKeyStoreManager.PRIV_KEY_PREFIX + "/" + "v1_rsa1",VaultKeyStoreManager.PUB_KEY_PREFIX + "/" + "v1_rsa1", rsakey);
		
		VersionedCipher vCipher = new AsymmetricVersionedCipher();
		VaultVersionedKeyBuilder keyBuilder = new VaultVersionedKeyBuilder(store);
		
		//I'M NOT A FAN OF this format
		byte []encrypted = vCipher.encrypt(keyBuilder.buildKey("public/rsa1","doesntmatter"), "helloworld".getBytes());
		
		byte []decrypted = vCipher.decrypt(keyBuilder.buildKey("private/rsa1",new byte[0],encrypted), encrypted);
		
				
		assertEquals("helloworld",new String(decrypted));
		
	}

	@Test
	public void latestKey() throws NoSuchAlgorithmException, KeyStoreException {
		
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
				
		VersionedCipher vCipher = new AsymmetricVersionedCipher();
		VaultVersionedKeyBuilder keyBuilder = new VaultVersionedKeyBuilder(store);
		assertEquals(1,keyBuilder.getVersion());
		
		String keyName = "latestKey" + new SecureRandom().nextLong();
		store.createOrUpdateKeyPair("RSA", keyName);
		byte []encrypted = vCipher.encrypt(keyBuilder.buildPublicKey(keyName),"helloworld".getBytes());
		store.createOrUpdateKeyPair("RSA", keyName);
		store.createOrUpdateKeyPair("RSA", keyName);
		
		VersionedKeySpec vKey = (VersionedKeySpec)keyBuilder.buildPublicKey(keyName);
		VersionedKeySpec vPrivKey = (VersionedKeySpec)keyBuilder.buildPrivateKey(keyName,encrypted);
		assertEquals(1,vPrivKey.getVersion());
		assertEquals(3,vKey.getVersion());
		
		
		byte []reencrypted = vCipher.encrypt(vKey, vCipher.decrypt(vPrivKey, encrypted));
		
		
		
	}
	@Test
	public void streamCipherTest() throws NoSuchAlgorithmException,IOException  {
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		final String CREDIT_CARD_NAME = "aes_credit_card";
		final String CREDIT_CARD_NUMBER_IV = "0123456789123456";
		
		store.createOrUpdateSecretVersion("AES",CREDIT_CARD_NAME);
		store.createOrUpdateIv(CREDIT_CARD_NUMBER_IV, CREDIT_CARD_NUMBER_IV.getBytes());
		
		//Assert.assertNotNull(store.getSecretKey("v1_" + CREDIT_CARD_NAME) );
		JCEVersionedCipher vCipher = new JCEVersionedCipher();
		ByteArrayInputStream bin = new ByteArrayInputStream("Hello Streaming Encryption".getBytes());
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		vCipher.encrypt(new VaultVersionedKeyBuilder(store).buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV),bin,bout);
		
		System.out.println(Base64.encodeBase64URLSafeString(bout.toByteArray()) );
		ByteArrayOutputStream decryptStream = new ByteArrayOutputStream();
		ByteArrayInputStream ein = new ByteArrayInputStream(bout.toByteArray());
		vCipher.decrypt(new VaultVersionedKeyBuilder(store).buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV,ein),ein , decryptStream);
	
		
		
		System.out.println(new String(decryptStream.toByteArray()) );
		Assert.assertEquals("Hello Streaming Encryption", new String(decryptStream.toByteArray()));
		Assert.assertArrayEquals("Hello Streaming Encryption".getBytes(), decryptStream.toByteArray());
		
		ein = new ByteArrayInputStream(bout.toByteArray());
		decryptStream = new ByteArrayOutputStream();
		vCipher.decrypt(new VaultVersionedKeyBuilder(store).buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV.getBytes(),ein),ein , decryptStream);
	}
	
	@Test
	public void streamLargeFile() throws NoSuchAlgorithmException,IOException {
		
		//write a large file:
		int size = 1024*1024;
		String template = "The quick brown fox jumps over the lazy dog\n";
		FileOutputStream fout = new FileOutputStream("largefile.dat");
		for (int i=0;i<size;i++) {
			fout.write(template.getBytes());
		}
		fout.close();
		
		VaultKeyStoreManager store = new VaultKeyStoreManager(getConfig());
		final String CREDIT_CARD_NAME = "aes_credit_card";
		final String CREDIT_CARD_NUMBER_IV = "0123456789123456";
		
		store.createOrUpdateSecretVersion("AES",CREDIT_CARD_NAME);
		store.createOrUpdateIv(CREDIT_CARD_NUMBER_IV, CREDIT_CARD_NUMBER_IV.getBytes());
		
		//Assert.assertNotNull(store.getSecretKey("v1_" + CREDIT_CARD_NAME) );
		JCEVersionedCipher vCipher = new JCEVersionedCipher();
		long start = System.currentTimeMillis();
		fout = new FileOutputStream("largefile.enc");
		vCipher.encrypt(new VaultVersionedKeyBuilder(store).buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV),new FileInputStream("largefile.dat"),fout);
		System.out.println("encrypt time: " + (System.currentTimeMillis() - start));
		fout.close();
		start = System.currentTimeMillis();
		FileInputStream fin = new FileInputStream("largefile.enc");
		vCipher.decrypt(new VaultVersionedKeyBuilder(store).buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV.getBytes(),fin),fin , new FileOutputStream("largefile.enc.dat"));
		System.out.println("decrypt time: " + (System.currentTimeMillis() - start));
		
		//TODO: clean up
		new File("largefile.dat").delete();
		new File("largefile.enc").delete();
		new File("largefile.enc.dat").delete();
	}
		
}
