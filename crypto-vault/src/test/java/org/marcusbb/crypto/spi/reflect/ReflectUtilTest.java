package org.marcusbb.crypto.spi.reflect;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.VersionedKeyBuilder;
import org.marcusbb.crypto.reflect.ByteShadow;
import org.marcusbb.crypto.reflect.ReflectException;
import org.marcusbb.crypto.spi.reflect.ReflectConfigBuilder;
import org.marcusbb.crypto.spi.reflect.ReflectUtil;
import org.marcusbb.crypto.spi.reflect.structures.Child;
import org.marcusbb.crypto.spi.reflect.structures.FirstLevel;
import org.marcusbb.crypto.spi.reflect.structures.SelfReferencing;
import org.marcusbb.crypto.spi.reflect.structures.TestMessage;
import org.marcusbb.crypto.spi.reflect.structures.TestMessageIncomplete;
import org.marcusbb.crypto.spi.reflect.structures.TestMessageWithHash;
import org.marcusbb.crypto.spi.stub.JCEVersionedCipher;
import org.marcusbb.crypto.spi.vault.VaultKeyStoreManager;
import org.marcusbb.crypto.spi.vault.VaultTestBase;
import org.marcusbb.crypto.spi.vault.VaultVersionedKeyBuilder;

public class ReflectUtilTest extends VaultTestBase {

	VersionedCipher vCipher;
	VersionedKeyBuilder keyBuilder;
	VaultKeyStoreManager store;
	static final String CREDIT_CARD_NAME = "aes_credit_card";
	static final String CREDIT_CARD_NUMBER_IV = "0123456789123456";
	
	@Before
	public void before() throws NoSuchAlgorithmException {
		store = new VaultKeyStoreManager(getConfig());
		
		store.createOrUpdateSecretVersion("AES",CREDIT_CARD_NAME);
		store.createOrUpdateIv(CREDIT_CARD_NUMBER_IV, CREDIT_CARD_NUMBER_IV.getBytes());
		vCipher = new JCEVersionedCipher();
		keyBuilder = new VaultVersionedKeyBuilder(store);
	}
	@Test
	public void discovery() throws Exception {
		ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
		
		assertNotNull ( ReflectConfigBuilder.getInstance().buildConfig(TestMessage.class) );
		
	}
	@Test(expected=ReflectException.class)
	public void discoveryException() throws Exception {
		ReflectConfigBuilder.getInstance().buildConfig(TestMessageIncomplete.class);
		//TODO: assert various configurations in place
		
	}
	@Test
	public void testEncryptDecrpt() throws Exception {
		//ByteShadow bs = new ByteShadow(new TestMessage("helloworld"));
		ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
		
		ByteShadow bs = ref.encrypt(new TestMessage("helloworld",11L));
		assertTrue( bs.getShadowByteMap().get("toencrypt") != null);
		
		assertTrue(bs.getSrcObj() instanceof TestMessage);
		
		assertTrue( ((TestMessage)bs.getSrcObj()).getToencrypt() == null);
		
		
		TestMessage hydrated = new TestMessage();
		ref.decrypt(hydrated, bs);
		assertEquals("helloworld",hydrated.getToencrypt());
		
		assertEquals(new Long(11),hydrated.getANumber());
		
	}
	
	@Test
	public void testEncryptDecrptNulls() throws Exception {
		//ByteShadow bs = new ByteShadow(new TestMessage("helloworld"));
		ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
		//Only difference from above is null Long
		ByteShadow bs = ref.encrypt(new TestMessage("helloworld",null));
		assertTrue( bs.getShadowByteMap().get("toencrypt") != null);
		ByteShadow allNulls = ref.encrypt(new TestMessage(null,null));
		
		
		assertTrue(bs.getSrcObj() instanceof TestMessage);
		
		assertTrue( ((TestMessage)bs.getSrcObj()).getToencrypt() == null);
		
		assertNull( ((TestMessage)allNulls.getSrcObj()).getToencrypt());
		assertNull( ((TestMessage)allNulls.getSrcObj()).getANumber());
		
		TestMessage hydrated = new TestMessage();
		ref.decrypt(hydrated, bs);
		assertEquals("helloworld",hydrated.getToencrypt());
		
		
	}

	@Test
	public void testEncodings() throws Exception {
		//ByteShadow bs = new ByteShadow(new TestMessage("helloworld"));
		ReflectUtil ref = new ReflectUtil(keyBuilder, vCipher,store);

		ByteShadow bs = ref.encrypt(new TestMessage("helloworld", 11L));
		assertTrue(bs.getShadowByteMap().get("toencrypt") != null);

		assertTrue(bs.getSrcObj() instanceof TestMessage);

		assertTrue(((TestMessage) bs.getSrcObj()).getToencrypt() == null);

		TestMessage hydrated = new TestMessage();
		ref.decrypt(hydrated, bs);
		assertEquals("helloworld", hydrated.getToencrypt());

		assertEquals(new Long(11),hydrated.getANumber());
	}
	
	//should change to support hierarchy
	@Test
	public void testHierarchy() {
		
		ReflectUtil ref = new ReflectUtil(keyBuilder, vCipher,store);

		ByteShadow bs = ref.encrypt(new FirstLevel(new TestMessage("helloworld", 11L)));
		assertTrue(bs.getShadowByteMap().get("embedded.toencrypt") != null);
		
		FirstLevel cloned = (FirstLevel)bs.getSrcObj();
		assertNotNull(cloned);assertNotNull(cloned.getEmbedded());
		assertNull(cloned.getEmbedded().getToencrypt());
		
		ref.decrypt(cloned, bs);
		
	}
	
	@Test
	public void testHierarchyNull() {
		
		ReflectUtil ref = new ReflectUtil(keyBuilder, vCipher,store);
		//this would not fail due to check in null embedded objects
		ByteShadow bs = ref.encrypt(new FirstLevel(null));
		
	}
	/**
	 * This test will lead to StackOverflow.  
	 * Someone please fix.
	 * 
	 */
	@Test
	@Ignore 
	public void cyclicTest() {
		
		
		SelfReferencing self = new SelfReferencing();
		SelfReferencing another = new SelfReferencing(self);
		self.setKaboom(another);
		
		ReflectUtil ref = new ReflectUtil(keyBuilder, vCipher,store);
		ref.encrypt(self);
		
		
	}
	
	private void createAndStoreMac(String alias) {
		SecretKey hmac_sha256 = new SecretKeySpec(new SecureRandom().generateSeed(16),"HmacSHA256");
		
		store = new VaultKeyStoreManager(getConfig());
		store.postSecret(alias, hmac_sha256);
		//Mac mac = store.getMac("mac1");
	}
	
	@Test
	public void encryptWithHashing() {
		
		createAndStoreMac("mac1");
		ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
		
		ByteShadow bs = ref.encrypt(new TestMessageWithHash("helloworld",11L));
		
		assertNotNull(bs.getHashedByteMap().get("toencrypt"));
		
		
	}
	
	
	/**
     * Mirror of {@link #testEncryptDecrpt()} with child object
     * @throws Exception
     */

     @Test

     public void testEncryptDecrptChild() throws Exception {

           //ByteShadow bs = new ByteShadow(new TestMessage("helloworld"));

           ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
           ByteShadow bs = ref.encrypt(new Child("helloworld",11L));
           assertTrue( bs.getShadowByteMap().get("toencrypt") != null);
           assertTrue(bs.getSrcObj() instanceof Child);
           assertTrue( ((Child)bs.getSrcObj()).getToencrypt() == null);
           Child hydrated = new Child();
           ref.decrypt(hydrated, bs);
           assertEquals("helloworld",hydrated.getToencrypt());
           assertEquals(new Long(11),hydrated.getANumber());

          

     }
     @Test
     public void testAddedFieldShadow() {
    	 ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
 		//Only difference from above is null Long
 		ByteShadow bs = ref.encrypt(new TestMessage("helloworld",null));
 		assertTrue( bs.getShadowByteMap().get("toencrypt") != null);
 		
 		//add some other non defined field
 		bs.getShadowByteMap().put("someMissingField", bs.getShadowByteMap().get("toencrypt"));
 		
 		
 		TestMessage hydrated = new TestMessage();
 		ref.decrypt(hydrated, bs);
 		assertEquals("helloworld",hydrated.getToencrypt());
     }

     @Test
     public void cloneAndNullifyTest() {
    	 TestMessage msg =new TestMessage("shouldbenull",0L);
    	 msg.setPlain("nonull");
    	 TestMessage cloned = (TestMessage)ReflectUtil.cloneAndNullify(msg);
    	 
    	 assertNull(cloned.getToencrypt());
    	 assertEquals("nonull",cloned.getPlain());
    	 
     }

}
