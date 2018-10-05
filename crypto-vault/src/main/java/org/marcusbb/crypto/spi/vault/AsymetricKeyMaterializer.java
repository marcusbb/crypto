package org.marcusbb.crypto.spi.vault;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public interface AsymetricKeyMaterializer {

	public PrivateKey materializePrivate(Map<String, byte[]> storedBytes) throws KeyStoreException;

	public PublicKey materializePublic(Map<String, byte[]> storedBytes) throws KeyStoreException;

	public Map<String, byte[]> privatePortion() throws KeyStoreException;
	
	public Map<String, byte[]> publicPortion() throws KeyStoreException;

	public static class KeyPairMaterializer implements AsymetricKeyMaterializer {

		private int initKeySize = 1024;
		private String algorithm = "RSA";
		private PrivateKey privateKey;
		private PublicKey publicKey;
		
		public KeyPairMaterializer() {
		}
		public KeyPairMaterializer(String algorithm,int keySize) {
			this.algorithm = algorithm;
			this.initKeySize = keySize;
		}
		public KeyPairMaterializer(int keySize) {
			this.initKeySize = keySize;
		}
		
		protected synchronized void generate() throws KeyStoreException {
			if (privateKey == null || publicKey ==null)
			try {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			    keyGen.initialize(initKeySize);
			    KeyPair pair = keyGen.generateKeyPair();
				privateKey = pair.getPrivate();
				
				publicKey = pair.getPublic();
				
			}catch (Exception e) {
				throw new KeyStoreException(e);
			}
		}

		
		@Override
		public PublicKey materializePublic(Map<String, byte[]> storedBytes) throws KeyStoreException {
			
			X509EncodedKeySpec spec = new X509EncodedKeySpec(storedBytes.get(VaultKeyStoreManager.MATERIAL_KEY));
			
			try {
				return KeyFactory.getInstance(algorithm).generatePublic(spec);
			} catch (Exception e) {
				throw new KeyStoreException(e);
			}
		}
		@Override
		public PrivateKey materializePrivate(Map<String, byte[]> storedBytes) throws KeyStoreException {
			try {
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(storedBytes.get(VaultKeyStoreManager.MATERIAL_KEY));
								
				KeyFactory fact = KeyFactory.getInstance(algorithm);
				
				return fact.generatePrivate(spec);
			} catch (Exception e) {
				throw new KeyStoreException(e);
			}
		}

		@Override
		public Map<String, byte[]> privatePortion() throws KeyStoreException {
			generate();
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
			HashMap <String,byte[]> stored = new HashMap<String,byte[]>();
			stored.put(VaultKeyStoreManager.ALG_KEY, algorithm.getBytes());
			stored.put(VaultKeyStoreManager.MATERIAL_KEY, spec.getEncoded());
			stored.put(VaultKeyStoreManager.KEY_SIZE, ByteBuffer.allocate(4).putInt(initKeySize).array());
			return stored;
		}
		@Override
		public Map<String, byte[]> publicPortion() throws KeyStoreException {
			generate();
			X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
			HashMap <String,byte[]> stored = new HashMap<String,byte[]>();
			stored.put(VaultKeyStoreManager.ALG_KEY, algorithm.getBytes());
			stored.put(VaultKeyStoreManager.MATERIAL_KEY, spec.getEncoded());
			stored.put(VaultKeyStoreManager.KEY_SIZE, ByteBuffer.allocate(4).putInt(initKeySize).array());
			return stored;
		}
		

	}
}
