package org.marcusbb.crypto.spi.stub;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.marcusbb.crypto.VersionedKeyBuilder;
import org.marcusbb.crypto.exception.UnknownKeyVersion;
import org.marcusbb.crypto.key.VersionedKeySpec;

//TODO: remove?
public class JCEVersionedKeyBuilder extends AbstractVersionedKeyBuilder implements VersionedKeyBuilder {

	KeyStore ks = null;
	private String password;
	private String fileName;
	private int version = 1;
	private Map<JCEVersionedKey, Key> keyMap = new HashMap<JCEVersionedKey, Key>();
	private static String CIPHER_ALGORITHM = "AES";
	
	public JCEVersionedKeyBuilder(String fileName, String password)throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException  {
		super(new FileBasedKeyStoreManager());
		ks = getOrCreateKS(fileName, password);
		//Needs to be stored for key storage
		this.password = password;
		this.fileName = fileName;
	}
	public JCEVersionedKeyBuilder(String fileName, String password,int version)throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException  {
		this(fileName,password);
		this.version = version;
	}
	
	public VersionedKeySpec buildKey(String name, String ivSpecName) throws UnknownKeyVersion {
		//ignore the ivSpecName
		JCEVersionedKey keyVersion = new JCEVersionedKey(name, version);
		keyMap.get(keyVersion);
		
		//return keyVersion;

		return null;
	}
	
	@Override
	public VersionedKeySpec buildKey(String keyAlias, byte[] iv, byte[] versionedCipherText) throws UnknownKeyVersion {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public VersionedKeySpec buildKey(String name, byte[] iv) throws UnknownKeyVersion {
		return null;
	}

	@Override
	public VersionedKeySpec buildKey(String keyAlias, String ivSpecName, byte[] versionedCipherText) throws UnknownKeyVersion {
		return null;
	}

	public synchronized void storeKey(JCEVersionedKey keyVersion, Key key) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());

		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(KeyGenerator.getInstance(CIPHER_ALGORITHM).generateKey());
		
		ks.setEntry(keyVersion.keyHash(), skEntry, protParam);
		FileOutputStream fos = new FileOutputStream(new File(fileName));
		ks.store(fos, password.toCharArray());
		fos.close();
	}

	/**
	 * Gets and stores cipher (if not found).
	 * 
	 * @param keyVersion
	 * @param mode
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public Cipher getCipher(JCEVersionedKey keyVersion, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, CertificateException, IOException {
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		Key key = keyMap.get(keyVersion);
		if (key == null) {
			key = KeyGenerator.getInstance(CIPHER_ALGORITHM).generateKey();
			storeKey(keyVersion,key);
		}
		cipher.init(mode, key );
		
		return cipher;
	}

	public void load() throws IOException {

		try {
			Enumeration<String> aliases = ks.aliases();
			for (; aliases.hasMoreElements(); ) {
				String alias = (String) aliases.nextElement();

				// Does alias refer to a private key?
				boolean b = ks.isKeyEntry(alias);
				try {
					Key key = ks.getKey(alias, password.toCharArray());
					keyMap.put(new JCEVersionedKey(alias, version), key);
				} catch (Exception e) {
					throw new KeyStoreException(e.getMessage(), e);
				}

			}
		} catch (KeyStoreException ex) {
			throw new RuntimeException("KeyStoreException");
		}

	}

	public int getVersion() {
		return version;
	}
	
	
	public static KeyStore getOrCreateKS(String fileName, String pw) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException  {
		File file = new File(fileName);
		
		//default instance can't store secret keys
		//KeyStore.getInstance(KeyStore.getDefaultType());
		
		final KeyStore keyStore = KeyStore.getInstance("JCEKS");
		if (file.exists()) {
			// .keystore file already exists => load it
			keyStore.load(new FileInputStream(file), pw.toCharArray());
		} else {
			// .keystore file not created yet => create it
			keyStore.load(null, null);
			FileOutputStream fos = new FileOutputStream(fileName);
			keyStore.store(fos, pw.toCharArray());
			fos.close();
		}

		return keyStore;
	}
	
	public Key cachedKey(JCEVersionedKey key) {
		return keyMap.get(key);
	}
}
