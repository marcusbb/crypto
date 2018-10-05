package org.marcusbb.crypto.spi.vault;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.marcusbb.crypto.KeyStoreManager;
import org.marcusbb.crypto.exception.UnknownKeyVersion;
import org.marcusbb.crypto.spi.vault.AsymetricKeyMaterializer.KeyPairMaterializer;


/**
 * 
 * A Vault https://www.vaultproject.io implementation of {@link KeyStoreManager}.
 * It relies heavily on Apache's HttpClient for restful calls
 * to the Vault
 *
 */
public class VaultKeyStoreManager implements KeyStoreManager {

	
	private final VaultConfiguration vConfig;
	
	public static final String PRIV_KEY_PREFIX = "/secret/private";
	public static final String SECR_KEY_PREFIX = "/secret/secret";
	public static final String PUB_KEY_PREFIX = "/secret/public";
	public static final String IV_PREFIX = "/secret/iv";
	public static final String INIT_PREFIX = "/secret/init";
	
	public static final String MATERIAL_KEY = "material";
	public static final String ALG_KEY = "algorithm";
	public static final String ALG_PROVIDER = "provider";
	public static final String KEY_SIZE = "size";
	
	public VaultKeyStoreManager(VaultConfiguration vaultConfig) {
		this.vConfig = vaultConfig;
		
	}
	
	@Override
	public PrivateKey getPrivateKey(String alias) {

		Map<String,byte[]> keyData = getKeyData(PRIV_KEY_PREFIX, alias);
		byte []clBytes = keyData.get("_materializer_className");
		String clName = KeyPairMaterializer.class.getName();
		if (clBytes != null)
			 clName = new String(clBytes);
		
		try {
			AsymetricKeyMaterializer materializer = (AsymetricKeyMaterializer) Class.forName(clName).newInstance();
	        
			return materializer.materializePrivate(keyData);
		}catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		
	}

	@Override
	public PublicKey getPublicKey(String alias) {

		Map<String,byte[]> keyData = getKeyData(PUB_KEY_PREFIX, alias);
		byte []clBytes = keyData.get("_materializer_className");
		String clName = KeyPairMaterializer.class.getName();
		if (clBytes != null)
			 clName = new String(clBytes);
		
				
		try {
			AsymetricKeyMaterializer materializer = (AsymetricKeyMaterializer) Class.forName(clName).newInstance();
	        
			return materializer.materializePublic(keyData);
		}catch (Exception e) {
			throw new RuntimeException(e);
		}
		
	}

	@Override
	public SecretKey getSecretKey(String alias) {
		
		Map<String,byte[]> keyData = getKeyData(SECR_KEY_PREFIX, alias);
		
		return new SecretKeySpec(keyData.get(MATERIAL_KEY),new String(keyData.get(ALG_KEY)));
		
	}
	public Map<String,byte[]> getKeyData(String prefix,String alias) {
		
		VaultHttpClient client = new VaultHttpClient(vConfig);
		try {
			Map<String,byte[]> map = client.get(prefix + "/" + alias);
			
			return map;
			
		} catch (Exception e) {
			//e.printStackTrace();
			//TODO: add a specific runtime exception for keystore concerns
			throw new RuntimeException(e); 
		}
		
	}
	/**
	 * Get the versions associated with this keyname,
	 * Vault 0.5.1 is required.
	 * 
	 * @param keyName
	 * @param pathPrefix
	 * @return
	 */
	public Integer[] getVersions(String keyName,String pathPrefix) {
		
		String []names = getKeyNames(pathPrefix);
		ArrayList<Integer> versions = new ArrayList<Integer>();
		Pattern p = Pattern.compile("v(\\d+)_" + keyName);
		if (names == null)
			return null;
		for (String name:names) {
			if (name.endsWith(keyName)) { 
				Matcher m = p.matcher(name);
				if (m.find()) {
					versions.add(Integer.parseInt(m.group(1)));
				}
			}
		}
		return versions.toArray(new Integer[0]);
	}
	
	/**
	 * Persist in vault a new asymmetric key with the given materializer
	 * 
	 * @param privateKeyPath
	 * @param publicKeyPath
	 * @param materializer
	 * @throws KeyStoreException
	 */
	public void postAsymmetricKey(String privateKeyPath, String publicKeyPath, AsymetricKeyMaterializer materializer)
			throws KeyStoreException {
		VaultHttpClient client = new VaultHttpClient(vConfig);
		try {
			// private
			Map<String, byte[]> map = materializer.privatePortion();
			map.put("_materializer_className", materializer.getClass().getName().getBytes());
			client.post(privateKeyPath, map);
			// public
			map = materializer.publicPortion();
			map.put("_materializer_className", materializer.getClass().getName().getBytes());
			client.post(publicKeyPath, map);
		} catch (Exception e) {
			throw new KeyStoreException(e);
		}
	}

	public void createOrUpdateKeyPair(String algorithm,String keyName) throws NoSuchAlgorithmException,KeyStoreException {
		
		Integer[] versions = getVersions(keyName,PRIV_KEY_PREFIX);
		String vKeyName = "v1_" + keyName;
		int keySize = 1024;
		
		if (versions != null && versions.length >0) {
			Arrays.sort(versions);
			String curVer = "v" + versions[versions.length-1] + "_" + keyName;
			Map<String,byte[]> keyData = getKeyData(PRIV_KEY_PREFIX,curVer);
			keySize = ByteBuffer.wrap( keyData.get(KEY_SIZE) ).getInt();
			vKeyName = "v" + (versions[versions.length-1] + 1) + "_" + keyName;
		}
		KeyPairMaterializer rsakey = new KeyPairMaterializer(algorithm,keySize);
		postAsymmetricKey(VaultKeyStoreManager.PRIV_KEY_PREFIX + "/" + vKeyName,VaultKeyStoreManager.PUB_KEY_PREFIX + "/" + vKeyName, rsakey);
		
		
	}
	
	/**
	 * Return a list key names on a given path
	 * @param path
	 * @return
	 */
	public String[] getKeyNames(String path) {
		VaultHttpClient client = new VaultHttpClient(vConfig);
		HashMap<String, String> qs = new HashMap<String, String>();
		qs.put("list", "true");
		String []str = null;
		try {
			VaultListData data = client.get(path, qs);
			str = data.getData().getKeys();

		} catch (Exception e) {
			//e.printStackTrace();
			//TODO: add a specific runtime exception for keystore concerns
			throw new RuntimeException(e); 
		}

		return str;
	}
	/**
	 * First find a keyname, if found attempt to generate a new key with provided algorithm and increment version.
	 * If IV is provided then also persist iv into keystore
	 * 
	 * @param algorithm
	 * @param keyName
	 * @param iv
	 * @throws NoSuchAlgorithmException 
	 */
	public void createOrUpdateSecretVersion(String algorithm,String keyName) throws NoSuchAlgorithmException {
		Integer []versions = null;
		
		versions = getVersions(keyName, SECR_KEY_PREFIX);
		
		String pathName = VaultKeyStoreManager.SECR_KEY_PREFIX + "/v1_" + keyName;
		if (versions !=null && versions.length > 0) {
			//sort the versions
			Arrays.sort(versions);
			pathName = VaultKeyStoreManager.SECR_KEY_PREFIX + "/v" + (versions[versions.length-1]+1 ) + "_" + keyName;
		}
		KeyGenerator kg = KeyGenerator.getInstance(algorithm);
		SecretKey key = kg.generateKey();
		postKey(pathName,key,algorithm);
		
		
	}
	public void createOrUpdateIv(String ivName,byte []ivMaterial) {
		
		
		postKey(VaultKeyStoreManager.IV_PREFIX + "/" + ivName, new SecretKeySpec(ivMaterial,"AES"));
	}
	/**
	 * Same as above, with default AES algorithm
	 * @param keyName
	 * @param iv
	 * @throws NoSuchAlgorithmException 
	 */
	public void createOrUpdateSecretVersion(String keyName) throws NoSuchAlgorithmException {
		createOrUpdateSecretVersion("AES", keyName);
		
	}
	//Post secret key
	public void postKey(String path,Key key,String provider) {

		VaultHttpClient client = new VaultHttpClient(vConfig);
		try {
			Map<String,byte[]> keyMap = new HashMap<String, byte[]>();
			keyMap.put(MATERIAL_KEY, key.getEncoded());
			keyMap.put(ALG_KEY, key.getAlgorithm().getBytes() );
			if (provider !=null) keyMap.put(ALG_PROVIDER,provider.getBytes());
			client.post(path, keyMap);
			
		} catch (Exception e) {
			e.printStackTrace();
			//TODO: add a specific runtime exception for keystore concerns
			throw new RuntimeException(e); 
		}
	}
	public void postKey(String path,Key key) {
		postKey(path,key,null);
	}
	
	public void postSecret(String alias,Key secretKey) {
		VaultHttpClient client = new VaultHttpClient(vConfig);
		try {
			Map<String,byte[]> keyMap = new HashMap<String, byte[]>();
			keyMap.put(MATERIAL_KEY, secretKey.getEncoded());
			keyMap.put(ALG_KEY, secretKey.getAlgorithm().getBytes() );
			client.post(SECR_KEY_PREFIX + "/" + alias, keyMap);
			
		} catch (Exception e) {
			e.printStackTrace();
			//TODO: add a specific runtime exception for keystore concerns
			throw new RuntimeException(e); 
		}
	}

	@Override
	public byte[] getIvParameter(String alias) {
		Map<String,byte[]> keyData = getKeyData(IV_PREFIX, alias);
		
		return keyData.get(MATERIAL_KEY);
	}

	@Override
	public void load() throws IOException, KeyStoreException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Mac getMac(String secretkeyAlias) {
		SecretKey sk = getSecretKey(secretkeyAlias);
		try {		
			Mac mac = Mac.getInstance(sk.getAlgorithm());
			mac.init(sk);
			return mac;
		}catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
