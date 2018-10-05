package org.marcusbb.crypto.spi.stub;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.marcusbb.crypto.KeyStoreManager;
import org.marcusbb.crypto.VersionedKey;
import org.marcusbb.crypto.VersionedKeyBuilder;
import org.marcusbb.crypto.exception.UnknownKeyVersion;
import org.marcusbb.crypto.key.VersionedKeySpec;
import org.marcusbb.crypto.key.VersionedKeyImpl;
import org.marcusbb.crypto.key.KeySigningUtils;


public abstract class AbstractVersionedKeyBuilder implements VersionedKeyBuilder {

	public int version = 1;
	KeyStoreManager keyStoreManager;
	public static String privatePath= "private/";
	public static String publicPath= "public/";
	
	public AbstractVersionedKeyBuilder(KeyStoreManager storeManager) {
		keyStoreManager = storeManager;
	}

	public AbstractVersionedKeyBuilder(KeyStoreManager storeManager, int version) {
		keyStoreManager = storeManager;
		this.version = version;
	}

	@Override
	public VersionedKey buildKey(String keyAlias, String ivSpecName) throws UnknownKeyVersion {
		if (keyAlias.startsWith(publicPath)) {
			return buildPublicKey(keyAlias.substring(publicPath.length()));
		}
		byte[] ivParameter = keyStoreManager.getIvParameter(ivSpecName);
		VersionedKeyImpl versionedKey = new VersionedKeyImpl(keyAlias, getSecretKeyVersion(keyAlias), ivParameter);

		SecretKey secretKey = keyStoreManager.getSecretKey(versionedKey.versionedKeyName());
		return new VersionedKeySpec(versionedKey, secretKey, new IvParameterSpec(ivParameter));
	}

	@Override
	public VersionedKey buildKey(String keyAlias, byte[] iv) throws UnknownKeyVersion {
		if (keyAlias.startsWith(publicPath)) {
			return buildPublicKey(keyAlias.substring(publicPath.length()));
		}
		VersionedKeyImpl versionedKey = new VersionedKeyImpl(keyAlias, getSecretKeyVersion(keyAlias), iv);
		SecretKey secretKey = keyStoreManager.getSecretKey(versionedKey.versionedKeyName());
		return new VersionedKeySpec(versionedKey, secretKey, new IvParameterSpec(iv));
	}

	@Override
	public VersionedKey buildKey(String keyAlias, String ivSpecName, byte[] versionedCipherText) throws UnknownKeyVersion {
		
		if (keyAlias.startsWith(privatePath)) {
			return buildPrivateKey(keyAlias.substring(privatePath.length()),versionedCipherText);
		}
		
		byte[] ivParameter = keyStoreManager.getIvParameter(ivSpecName);
		return buildKey(keyAlias, ivParameter, versionedCipherText);
	}


	@Override
	public VersionedKey buildKey(String keyAlias, byte[] iv, byte[] versionedCipherText) throws UnknownKeyVersion {
		
		if (keyAlias.startsWith(privatePath)) {
			return buildPrivateKey(keyAlias.substring(privatePath.length()),versionedCipherText);
		}
		
		KeySigningUtils.VersionedCipherText versionedCipherTextTuple =
				KeySigningUtils.extractVersion(versionedCipherText);

		VersionedKeyImpl versionedKey = new VersionedKeyImpl(keyAlias, versionedCipherTextTuple.getVersion(), iv);

		SecretKey secretKey = keyStoreManager.getSecretKey(versionedKey.versionedKeyName());
		return new VersionedKeySpec(versionedKey, secretKey, new IvParameterSpec(iv));
	}
	
	public VersionedKey buildKey(String keyAlias,byte []iv, InputStream in) throws UnknownKeyVersion {
		byte []header = new byte[3];
		try {
			in.read(header);
			int version = VersionedKeyImpl.version(header);
			VersionedKeyImpl versionedKey = new VersionedKeyImpl(keyAlias, version, iv);
			SecretKey secretKey = keyStoreManager.getSecretKey(versionedKey.versionedKeyName());
			return new VersionedKeySpec(versionedKey, secretKey, new IvParameterSpec(iv));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
	
	}
	public VersionedKey buildKey(String keyAlias,String ivAlias, InputStream in) throws UnknownKeyVersion {
		return buildKey(keyAlias,keyStoreManager.getIvParameter(ivAlias),in);		
	
	}
	public VersionedKey buildPrivateKey(String keyAlias, byte[] versionedCipherText) throws UnknownKeyVersion {
		
		KeySigningUtils.VersionedCipherText versionedCipherTextTuple =
				KeySigningUtils.extractVersion(versionedCipherText);

		VersionedKeyImpl versionedKey = new VersionedKeyImpl(keyAlias, versionedCipherTextTuple.getVersion(), null);

		PrivateKey key = keyStoreManager.getPrivateKey(versionedKey.versionedKeyName());
		return new VersionedKeySpec(versionedKey, key, null);
	}
	
	
	public VersionedKey buildPublicKey(String keyAlias) throws UnknownKeyVersion {
		
		VersionedKeyImpl versionedKey = new VersionedKeyImpl(keyAlias, getPublicKeyVersion(keyAlias), null);

		PublicKey key = keyStoreManager.getPublicKey( versionedKey.versionedKeyName() );
		return new VersionedKeySpec(versionedKey, key, null);
	}
	
	@Override
	public int getVersion() {
		return version;
	}
	
	public int getPublicKeyVersion(String keyAlias) {
		return version;
	}
	public int getSecretKeyVersion(String alias) {
		return version;
	}
}
