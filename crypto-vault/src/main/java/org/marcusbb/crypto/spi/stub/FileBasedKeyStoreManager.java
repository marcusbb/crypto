package org.marcusbb.crypto.spi.stub;


import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.marcusbb.crypto.KeyStoreManager;
import org.marcusbb.crypto.commons.ByteUtils;

public class FileBasedKeyStoreManager implements KeyStoreManager {

	private Configuration config;

	public FileBasedKeyStoreManager() {
		init();
	}

	private void init() {
		try {
			if (config == null) {
				config = new PropertiesConfiguration("keystore.properties");
			}
		} catch (ConfigurationException e) {
			throw new RuntimeException();
		}
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return null;
	}

	@Override
	public PublicKey getPublicKey(String alias) {
		return null;
	}

	@Override
	public SecretKey getSecretKey(String alias) {
		byte[] decodedKey = ByteUtils.base64Decode(config.getString(alias));
		SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return key;
	}

	@Override
	public byte[] getIvParameter(String alias) {
		return ByteUtils.base64Decode(config.getString(alias));

	}

	@Override
	public void load() throws IOException, KeyStoreException {

	}

	@Override
	public Mac getMac(String secretkeyAlias) {
		return null;
	}


}
