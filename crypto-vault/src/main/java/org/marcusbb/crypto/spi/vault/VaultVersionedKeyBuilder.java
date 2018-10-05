package org.marcusbb.crypto.spi.vault;

import java.util.Arrays;

import org.marcusbb.crypto.KeyStoreManager;
import org.marcusbb.crypto.spi.stub.AbstractVersionedKeyBuilder;

public class VaultVersionedKeyBuilder extends AbstractVersionedKeyBuilder {

	private VaultKeyStoreManager keyStore;
	private boolean latestKey = true; 
	
	public VaultVersionedKeyBuilder(KeyStoreManager storeManager, int version) {
		super(storeManager, version);
		this.keyStore = (VaultKeyStoreManager)storeManager;
		this.latestKey = false;
	}

	public VaultVersionedKeyBuilder(KeyStoreManager storeManager) {
		super(storeManager);
		this.keyStore = (VaultKeyStoreManager)storeManager;
	}

	/**
	 * Always get the latest key version not one provided by default by key builder
	 */
	@Override
	public int getPublicKeyVersion(String keyAlias) {
		Integer []versions = keyStore.getVersions(keyAlias, VaultKeyStoreManager.PUB_KEY_PREFIX);
		if (latestKey && versions != null && versions.length > 0) {
			Arrays.sort(versions);
			return versions[versions.length-1];
		}
		return super.getPublicKeyVersion(keyAlias);
	}
	/**
	 * Always get the latest key version not one provided by default by key builder
	 */
	@Override
	public int getSecretKeyVersion(String keyAlias) {
		Integer []versions = keyStore.getVersions(keyAlias, VaultKeyStoreManager.SECR_KEY_PREFIX);
		if (latestKey && versions != null && versions.length > 0) {
			Arrays.sort(versions);
			return versions[versions.length-1];
		}
		return super.getSecretKeyVersion(keyAlias);
	}
	
}
