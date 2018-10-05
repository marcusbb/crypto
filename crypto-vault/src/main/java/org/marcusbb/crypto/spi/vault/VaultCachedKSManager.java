package org.marcusbb.crypto.spi.vault;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class VaultCachedKSManager extends VaultKeyStoreManager {

	protected Cache<String, Map<String,byte[]>> keyCache = null;
	protected Cache<String, Integer[]> vCache = null;
	
	public VaultCachedKSManager(VaultConfiguration vaultConfig,int ttl,TimeUnit ttlUnits,int maxSize) {
		super(vaultConfig);
		this.keyCache = CacheBuilder.newBuilder()
				.maximumSize(maxSize)
			    .expireAfterAccess(ttl, ttlUnits)
			    .build();
		this.vCache = CacheBuilder.newBuilder()
			    .expireAfterAccess(ttl, ttlUnits)
			    .build();

	}

	@Override
	public Map<String, byte[]> getKeyData(String prefix, String alias) {
		String key = prefix + "/" + alias;
		Map<String,byte []> obj = keyCache.getIfPresent(key);
		if ( obj != null)
			return obj;
		else {
			obj = super.getKeyData(prefix, alias);
			if (obj != null)
				keyCache.put(key, obj);
		}
		return obj;
	}

	/**
	 * Cache the versions, using same mechanisms as keycache
	 */
	@Override
	public Integer[] getVersions(String keyName, String pathPrefix) {
		String key = pathPrefix + "/" + keyName;
		Integer []versions = vCache.getIfPresent(key);
		if (versions == null) {
			versions = super.getVersions(keyName, pathPrefix);
			if (versions != null) {
				Arrays.sort(versions);
				vCache.put(key, versions);
			}
		}
		return versions;
	}
	
	
	

}
