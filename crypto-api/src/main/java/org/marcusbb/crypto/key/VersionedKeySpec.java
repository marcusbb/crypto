package org.marcusbb.crypto.key;


import java.security.Key;

import javax.crypto.spec.IvParameterSpec;

import org.marcusbb.crypto.VersionedKey;

/**
 * A decorator around {@link VersionedKey} metadata
 * containing materialzied key.
 */
public class VersionedKeySpec implements VersionedKey {

	private Key key;
	private IvParameterSpec ivParameterSpec;
	private VersionedKeyImpl versionedKey;

	public VersionedKeySpec(VersionedKeyImpl versionedKey, Key key, IvParameterSpec ivParameterSpec) {
		this.key = key;
		this.ivParameterSpec = ivParameterSpec;
		this.versionedKey = versionedKey;
	}

	public Key getKey() {
		return key;
	}

	public IvParameterSpec getIvParameterSpec() {
		return ivParameterSpec;
	}

	@Override
	public String keyHash() {
		return versionedKey.keyHash();
	}

	@Override
	public int headerLength() {
		return versionedKey.headerLength();
	}

	@Override
	public byte[] header() {
		return versionedKey.header();
	}

	@Override
	public IvParameterSpec iv() {
		return versionedKey.iv();
	}

	@Override
	public String versionedKeyName() {
		return versionedKey.versionedKeyName();
	}

	@Override
	public int getVersion() {
		return versionedKey.getVersion();
	}
}
