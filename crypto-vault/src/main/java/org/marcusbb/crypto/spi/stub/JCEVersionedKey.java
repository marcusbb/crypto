package org.marcusbb.crypto.spi.stub;

import javax.crypto.spec.IvParameterSpec;

import org.marcusbb.crypto.VersionedKey;

public class JCEVersionedKey implements VersionedKey {

	private String name;
	private int version;
	
	public JCEVersionedKey(String name,int version) {
		this.name = name;
		this.version = version;
	}
	public String keyHash() {
		return name + "_" + version;
	}

	public int headerLength() {
		return 0;
	}

	public byte[] header() {
		return new byte[0];
	}

	public IvParameterSpec iv() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String versionedKeyName() {
		return null;
	}

	@Override
	public int getVersion() {
		return 0;
	}

	@Override
	public int hashCode() {
		return keyHash().hashCode();
	}
	@Override
	public boolean equals(Object obj) {
		return keyHash().equals(((JCEVersionedKey)obj).keyHash());
	}
	
	
	

}
