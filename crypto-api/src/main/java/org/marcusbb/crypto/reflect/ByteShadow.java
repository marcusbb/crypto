package org.marcusbb.crypto.reflect;

import java.util.HashMap;
import java.util.Map;


public class ByteShadow {

	public static class Field {
		private String algorithm = "AES/CBC/PKCS5Padding";
		
		private String keyAlias;
		
		private String ivAlias;
		
		private byte []encrypted;
		
		public Field(String keyAlias,String ivAlias,byte []enc) {
			this.keyAlias = keyAlias;
			this.ivAlias = ivAlias;
			this.encrypted = enc;
		}
		public String getAlgorithm() {
			return algorithm;
		}
		public String getKeyAlias() {
			return keyAlias;
		}
		public String getIvAlias() {
			return ivAlias;
		}
		public byte[]getEnc() {
			return encrypted;
		}
	}
	//symmetric encrypted fields 
	private Map<String,Field> shadowByteMap = new HashMap<>();
	private Map<String,Field> hashedByteMap = new HashMap<>();
	
	//Depending on the type of operation will hold the new operations
	//encrypt: nulled fields
	//decrypt: hydrated fields
	private Object srcObj;
	
	public ByteShadow() {}
	public ByteShadow(Object src) {
		this.srcObj = src;
	}
	public Map<String, Field> getShadowByteMap() {
		return shadowByteMap;
	}

	public void setShadowByteMap(Map<String, Field> shadowByteMap) {
		this.shadowByteMap = shadowByteMap;
	}
	
	public Map<String, Field> getHashedByteMap() {
		return hashedByteMap;
	}
	public void setHashedByteMap(Map<String, Field> hashedByteMap) {
		this.hashedByteMap = hashedByteMap;
	}
	public Object getSrcObj() {
		return srcObj;
	}
	public void setSrcObj(Object srcObj) {
		this.srcObj = srcObj;
	}
	
	
}
