package org.marcusbb.crypto.spi.reflect;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.marcusbb.crypto.commons.KeyedVectoredSymmetricCipher;

public class ReflectConfig {

	/**
	 * {@link EncryptedField} config
	 */
	private Map<String, FieldConfig> fieldConfig = new HashMap<String, FieldConfig>();
	/**
	 * {@link HashedField} (tokenized) fields 
	 */
	private Map<String, FieldConfig> hashFieldConfig = new HashMap<>();
	
	protected void addConfig(String name, Method getter,Method setter,Field f,String keyAlias, String ivAlias) {
		fieldConfig.put(name, new FieldConfig(name,getter,setter,f,keyAlias,ivAlias));
	}
	protected void addHashFieldConfig(String name, Method getter,Method setter,Field f,String keyAlias, String ivAlias) {
		hashFieldConfig.put(name, new FieldConfig(name,getter,setter,f,keyAlias,ivAlias));
	}
	protected Map<String,FieldConfig> fieldConfig() {
		return fieldConfig;
	}
	protected Map<String,FieldConfig> hashFieldConfig() {
		return hashFieldConfig;
	}
	public static class FieldConfig {
		private String name;
		
		private Field field;
		
		private Method getter;
		
		private Method setter;

		//This is hard coded for now
		private String algorithm = KeyedVectoredSymmetricCipher.fullName;
		
		private String keyAlias;
		
		private String ivAlias;
				
		public FieldConfig(String name, Method getter, Method setter,Field f,String keyAlias, String ivAlias) {
			super();
			this.name = name;
			this.getter = getter;
			this.setter = setter;
			this.field = f;
			this.keyAlias = keyAlias;
			this.ivAlias = ivAlias;
		}

		public String getName() {
			return name;
		}

		public Method getGetter() {
			return getter;
		}

		public Method getSetter() {
			return setter;
		}
		public Field getField() {
			return field;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public void setAlgorithm(String algorithm) {
			this.algorithm = algorithm;
		}

		public String getKeyAlias() {
			return keyAlias;
		}

		public void setKeyAlias(String keyAlias) {
			this.keyAlias = keyAlias;
		}

		public String getIvAlias() {
			return ivAlias;
		}

		public void setIvAlias(String ivAlias) {
			this.ivAlias = ivAlias;
		}
		
	}
	
	public String asJson() {
		throw new UnsupportedOperationException("This is when you want a schema for later persistence");
	}
}
