package org.marcusbb.crypto.spi.reflect;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.marcusbb.crypto.KeyStoreManager;
import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.VersionedKeyBuilder;
import org.marcusbb.crypto.reflect.ByteShadow;
import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;
import org.marcusbb.crypto.reflect.HashedField;
import org.marcusbb.crypto.reflect.ReflectException;
import org.marcusbb.crypto.reflect.ReflectVersionedCipher;


public class ReflectUtil implements ReflectVersionedCipher {

	private VersionedCipher cipher;
	private VersionedKeyBuilder keyBuilder;
	private KeyStoreManager keyStore;
	
	
	private static final Object[] NULL_OBJ_ARR =new Object[]{null};
	ReflectConfigBuilder builder = ReflectConfigBuilder.getInstance();
	
	public ReflectUtil(VersionedKeyBuilder keyBuilder, VersionedCipher cipher,KeyStoreManager keyStore) {
		this.cipher = cipher;
		this.keyBuilder = keyBuilder;
		this.keyStore = keyStore;
	}
	@Override
	public ByteShadow encrypt(CipherCloneable obj)  {
		
		ByteShadow shadow = new ByteShadow();
		Class<? extends CipherCloneable> cl = obj.getClass();
		Object clone = obj.clone();
		
		//through discovery
		Map<String,ReflectConfig.FieldConfig> conf = builder.getOrBuildConfig(cl).fieldConfig();
		for (String key: conf.keySet()) {
			ReflectConfig.FieldConfig fconf = conf.get(key);
			if (fconf != null) {
				try {
					Field f = fconf.getField();
					//Object gotObj = fconf.getGetter().invoke(obj, EMPTY_OBJ_ARR);
					Object gotObj = builder.getTargetObject(obj, key);
					EncryptedField ef = f.getAnnotation(EncryptedField.class);
					byte []encodedbytes = null;
					if (gotObj!=null) {
						 encodedbytes = ef.encodable().newInstance().encode(gotObj);					
						 
						 shadow.getShadowByteMap().put(
							key, 
							new ByteShadow.Field(fconf.getKeyAlias(),fconf.getIvAlias(), cipher.encrypt( keyBuilder.buildKey(ef.alias(), ef.iv()),encodedbytes) ));
					}
					Method setter = fconf.getSetter();
					Object targetClone = builder.getTargeObjectParent(clone, key);
					if (targetClone !=null) 
						setter.invoke(targetClone,NULL_OBJ_ARR);
					
				} catch (SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | InstantiationException | NoSuchFieldException e) {
					throw new ReflectException(e);
				}
			}
			
		}
		//hashed values - possible re-arrangement with above
		conf = builder.getOrBuildConfig(cl).hashFieldConfig();
		for (String key: conf.keySet()) {
			ReflectConfig.FieldConfig fconf = conf.get(key);
			try {
				Field f = fconf.getField();
				//Object gotObj = fconf.getGetter().invoke(obj, EMPTY_OBJ_ARR);
				Object gotObj = builder.getTargetObject(obj, key);
				//HashedField ef = f.getDeclaredAnnotation(HashedField.class);
				HashedField ef = f.getAnnotation(HashedField.class);
				byte []encodedbytes = null;
				if (gotObj!=null) {
					 encodedbytes = ef.encodable().newInstance().encode(gotObj);					
					 
					 shadow.getHashedByteMap().put(
						key, 
						new ByteShadow.Field(fconf.getKeyAlias(),fconf.getIvAlias(),keyStore.getMac(ef.alias()).doFinal(encodedbytes) ));
				}
				Method setter = fconf.getSetter();
				Object targetClone = builder.getTargeObjectParent(clone, key);
				if (targetClone !=null) 
					setter.invoke(targetClone,NULL_OBJ_ARR);
				
			} catch (SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | InstantiationException | NoSuchFieldException e) {
				throw new ReflectException(e);
			}
			
		}
		shadow.setSrcObj(clone);
		
		return shadow;
		
	}
	/**
	 * Cloned object is nullified
	 * @param obj
	 * @return
	 * @throws InvocationTargetException 
	 * @throws IllegalArgumentException 
	 * @throws IllegalAccessException 
	 * @throws SecurityException 
	 * @throws NoSuchFieldException 
	 */
	public static CipherCloneable cloneAndNullify(CipherCloneable obj) {
		
		ReflectConfigBuilder builder = ReflectConfigBuilder.getInstance();
		
		
		Class<? extends CipherCloneable> cl = obj.getClass();
		CipherCloneable clone = (CipherCloneable)obj.clone();
		try {
			
			Map<String,ReflectConfig.FieldConfig> conf = builder.getOrBuildConfig(cl).fieldConfig();
			for (String key: conf.keySet()) {
				ReflectConfig.FieldConfig fconf = conf.get(key);
				if (fconf != null) {
					Object targetClone = builder.getTargeObjectParent(clone, key);
					Method setter = fconf.getSetter();
					if (targetClone !=null) 
						setter.invoke(targetClone,NULL_OBJ_ARR);
				}
			}
		}catch (InvocationTargetException| IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException e) {
			throw new ReflectException(e);
		}
		return clone;
	}
	
	@Override
	public void decrypt(CipherCloneable obj, ByteShadow shadow) {
		
		Class<? extends CipherCloneable> cl = obj.getClass();
		Map<String,ReflectConfig.FieldConfig> conf = builder.getOrBuildConfig(cl).fieldConfig();
		
		for (String fieldName:shadow.getShadowByteMap().keySet()) {

			ReflectConfig.FieldConfig fconf = conf.get(fieldName);
			if (fconf !=null) {
				EncryptedField af =  fconf.getField().getAnnotation(EncryptedField.class);
				byte []be = shadow.getShadowByteMap().get(fieldName).getEnc();
				
				try {
					
					byte []decrypted = cipher.decrypt(keyBuilder.buildKey(af.alias(), af.iv(), be),be) ;
					
					Object decoded = af.encodable().newInstance().decode(decrypted);
					Object targetObj = builder.getTargeObjectParent(obj, fieldName);
					fconf.getSetter().invoke(targetObj, decoded);
					
				}catch(Exception e) {
					throw new ReflectException(e);
				}
			}
			
		}
		
				
	}
	
	public ReflectConfigBuilder getRelectConfigBuilder() {
		return builder;
	}
	
	
}
