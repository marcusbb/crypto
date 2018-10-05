package org.marcusbb.crypto.spi.reflect;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;
import org.marcusbb.crypto.reflect.HashedField;
import org.marcusbb.crypto.reflect.ReflectException;

public class ReflectCloneable  {

	/**
	 * Utility method to clone objects deeply, based on traversing 
	 * the {@link EncryptedField} OR {@link HashedField} annotation.
	 * 
	 * @param cloneable
	 * @return
	 */
	private static ReflectConfigBuilder builder = ReflectConfigBuilder.getInstance();
	
	public static <T extends CipherCloneable>T clone(T cloneable) throws NoSuchFieldException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		//cache it
		builder.getOrBuildConfig(cloneable.getClass());
		//clone it
		T theClone = (T)cloneable.clone();
		//
		Map<String,ReflectConfig.FieldConfig> conf = builder.getOrBuildConfig(cloneable.getClass()).fieldConfig();
		for (String key: conf.keySet()) {
			ReflectConfig.FieldConfig fconf = conf.get(key);
			Field f = fconf.getField();
			if (CipherCloneable.class.isAssignableFrom(f.getType())) {
				CipherCloneable clonedChild = (CipherCloneable) ((CipherCloneable)builder.getTargetObject(cloneable, key)).clone();
				CipherCloneable parent = (CipherCloneable)builder.getTargeObjectParent(theClone, key);
				
				builder.setter(parent.getClass(), f).invoke(parent, clonedChild);
			}
			
		}
		return theClone;
	}
	public static <T extends CipherCloneable>T cloneNoThrow(T cloneable) {
		try {
			return clone(cloneable);
		}catch (Exception e) {
			throw new ReflectException(e);
		}
	}
	
}
