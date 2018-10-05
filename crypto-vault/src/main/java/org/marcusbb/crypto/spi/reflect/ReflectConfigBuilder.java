package org.marcusbb.crypto.spi.reflect;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;
import org.marcusbb.crypto.reflect.HashedField;
import org.marcusbb.crypto.reflect.ReflectException;

public class ReflectConfigBuilder {

	
	private static final String EMPTY_ROOT = "";
	private static final Object[] EMPTY_OBJ_ARR = new Object[]{};
	
	private static Map<Class<?>, ReflectConfig> config = new HashMap<Class<?>, ReflectConfig>();

	private static ReflectConfigBuilder inst = new ReflectConfigBuilder();
			
	private ReflectConfigBuilder() {
		
	}
	public static ReflectConfigBuilder getInstance() {
		return inst;
	}
	public ReflectConfig getOrBuildConfig(Class<? extends CipherCloneable> cl) {
		ReflectConfig conf = config.get(cl);
		if (conf == null) {
			conf = buildConfig(cl);
			config.put(cl, conf);
		}
		return conf;
	}

	public ReflectConfig buildConfig(Class<? extends CipherCloneable> cl) {
		ReflectConfig config = new ReflectConfig();

		discover(cl, 1, config, EMPTY_ROOT);

		return config;
	}
	
	private void discover(Class<?> cl, int depth, ReflectConfig config, String root) {

		//recurse to top of class hierarchy
		if (cl.getSuperclass()!= null) {
			discover(cl.getSuperclass(),depth,config,root);
		}
		Field[] fields = cl.getDeclaredFields();
		String prefix = EMPTY_ROOT.equals(root) ? EMPTY_ROOT : root + ".";

		for (Field f : fields) {
			String prefixedName = prefix + f.getName();
			if (CipherCloneable.class.isAssignableFrom(f.getType())) {
				try {

					discover(f.getType(), depth + 1, config, prefixedName);

				} catch (Exception e) {
					throw new ReflectException(e);
				}
			}
			EncryptedField ef = f.getAnnotation(EncryptedField.class);
			if (ef != null) {

				try {

					config.addConfig(prefixedName, getter(cl, f.getName()), setter(cl, f), f,ef.alias(),ef.iv());

				} catch (Exception e) {
					throw new ReflectException(e);
				}

			}
			HashedField hf = f.getAnnotation(HashedField.class);
			if (hf != null) {
				try {

					config.addHashFieldConfig(prefixedName, getter(cl, f.getName()), setter(cl, f), f,hf.alias(),null);

				} catch (Exception e) {
					throw new ReflectException(e);
				}
			}

		}

	}

	// boolean (is) not supported
	protected Method getter(Class<?> cl, String fieldName) {
		String methodSuffix = fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
		try {			
			return cl.getMethod("get" + methodSuffix);
		} catch (NoSuchMethodException e) {
			throw new ReflectException("You have specified an annotated field " + 
		fieldName + ", but not provided the apppropriate getter get" + methodSuffix,e);
		} catch (SecurityException e) {
			throw new ReflectException(e);
		}

	}

	protected Method setter(Class<?> cl, Field f) {
		String fieldName = f.getName();
		String methodSuffix = fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
		try {
			
			return cl.getMethod("set" + methodSuffix, f.getType());
		} catch (NoSuchMethodException e) {
			throw new ReflectException("You have specified an annotated field " + 
					fieldName + ", but not provided the apppropriate setter set" + methodSuffix,e);
		} catch (SecurityException e) {
			throw new ReflectException(e);
		}
	}
	
	private Map<ClassString, String[]> cachedStrings = new HashMap<>();
	private static class ClassString {
		ClassString(Class<?> cl,String st) {
			this.cl = cl;
			this.dottedString = st;
		}
		static ClassString get(Class<?> cl, String st) {
			return new ClassString(cl,st);
		}
		Class<?> cl;
		String dottedString;
		public int hashCode() {
			return cl.hashCode()/7 + dottedString.hashCode()/31;
		}
		public boolean equals(Object obj) {
			return ((ClassString)obj).cl.equals(cl) && ((ClassString)obj).dottedString.equals(dottedString);
		}
	}
	private String []getSplit(Class<?>cl, String name) {
		ClassString cs = ClassString.get(cl, name);
		String []split = cachedStrings.get(cs);
		if (split == null) {
			split = name.split("\\.");
			if (split.length == 0) {
				split = new String[1];split[0] = name;
			}
			cachedStrings.put(cs, split);
		}
		return split;
		
	}
	
	protected Object getTargeObjectParent(Object rootObj,String name) throws NoSuchFieldException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String[] splits = getSplit(rootObj.getClass(), name);
		if (splits.length == 1) {
			return rootObj;
		}else {
				
			return getTargetObject(rootObj,name.substring(0, name.lastIndexOf('.')));
			
		}
			
	}
	protected Object getTargetObject(Object rootObj, String name) throws NoSuchFieldException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		Object obj = rootObj;
		
		Class<?> targetClass = rootObj.getClass();
		String []hierarchy = getSplit(targetClass,name);
		String targetName = name;
		for (String level:hierarchy) {
			if (obj == null)
				return null;
			Method mget = getter(targetClass,level);
			obj = mget.invoke(obj, EMPTY_OBJ_ARR);
			
			//targetClass = targetClass.getDeclaredField(level).getType();
			targetClass = mget.getReturnType();
			targetName = level;
		}
		return obj;
	}
	

}
