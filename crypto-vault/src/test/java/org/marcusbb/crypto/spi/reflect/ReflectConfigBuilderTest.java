package org.marcusbb.crypto.spi.reflect;

import static org.junit.Assert.*;

import java.lang.reflect.Method;

import org.junit.Test;
import org.marcusbb.crypto.reflect.ReflectException;
import org.marcusbb.crypto.spi.reflect.ReflectConfig;
import org.marcusbb.crypto.spi.reflect.ReflectConfigBuilder;
import org.marcusbb.crypto.spi.reflect.structures.Child;
import org.marcusbb.crypto.spi.reflect.structures.ChildWith;
import org.marcusbb.crypto.spi.reflect.structures.ErrorStruct;
import org.marcusbb.crypto.spi.reflect.structures.FirstLevel;
import org.marcusbb.crypto.spi.reflect.structures.TestMessage;
import org.marcusbb.crypto.spi.reflect.structures.TestMessageWithHash;

public class ReflectConfigBuilderTest {

	ReflectConfigBuilder builder = ReflectConfigBuilder.getInstance();
	
	
	@Test
	public void testFieldSize() throws NoSuchMethodException, SecurityException {
		ReflectConfig config = builder.buildConfig(TestMessage.class);
		assertEquals(2,config.fieldConfig().size());
		
		assertNotNull(config.fieldConfig().get("toencrypt"));
		assertNotNull(config.fieldConfig().get("aNumber"));
		Method getter = TestMessage.class.getMethod("getToencrypt");
		assertEquals(getter,config.fieldConfig().get("toencrypt").getGetter());
		Method setter = TestMessage.class.getMethod("setToencrypt",String.class);
		assertEquals(setter,config.fieldConfig().get("toencrypt").getSetter());
		
		config = builder.buildConfig(TestMessageWithHash.class);
		assertEquals(2,config.fieldConfig().size());
		assertEquals(1,config.hashFieldConfig().size());
		
		
		
	}
	@Test
	public void cacheTest() {
		ReflectConfig config = builder.getOrBuildConfig(TestMessage.class);
		
		ReflectConfig config2 = builder.getOrBuildConfig(TestMessage.class);
		
		assertEquals(config,config2);
	}
	
	
	@Test
	public void testCompositionSize() {
		ReflectConfig config = builder.buildConfig(FirstLevel.class);
		assertEquals(2,config.fieldConfig().size());
		
		
	}
	
	@Test(expected = ReflectException.class)
	public void methodErrors() {
		ReflectConfig config = builder.buildConfig(ErrorStruct.class);
		
	}
	
	@Test
	public void testChildFieldSize() throws NoSuchMethodException, SecurityException {
		ReflectConfig config = builder.buildConfig(Child.class);
		assertEquals(2,config.fieldConfig().size());
		Method getter = Child.class.getMethod("getToencrypt");
		assertEquals(getter,config.fieldConfig().get("toencrypt").getGetter());
		config = builder.buildConfig(ChildWith.class);
		assertEquals(3,config.fieldConfig().size());
	}

}
