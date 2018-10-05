package org.marcusbb.crypto.spi.reflect;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.marcusbb.crypto.spi.reflect.ReflectCloneable;
import org.marcusbb.crypto.spi.reflect.structures.Child;
import org.marcusbb.crypto.spi.reflect.structures.FirstLevel;
import org.marcusbb.crypto.spi.reflect.structures.TestMessage;

public class ReflectCloneableTests {

	@Test
	public void testSimple() throws Exception {
		TestMessage msg = new TestMessage();
		msg.setToencrypt("hello");
		msg.setPlain("plain");
		TestMessage clone = ReflectCloneable.clone(msg);	
		assertEquals(msg.getToencrypt(),clone.getToencrypt());
		
	}
	@Test
	public void testClassComposition() throws Exception {
		TestMessage msg = new TestMessage();
		msg.setToencrypt("hello");
		msg.setPlain("plain");
		FirstLevel fl = new FirstLevel(msg);
		
		FirstLevel clone = ReflectCloneable.clone(fl);
		assertEquals(msg.getToencrypt(),clone.getEmbedded().getToencrypt());
	}
	
	@Test

    public void testHierarchy() throws Exception {

          Child child = new Child();
          child.setANumber(99L);
          child.setPlain("wayne");
          child.setToencrypt("greatone");
          Child clone = ReflectCloneable.clone(child);

          assertEquals(child.getANumber(),clone.getANumber());
          assertEquals(child.getPlain(),clone.getPlain());

         

    }

}
