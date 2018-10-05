package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.CipherCloneable;

public class SelfReferencing extends CipherCloneable.DefaultCloneable   {
	
	private TestMessage testMessage;
	
	private SelfReferencing kaboom;
	public SelfReferencing(){}
	public SelfReferencing(SelfReferencing kaboom) {
		super();
		this.kaboom = kaboom;
	}

	public TestMessage getTestMessage() {
		return testMessage;
	}

	public void setTestMessage(TestMessage testMessage) {
		this.testMessage = testMessage;
	}

	public SelfReferencing getKaboom() {
		return kaboom;
	}

	public void setKaboom(SelfReferencing kaboom) {
		this.kaboom = kaboom;
	}
	
	
}