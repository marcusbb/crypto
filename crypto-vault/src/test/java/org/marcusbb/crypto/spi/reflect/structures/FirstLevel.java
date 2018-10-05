package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.NotCloneable;

public class FirstLevel implements CipherCloneable {
	
	private TestMessage embedded;
	
	private String notEncrypted;
	
	public FirstLevel(){}
	public FirstLevel(TestMessage embedded) {
		this.embedded = embedded;
	}
	public TestMessage getEmbedded() {
		return embedded;
	}


	public void setEmbedded(TestMessage embedded) {
		this.embedded = embedded;
	}


	public Object clone () {
		try {
			Object cloned = super.clone();
			if (embedded != null)
				((FirstLevel)cloned).embedded = (TestMessage)embedded.clone();
			return cloned;
		} catch (CloneNotSupportedException e) {
			throw new NotCloneable(e);
		}
	}


	public String getNotEncrypted() {
		return notEncrypted;
	}


	public void setNotEncrypted(String notEncrypted) {
		this.notEncrypted = notEncrypted;
	}
}