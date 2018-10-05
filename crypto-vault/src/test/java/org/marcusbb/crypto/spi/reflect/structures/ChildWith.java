package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.EncryptedField;

public class ChildWith extends TestMessage {

	@EncryptedField(alias="useful", iv="asif")
	private String anotherEncrypted;
	
	public ChildWith() {
		super();
		// TODO Auto-generated constructor stub
	}

	public ChildWith(String toencrypt, Long anum) {
		super(toencrypt, anum);
		// TODO Auto-generated constructor stub
	}

	public String getAnotherEncrypted() {
		return anotherEncrypted;
	}

	public void setAnotherEncrypted(String anotherEncrypted) {
		this.anotherEncrypted = anotherEncrypted;
	}
	
	
	
}
