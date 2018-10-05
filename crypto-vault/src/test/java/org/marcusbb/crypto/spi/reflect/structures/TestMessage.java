package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.ByteEncodable;
import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;

public class TestMessage extends CipherCloneable.DefaultCloneable   {
	
	
	static final String CREDIT_CARD_NAME = "aes_credit_card";
	static final String CREDIT_CARD_NUMBER_IV = "0123456789123456";
	
	@EncryptedField(iv = CREDIT_CARD_NUMBER_IV,alias = CREDIT_CARD_NAME )
	private String toencrypt;

	private String plain;
	
	@EncryptedField(iv = CREDIT_CARD_NUMBER_IV,alias = CREDIT_CARD_NAME, encodable = ByteEncodable.LongEncodable.class )
	private Long aNumber;
	
	public TestMessage() {}
	public TestMessage(String toencrypt,Long anum) {
		this.toencrypt = toencrypt;
		this.aNumber = anum;
	}
	public String getToencrypt() {
		return toencrypt;
	}

	public void setToencrypt(String toencrypt) {
		this.toencrypt = toencrypt;
	}
	public String getPlain() {
		return plain;
	}
	public void setPlain(String plain) {
		this.plain = plain;
	}
	public Long getANumber() {
		return aNumber;
	}
	public void setANumber(Long aNumber) {
		this.aNumber = aNumber;
	}
	
	
}