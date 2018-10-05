package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.ByteEncodable;
import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;
import org.marcusbb.crypto.reflect.HashedField;
import org.marcusbb.crypto.spi.reflect.ReflectUtilTest;

public class TestMessageWithHash extends CipherCloneable.DefaultCloneable   {
	
	@EncryptedField(iv = TestMessage.CREDIT_CARD_NUMBER_IV,alias = TestMessage.CREDIT_CARD_NAME )
	@HashedField(alias= "mac1")
	private String toencrypt;

	private String plain;
	
	@EncryptedField(iv = TestMessage.CREDIT_CARD_NUMBER_IV,alias = TestMessage.CREDIT_CARD_NAME, encodable = ByteEncodable.LongEncodable.class )
	private Long aNumber;
	
	public TestMessageWithHash() {}
	public TestMessageWithHash(String toencrypt,Long anum) {
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