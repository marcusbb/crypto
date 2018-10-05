package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.ByteEncodable;
import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;
import org.marcusbb.crypto.spi.reflect.ReflectUtilTest;

public class TestMessageIncomplete extends CipherCloneable.DefaultCloneable   {
	
	@EncryptedField(iv = TestMessage.CREDIT_CARD_NUMBER_IV,alias = TestMessage.CREDIT_CARD_NAME )
	private String toencrypt;

	
	@EncryptedField(iv = TestMessage.CREDIT_CARD_NUMBER_IV,alias = TestMessage.CREDIT_CARD_NAME, encodable = ByteEncodable.LongEncodable.class )
	private Long aNumber;
}