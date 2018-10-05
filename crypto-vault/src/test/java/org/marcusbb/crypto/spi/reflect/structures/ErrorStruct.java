package org.marcusbb.crypto.spi.reflect.structures;

import org.marcusbb.crypto.reflect.CipherCloneable;
import org.marcusbb.crypto.reflect.EncryptedField;

public class ErrorStruct extends CipherCloneable.DefaultCloneable {

	@EncryptedField(alias="useful", iv="asif")
	private String anotherEncrypted;
}
