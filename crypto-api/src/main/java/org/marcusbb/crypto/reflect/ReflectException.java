package org.marcusbb.crypto.reflect;

/**
 * 
 * General purpose reflect exception
 *
 */
public class ReflectException extends RuntimeException{

	public ReflectException(String msg,Exception e) {
		super(msg,e);
	}
	public ReflectException(Exception e) {
		super(e);
	}
}
