package org.marcusbb.crypto.reflect;

/**
 * 
 * Wraps {@link CloneNotSupportedException} in a runtime exception
 *
 */
public class NotCloneable extends RuntimeException {

	
	private static final long serialVersionUID = 1L;

	public NotCloneable(Exception e) {
		super(e);
	}
}
