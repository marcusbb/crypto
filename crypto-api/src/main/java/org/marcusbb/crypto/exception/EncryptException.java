package org.marcusbb.crypto.exception;

/**
 * Runtime Exception related to the concerns of encrypt and decrypt
 * operations of the cipher, and any other errors that each implementation
 * may impart.
 * 
 * These errors are generally not recoverable, and indicate configuration
 * related errors, or errors in cipher initialization.
 *
 */
public class EncryptException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public EncryptException() {
		super();
		// TODO Auto-generated constructor stub
	}

	public EncryptException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	public EncryptException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	public EncryptException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	
}
