package org.marcusbb.crypto.reflect;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;


public interface ByteEncodable {

	Object decode(byte []b);
	
	byte[] encode(Object obj);
	
	//remove to Long.BYTES for jdk 8+ 
	public static int LONG_BYTE_SIZE = 8;
	
	/**
	 * 
	 * Uses java serialization to encode and decode bytes.
	 * Therefore you can save yourself from multiple operations of
	 * encrypt by encoding blocks (classes) of information.
	 * Other possible serialization mechanisms are possible as well
	 * such as Kryo, Avro etc.
	 *
	 */
	public final class GenericEncdoable implements ByteEncodable {

		@Override
		public Object decode(byte[] b) {
			try {
				ObjectInputStream ins = new ObjectInputStream(new ByteArrayInputStream(b));
				return ins.readObject();
			}catch (Exception e) {
				throw new ReflectException(e);
			}
		}

		@Override
		public byte[] encode(Object obj) {
			try {
				 ByteArrayOutputStream bo = new ByteArrayOutputStream();
				 ObjectOutputStream oo = new ObjectOutputStream(bo);
				 oo.writeObject(obj);
				 return bo.toByteArray();
			}catch (Exception e) {
				throw new ReflectException(e);
			}
		}
		
	}
	/**
	 * Uses String default (UTF-8) encoding 
	 *
	 */
	public final class StringEncodable implements ByteEncodable {

		@Override
		public Object decode(byte[] b) {
			return new String(b);
		}

		@Override
		public byte[] encode(Object obj) {
			return obj.toString().getBytes();
		}
		
	}
	/**
	 * Writes and reads 8 byte long. 
	 *
	 */
	public final class LongEncodable implements ByteEncodable {

		@Override
		public Object decode(byte[] b) {
			ByteBuffer bb = ByteBuffer.allocate(LONG_BYTE_SIZE);
			bb.put(b).flip();
			return bb.getLong();
		}

		@Override
		public byte[] encode(Object obj) {
			 ByteBuffer buffer = ByteBuffer.allocate(LONG_BYTE_SIZE);
			 buffer.putLong((Long)obj);
			 return buffer.array();
		}
		
	}
	
	
	
}
