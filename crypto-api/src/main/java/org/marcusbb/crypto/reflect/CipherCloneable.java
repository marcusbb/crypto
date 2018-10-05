package org.marcusbb.crypto.reflect;

public interface CipherCloneable extends Cloneable {

	public Object clone() throws NotCloneable;
	
	public static class DefaultCloneable implements CipherCloneable,Cloneable {
		
		public Object clone() {
			try {
				return super.clone();
			} catch (CloneNotSupportedException e) {
				throw new NotCloneable(e);
			}
		}
	}
}
