package org.marcusbb.crypto.policy;

/**
 * 
 * This is a mapping of Vault Policy to Cipher policy
 * 
 * Each category of policy can have an associated {@link Authorization}.
 * 
 * 
 * 
 */
public interface Policy {

	//Hide key cipher through 
	//deployment of Vault + companion "spoke" service - in a 
	//co-resident container
	/**
	 *
	 */
	public static enum Authorization {
		ENCRYPT,
		DECRYPT,
		ALL
	}
	
	//each Category is assigned a level
	public static enum Category {
		
		ZERO(0,"transit/gap"),
		PII(10,"transit/pii"),
		PCI_1(1000,"transit/pci_1"),
		PCI_2(1010,"transit/pci_2");
		
		int level;
		
		private Category(int level,String pathPrefix) {
			this.level = level;
		}
	}
	
	public String getToken();
	
	public Category[] getCategories();
	
	public static final class NoPolicy implements Policy {
		public static String EMPTY = "";
		@Override
		public String getToken() {
			return EMPTY;
		}
		@Override
		public Category[] getCategories() {
			return null;
		}
		 
	}
}
