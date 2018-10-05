package org.marcusbb.crypto.policy;

/**
 * 
 * 
 *
 */
public class VaultPolicy implements Policy {

	public static String TOKEN_KEY = "VAULT_TOKEN"; 
	String token;
	Category []categories;
	
	public VaultPolicy() {
		token = System.getenv(TOKEN_KEY);
		if (token == null)
			token = System.getProperty(TOKEN_KEY);
		
		
	}
	public VaultPolicy(String policyFile) {
		
	}
	public VaultPolicy(Category []supportedCategories) {
		this.categories = supportedCategories;
	}
	@Override
	public String getToken() {
		return token;
	}

	@Override
	public Category[] getCategories() {
		return categories;
	}
	
	

}
