package org.marcusbb.crypto.spi.vault;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * 
 * 
 */
public class VaultConfiguration {

	private final String baseUrl;
	private final String token;
	private SSLConfiguration sslConfig = new SSLConfiguration(null, null,true);
	
	public final static class SSLConfiguration {
		private String keyStorePath;
		private String keyStorePass;
		private boolean trusting;
		public SSLConfiguration(String keyStorePath, String keyStorePass, boolean trusting) {
			super();
			this.keyStorePath = keyStorePath;
			this.keyStorePass = keyStorePass;
			this.trusting = trusting;
		}
		public String getKeyStorePath() {
			return keyStorePath;
		}
		public void setKeyStorePath(String keyStorePath) {
			this.keyStorePath = keyStorePath;
		}
		public String getKeyStorePass() {
			return keyStorePass;
		}
		public void setKeyStorePass(String keyStorePass) {
			this.keyStorePass = keyStorePass;
		}
		public boolean isTrusting() {
			return trusting;
		}
		public void setTrusting(boolean trusting) {
			this.trusting = trusting;
		}
		
		
	}
	public VaultConfiguration(String baseUrl, String token)  {
		//URI uri = new URI(baseUrl);
		this.baseUrl = baseUrl;
		this.token = token;
	}
	public VaultConfiguration(String baseUrl, String token,SSLConfiguration sslConfig)  {
		this(baseUrl,token);
		this.sslConfig = sslConfig;
	}

	public String getBaseUrl() {
		return baseUrl;
	}

	public String getToken() {
		return token;
	}
	
	public SSLConfiguration getSSLConfig() {
		return this.sslConfig;
	}
	
	
}
