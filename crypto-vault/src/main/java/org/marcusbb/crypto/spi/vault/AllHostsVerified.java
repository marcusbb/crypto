package org.marcusbb.crypto.spi.vault;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.http.conn.ssl.X509HostnameVerifier;

/**
 * 
 * Insecure workaround for self-signed certs with no peer verification
 *
 */
public  class AllHostsVerified implements X509HostnameVerifier {

	private String[] allowedhosts;
	
	/**
	 * Allow all
	 */
	public AllHostsVerified() {
		
	}
	public AllHostsVerified(String ...allowedHosts) {
		this.allowedhosts = allowedHosts;
	}
	
	@Override
	public boolean verify(String hostname, SSLSession session) {
		if (allowedhosts != null) {
			for (String host:allowedhosts) {
				if (hostname.equals(host)) return true;
			}
			return false;
		}
		
		return true;
	}
	@Override
	public void verify(String host, SSLSocket ssl) throws IOException {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void verify(String host, X509Certificate cert) throws SSLException {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void verify(String host, String[] cns, String[] subjectAlts) throws SSLException {
		// TODO Auto-generated method stub
		
	}
	
}
