package org.marcusbb.crypto.management;

/**
 * 
 * Allowing programmatic/runtime access to the set of managing implementations.
 *
 */
public interface KeyManagementMBean {

	int getDefaultVersion();
	
	void setVersion(int version);
	
	int getVersion();
	
}
