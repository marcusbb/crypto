package org.marcusbb.crypto.spi.vault;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

//{"lease_id":"","renewable":false,"lease_duration":2592000,"data":{"key":"jloXkhlEZ5Ry5vG5vffI4w=="},"warnings":null,"auth":null}
@JsonIgnoreProperties
public class VaultKeyData {

	private String lease_id;
	
	private boolean renewable;
	private long lease_duration;
	private Map<String,String> data;
	private String warnings;
	private String auth;
	
//	private String request_id;
//	private String wrap_info;
	
	public String getLease_id() {
		return lease_id;
	}
	public void setLease_id(String lease_id) {
		this.lease_id = lease_id;
	}
	public boolean isRenewable() {
		return renewable;
	}
	public void setRenewable(boolean renewable) {
		this.renewable = renewable;
	}
	public long getLease_duration() {
		return lease_duration;
	}
	public void setLease_duration(long lease_duration) {
		this.lease_duration = lease_duration;
	}
	public Map<String, String> getData() {
		return data;
	}
	public void setData(Map<String, String> data) {
		this.data = data;
	}
	public String getWarnings() {
		return warnings;
	}
	public void setWarnings(String warnings) {
		this.warnings = warnings;
	}
	public String getAuth() {
		return auth;
	}
	public void setAuth(String auth) {
		this.auth = auth;
	}
//	public String getRequest_id() {
//		return request_id;
//	}
//	public void setRequest_id(String request_id) {
//		this.request_id = request_id;
//	}
//	public String getWrap_info() {
//		return wrap_info;
//	}
//	public void setWrap_info(String wrap_info) {
//		this.wrap_info = wrap_info;
//	}
	
	
	
}
