package org.marcusbb.crypto.spi.vault;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
//{"lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":["v2_SettingsValue","SearchHash","EPaymentAccount","ExposedHash"
@JsonIgnoreProperties
public class VaultListData {

	private String lease_id;
	private boolean renewable;
	private long lease_duration;
	private DataArrayObj data = new DataArrayObj();
	public static class DataArrayObj {
		private String[] keys;

		public String[] getKeys() {
			return keys;
		}

		public void setKeys(String[] data) {
			this.keys = data;
		}
		
	}
	private String warnings;
	private String auth;
	
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
	
	
	public DataArrayObj getData() {
		return data;
	}
	public void setData(DataArrayObj dataObj) {
		this.data = dataObj;
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
	
	
}
