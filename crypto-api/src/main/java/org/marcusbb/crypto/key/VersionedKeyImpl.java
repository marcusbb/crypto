package org.marcusbb.crypto.key;

import javax.crypto.spec.IvParameterSpec;

import org.marcusbb.crypto.VersionedKey;

/**
 * 
 *  
 *
 */
public class VersionedKeyImpl implements VersionedKey {
	
	private String keyName;
	private int version;
	byte []iv;
	
	public VersionedKeyImpl(String keyName, int version, byte[] iv) {
		this.keyName = keyName;
		this.version = version;
		this.iv = iv;
	}
	//Derive the key from payload (header)
	public VersionedKeyImpl(String keyName, byte[] payload, byte[] iv) {
		this(keyName,-1,iv);
		this.version = version(payload);
	}
	public String versionedKeyName() {
		return (version == -1 || version == 0 ? "" : ("v" + Integer.toString(version) + "_")) + keyName;
	}
	public String keyHash() {
		
		String cipherTableKey = versionedKeyName() + "-" + byteArrayToHexString(iv);
		
		return cipherTableKey;
	}
	public static int version(byte []header) {
		if (header[0] == 16)
			return ((header[1] & 0x000000ff) * 16) + ((header[2] & 0x000000f0) >>> 4);
		return -1;
	}
	
	//is this really necessary?! 
	//preserve this implementation for backward compatibility
	public static String byteArrayToHexString(byte in[]) {
	    byte ch = 0x00;
	    int i = 0;
	    if (in == null || in.length <= 0)
	        return null;

	    String pseudo[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8",	"9", "A", "B", "C", "D", "E", "F"};
	    StringBuffer out = new StringBuffer(in.length * 2);

	    while (i < in.length) {
	        ch = (byte) (in[i] & 0xF0); // Strip off high nibble
	        ch = (byte) (ch >>> 4);     // shift the bits down
	        ch = (byte) (ch & 0x0F);    //  	 must do this is high order bit is on!
	        out.append(pseudo[ (int) ch]); // convert the nibble to a String Character
	        ch = (byte) (in[i] & 0x0F); // Strip off low nibble
	        out.append(pseudo[ (int) ch]); // convert the nibble to a String Character
	        i++;
	    }
	    String rslt = new String(out);
	    return rslt;
	}
	
	public int headerLength() {
		return 3;
	}
	
	public byte[] header() {
		byte []header = new byte[3];
		header[0] = 16;
		header[1] = (byte) (version / 16);
		header[2] = (byte) ((version % 16) << 4);
		return header;
	}
	
	public String getKeyName() {
		return keyName;
	}
	public int getVersion() {
		return version;
	}
	public byte[] getIv() {
		return iv;
	}
	public IvParameterSpec iv() {
		return new IvParameterSpec(iv);
	}
	
	
	
	
}