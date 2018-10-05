package org.marcusbb.crypto.spi.vault;

import java.io.File;
import java.io.InputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.KeyGenerator;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.marcusbb.crypto.spi.vault.VaultConfiguration;

public class VaultTestBase {

	static String VAULT_TOKEN = "ad08876f-777a-83bc-6bec-cc33e3b0ceec";
	static String VAULT_BASE_URL = "http://localhost:8200/v1";
	//Use links or shortcuts to executable
	static String VAULT_INSTALL_PATH = "/opt/hashicorp/vault.exe";
	static Process vaultProcess;
	
	public static VaultConfiguration getConfig() {
		
		return new VaultConfiguration(VAULT_BASE_URL, VAULT_TOKEN);
	}
	
	public static byte[] generateAesSecretMaterial() throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		Key key = kg.generateKey();
		return key.getEncoded();
	}
	public static Map<String,byte[]> generateAesSecretMap(String ...keys) throws NoSuchAlgorithmException {
		HashMap<String, byte[]> map = new HashMap<String, byte[]>();
		for (String key:keys) {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			Key secretKey = kg.generateKey();
			map.put(key, secretKey.getEncoded());
		}
		return map;
	}
	@BeforeClass
	public static void beforeClass() throws Exception {
		startVault();
	}
	@AfterClass
	public static void afterClass() {
		if (vaultProcess !=null)
			vaultProcess.destroy();
		vaultProcess = null;
	}
	
	public static void startVault() throws Exception {
		if (vaultProcess == null)
		try {
			if (System.getProperty("VAULT_INSTALL_PATH") != null)
				VAULT_INSTALL_PATH = System.getProperty("VAULT_INSTALL_PATH");
			if (!new File(VAULT_INSTALL_PATH).canExecute())
				throw new RuntimeException("Vault path does not appear executable");
			
			ProcessBuilder pb = new ProcessBuilder(VAULT_INSTALL_PATH,"server","-dev");
			
			Pattern rootToken = Pattern.compile("Root\\sToken\\:\\s+(.*)");
			vaultProcess = pb.start();
			 
			 InputStream ps = vaultProcess.getInputStream();
			StringBuffer stdOut = new StringBuffer();
			boolean done = false;
			while (!done) {
				byte []content = new byte[ps.available()];
				ps.read(content);
				String strContent = new String(content);
				stdOut.append(strContent);
				System.out.println(strContent);
								
				Matcher m = rootToken.matcher(stdOut.toString());
				if (m.find()) {
					System.out.println("FoundToken! " + m.group(1));
					VAULT_TOKEN = m.group(1);
					done = true;
				} else
					Thread.sleep(100);
			}
			
			try {
				vaultProcess.exitValue();
				System.out.println("WARNING: Vault.exe DOES NOT run on mingw shell");
				throw new RuntimeException("The vault subprocess has died unexpectedly, check that there are no other vault processes or port bindings on 8200 ");
			}catch (IllegalThreadStateException e) {
				System.out.println("Process is alive");
				
			}
		}
		catch (Exception e) {
			System.out.println("Something went wrong, please ensure Vault is installed and the path is " + VAULT_INSTALL_PATH);
			throw e;
		}
		
		
	}
}
