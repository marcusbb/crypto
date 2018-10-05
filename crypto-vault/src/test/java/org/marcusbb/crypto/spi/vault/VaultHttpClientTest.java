package org.marcusbb.crypto.spi.vault;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Test;
import org.marcusbb.crypto.spi.vault.VaultConfiguration;
import org.marcusbb.crypto.spi.vault.VaultHttpClient;

public class VaultHttpClientTest extends VaultTestBase {

	@Test
	public void testBuildClient() {
		VaultConfiguration confWithDefaultClient = new VaultConfiguration(VAULT_BASE_URL, VAULT_TOKEN, new VaultConfiguration.SSLConfiguration(null, null, false));
		
		VaultHttpClient client = new VaultHttpClient(confWithDefaultClient);
		CloseableHttpClient httpClient = client.buildClient();
		try {
			httpClient.execute(new HttpGet("https://www.google.com"));
		}catch (Exception e) {
			fail("Failed to execute");
		}
		
		VaultConfiguration trustingConfig = new VaultConfiguration(VAULT_BASE_URL, VAULT_TOKEN, new VaultConfiguration.SSLConfiguration(null, null, true));
		
		client = new VaultHttpClient(trustingConfig);
		httpClient = client.buildClient();
		try {
			//whether http or https will succeed
			httpClient.execute(new HttpGet(VAULT_BASE_URL));
			
		}catch (Exception e) {
			fail("Failed to execute");
		}
		
		
		
	}
	@Test
	public void testInsertKeys() throws Exception {
		VaultConfiguration config = new VaultConfiguration(VAULT_BASE_URL, VAULT_TOKEN);
		VaultHttpClient client = new VaultHttpClient(config);
		
		Map<String,byte[]> secretMap = generateAesSecretMap("key");
		Map<String,byte[]> multiMap = generateAesSecretMap("key","key_b");
		
		client.post("/secret/aeskey1", secretMap );
		client.post("/secret/aes_key1", multiMap);
		
		Map<String,byte[]> map = client.get("/secret/aeskey1");
		
		assertEquals( new String(secretMap.get("key")), new String(map.get("key")) );
		
		
		map = client.get("/secret/aes_key1");
		
		assertEquals(2, map.size());
	}

}
