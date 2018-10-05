package org.marcusbb.crypto.spi.vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.Consts;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.marcusbb.crypto.commons.ByteUtils;
import org.marcusbb.crypto.exception.UnknownKeyVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class VaultHttpClient {

	
	private final VaultConfiguration vConfig;

	static Logger logger = LoggerFactory.getLogger(VaultHttpClient.class);
	
	public VaultHttpClient(VaultConfiguration vaultConfig) {
		this.vConfig = vaultConfig;

	}

	/**
	 * Builds a client that can support both TLS and HTTP protocols.
	 * Caution must be used as it currently trusts all certificates - from any host.
	 * 
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws KeyManagementException
	 */
	public CloseableHttpClient buildSelfTrusted()
			throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		
		SSLContextBuilder builder = new SSLContextBuilder(); //.useTLS();
	
		builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
		//builder.useProtocol("TLSv1");

		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(), new String[] {"TLSv1.2","TLSv1"}, null, new AllHostsVerified());
		//SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(), new AllHostsVerified());

		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		
		return httpclient;
	}
	
	public CloseableHttpClient buildClient() {
		if (vConfig.getSSLConfig().isTrusting()) {
			try {
				return buildSelfTrusted();
			}catch (Exception e) {
				logger.warn(e.getMessage(),e);
				logger.warn("Returning a default client");
				return HttpClients.createDefault();
			}
		}else {
			return HttpClients.createDefault();
		}
	}

	protected void execute(HttpClient client, HttpPost post)
			throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

	}

	protected void execute(HttpPost post) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, ClientProtocolException, IOException {
		CloseableHttpClient httpclient = buildClient();

		try {
			CloseableHttpResponse response = httpclient.execute(post);
			assertResponse(response);
		} finally {
			close(httpclient);
		}

	}

	private void close(CloseableHttpClient client) {
		try {
			if (client != null)
				client.close();
		} catch (IOException e) {

		}
	}
	
	private void assertResponse(HttpResponse response) {
		int statusCode = response.getStatusLine().getStatusCode();
		if (statusCode == 404)
			throw new UnknownKeyVersion("Can not find key with that url");
		if (statusCode < 200 || statusCode > 299) {
			//TODO: figure out exceptions
			throw new RuntimeException("Request was not successful " + response.getStatusLine().getStatusCode() );
		}
	}

	protected VaultListData get(String relativePath,Map<String,String> queryString) throws KeyManagementException, JsonProcessingException, NoSuchAlgorithmException, KeyStoreException, IOException, URISyntaxException {
		
	    URIBuilder builder = new URIBuilder(vConfig.getBaseUrl() + relativePath);
	   	for (String qk:queryString.keySet()) {
	   		builder.addParameter(qk, queryString.get(qk));
	   	}
		HttpGet get = new HttpGet(builder.build());
		
		get.addHeader("X-Vault-Token",vConfig.getToken());
		
		CloseableHttpClient httpclient = buildClient();
		VaultListData data = null;
		try {
					
			CloseableHttpResponse response = httpclient.execute(get);
			//assertResponse(response);
			ObjectMapper mapper = new ObjectMapper();
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			data = mapper.readValue(response.getEntity().getContent(), VaultListData.class);
		}finally {
			close(httpclient);
		}
		return data;
	}
	/**
	 * Gets Vault's data map with respect to a relative path.
	 * 
	 * @param relativePath
	 * @return
	 * @throws KeyManagementException
	 * @throws JsonProcessingException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public Map<String,byte[]> get(String relativePath) throws KeyManagementException, JsonProcessingException, NoSuchAlgorithmException, KeyStoreException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		HttpGet get = new HttpGet(vConfig.getBaseUrl() + relativePath);
		get.addHeader("X-Vault-Token",vConfig.getToken());
		HashMap<String, byte[]> byteMap = new HashMap<String, byte[]>();
		CloseableHttpClient httpclient = buildClient();
		try {
			
			CloseableHttpResponse response = httpclient.execute(get);
			assertResponse(response);
						
//			JsonNode node = mapper.readTree(response.getEntity().getContent());
//			JsonNode dataNode = node.get("data");
//			Iterator<String> fieldNames = dataNode.fieldNames();
//	        while (fieldNames.hasNext()) {
//	            String fieldName = fieldNames.next();
//	            byteMap.put(fieldName, new Base64().decode(dataNode.get(fieldName).asText()));
//	        }
	        VaultKeyData vaultData = mapper.readValue(response.getEntity().getContent(), VaultKeyData.class);
	        
	        for (String key:vaultData.getData().keySet()) {
	        	byteMap.put(key, ByteUtils.base64Decode(vaultData.getData().get(key)));
	        }
			
		}finally {
			close(httpclient);
		}
			 
		return byteMap;
	}
	/**
	 * Encode in base 64 and write to Vault's relative path. 
	 * 
	 * @param relativePath
	 * @param map
	 * @throws JsonGenerationException
	 * @throws JsonMappingException
	 * @throws IOException
	 * @throws KeyStoreException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 */
	public void post(String relativePath, Map<String, byte[]> map) throws JsonGenerationException, JsonMappingException, IOException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		
		ObjectMapper mapper = new ObjectMapper();
		HashMap<String,String> encoded = new HashMap<String, String>(map.size());
		for (String key:map.keySet()) {
			encoded.put(key, ByteUtils.base64Encode(map.get(key)));
		}
		
		//TODO: investigate possible better streaming mechanisms 
		//such as using different Entity types (ByteEntity for instance)
		HttpPost post = new HttpPost(vConfig.getBaseUrl() + relativePath);
		post.addHeader("X-Vault-Token",vConfig.getToken());
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		mapper.writeValue(os, encoded);
		
		StringEntity entity = new StringEntity(os.toString("UTF-8"),
		        ContentType.create("application/json", Consts.UTF_8));
		post.setEntity(entity);
		
		execute(post);
		
	}

	
}
