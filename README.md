
# Crypto
Is versioned cipher operations backed by Hashicorp's [Vault](https://www.vaultproject.io/) key store implementation.
This project only works with vault 0.9.6 and older - some investigation is required for 1.0+ Vault versions.

This project has some feature parities to Vault's transit backend, however this is premised on the fact that key may exit the Vault, where cipher operations can occur locally.  This ensures scalable distribution of cipher operations but must allow that clients can read the secret material for symmetric or hashing operations.

Like Vault, key versioning is central to secret management.  There are other features which make this project unique, most notably a streaming feature and field level encryption which also founded on the same system of key versioning.

## Building/ Installing
Use maven
```
mvn install
```
**Tests are disabled by default** as they require a Vault installation.

If you want to run the build with tests you need to first start a vault server.
If you're a docker user:

```
docker run -p 8200:8200 --rm -d --cap-add=IPC_LOCK --name=dev-vault-for-crypto  -e VAULT_DEV_ROOT_TOKEN_ID=ad08876f-777a-83bc-6bec-cc33e3b0ceec vault:0.9.6

mvn install -DskipTests=false

docker rm -f dev-vault-for-crypto
```
For non docker tests you will need to install a version of vault on /opt/hashicorp/vault.exe for you particular version of platform you are running.  



## Versioned Crypto and Keystore

The bulk to of the crypto features are based off a versioned based encryption strategy with a main interface:
```java
public interface VersionedCipher  {

	public byte[] encrypt(VersionedKey version, byte[] payload);
	
	public byte[] decrypt(VersionedKey version, byte[] payload);
	
}
```
Where the Versioned Key is simply an alias to a monotony increasing sequence.

The keystore is very closely aligned to the JCE api for key retrieval and manipulation.
And is initialized with some basic properties of a vault configuration 
```java
store = new VaultKeyStoreManager(new VaultConfiguration("http://localhost:8200/v1","my_app_token"))
```

For fuller details on how to generating this token or managing controls please see the vault documentation.
Vault can be easily used in developer mode where this token can be hard coded.
```
vault server -dev -dev-root-token-id="my_app_token"
```
DO NOT DO THIS IN PRODUCTION!

```java
public interface KeyStoreManager {

	PrivateKey getPrivateKey(String alias);
	
	PublicKey getPublicKey(String alias);
	
	SecretKey getSecretKey(String alias);
	
	byte[] getIvParameter(String alias);
	
	
	Mac getMac(String secretkeyAlias);
}

```
You can also conveniently save, update/rotate keys into Vault, so that you don't have to have operator intervention in the lifecycle management of keys. For instance, at fixed periodic schedules or during application restart, redeployment an application may which to create to update a key:
```java
store = new VaultKeyStoreManager(myVaultconfig);
store.createOrUpdateSecretVersion("AES",CREDIT_CARD_NAME);
		
```

### Streaming
The same api is available in stream format, where you provide the key the appropriate input stream and outputstream.

```java
public interface VersionedStreamCipher {


	public void encrypt(VersionedKey version, InputStream in,OutputStream out) throws IOException;
		
	public void decrypt(VersionedKey version, InputStream in,OutputStream out) throws IOException;
}

//An example
JCEVersionedCipher vCipher = new JCEVersionedCipher();
ByteArrayInputStream bin = new ByteArrayInputStream("Hello Streaming Encryption".getBytes());
ByteArrayOutputStream bout = new ByteArrayOutputStream();
vCipher.encrypt(new VaultVersionedKeyBuilder(store).buildKey(key_alias, iv_alias),bin,bout);
```

## Field (bean) level Encryption

An annotated approach to application encryption. 
For a given data structure fields are annotated to produce a ByteShadow holder object which is holds a cloned and nulled version 
of the original content as well as a "Shadow" of metadata representing the encrypted or hashed fields.
Example
```java
//Define data structure
class TestMessage extends CipherCloneable.DefaultCloneable   {
		
	
	@EncryptedField(iv = CREDIT_CARD_NUMBER_IV,alias = CREDIT_CARD_NAME )
	String toencrypt;

	private String plain;
	
	@EncryptedField(iv = CREDIT_CARD_NUMBER_IV,alias = CREDIT_CARD_NAME, encodable = ByteEncodable.LongEncodable.class )
	Long aNumber;
}

//Use api to 
//keybuilder and store as described above
ReflectUtil ref = new ReflectUtil(keyBuilder,vCipher,store);
		
ByteShadow bs = ref.encrypt(new TestMessage("helloworld",11L));

```


