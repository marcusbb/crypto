package org.marcusbb.crypto.spi.vault;

import static  com.codahale.metrics.MetricRegistry.name;

import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.marcusbb.crypto.VersionedCipher;
import org.marcusbb.crypto.spi.stub.JCEVersionedCipher;
import org.marcusbb.crypto.spi.vault.VaultCachedKSManager;
import org.marcusbb.crypto.spi.vault.VaultKeyStoreManager;
import org.marcusbb.crypto.spi.vault.VaultVersionedKeyBuilder;

import com.codahale.metrics.ConsoleReporter;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
public class LargeLoadTest extends VaultTestBase {

	
	int iterations = 100000;
	static final MetricRegistry metrics = new MetricRegistry();
	private final Meter requests = metrics.meter("requests");
	private final Timer encryptTimer = metrics.timer(name("encryptOp", "responses"));
	private final Timer decryptTimer = metrics.timer(name("decryptOp", "responses"));
	static ConsoleReporter reporter = null;
			
	public static void main(String []args) throws Exception {
		LargeLoadTest test = new LargeLoadTest();
		LargeLoadTest.beforeClass();
		test.parallelThroughputCache();
	}
	
	public static void beforeClass() throws Exception {
		VaultTestBase.beforeClass();
		      reporter = ConsoleReporter.forRegistry(metrics)
		          .convertRatesTo(TimeUnit.SECONDS)
		          .convertDurationsTo(TimeUnit.MILLISECONDS)
		          .build();
		      reporter.start(1, TimeUnit.SECONDS);
	}
	
	public void parallelThroughputCache() throws Exception {
		
		//SecretKey aes1 = KeyGenerator.getInstance("AES").generateKey();
		VaultKeyStoreManager store = new VaultCachedKSManager(getConfig(),10,TimeUnit.MINUTES,10000);
		
		
		
		final VersionedCipher vCipher = new JCEVersionedCipher();
		final VaultVersionedKeyBuilder keyBuilder = new VaultVersionedKeyBuilder(store);
		final String CREDIT_CARD_NAME = "aes_credit_card";
		final String CREDIT_CARD_NUMBER_IV = "0123456789123456";
		store.createOrUpdateSecretVersion("AES",CREDIT_CARD_NAME);
		store.createOrUpdateIv(CREDIT_CARD_NUMBER_IV, CREDIT_CARD_NUMBER_IV.getBytes());
		//store.postKey(VaultKeyStoreManager.IV_PREFIX + "/" + CREDIT_CARD_NUMBER_IV, new SecretKeySpec(CREDIT_CARD_NUMBER_IV.getBytes(),"AES"));
		
		Random rand = new Random();
		final byte []encodeByte = randomBytes(4*1024);
		int numthreads = 10;
		
		ExecutorService exec = Executors.newFixedThreadPool(numthreads);
		for (int i=0;i<iterations;i++) {
			exec.submit(new Runnable() {
				
				@Override
				public void run() {
					final Timer.Context context = encryptTimer.time();
					byte []e = null;
					try {
						e = vCipher.encrypt(keyBuilder.buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV), encodeByte);
					}finally {
						context.stop();
					}
					final Timer.Context context2 = decryptTimer.time();
					try {
						vCipher.decrypt(keyBuilder.buildKey(CREDIT_CARD_NAME, CREDIT_CARD_NUMBER_IV), e);
					}finally {
						context2.stop();
					}
					
				}
			});
		}
		exec.shutdown();
		exec.awaitTermination(10, TimeUnit.MINUTES);
		VaultTestBase.afterClass();
		reporter.report();
		
	}
	public static byte []randomBytes(int size) {
		byte []b_input = new byte[size];
		Random r = new Random();
		int bi = 0;
		for (int i=0;i<size;i++) {
			b_input[i] = (byte)r.nextInt(256);
		}
		return b_input;
	}
		
		
	
	
}
