package org.marcusbb.crypto.spi.vault;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipherStreamSample {

	public static void main(String args[]) {
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(new SecureRandom());
			SecretKey key = kg.generateKey();
			/*SecretKeyFactory skf = SecretKeyFactory.getInstance("AES");
			Class spec = Class.forName("javax.crypto.spec.AESKeySpec");
			DESKeySpec ks = (DESKeySpec) skf.getKeySpec(key, spec);*/
			ObjectOutputStream oos = new ObjectOutputStream(
						new FileOutputStream("keyfile"));
			oos.writeObject(new SecretKeySpec(key.getEncoded(),"AES"));

			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			c.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec("0123456789123456".getBytes()));
			CipherOutputStream cos = new CipherOutputStream(
						new FileOutputStream("ciphertext"), c);
			PrintWriter pw = new PrintWriter(
						new OutputStreamWriter(cos));
			pw.println("Why missing Stand and unfold yourself.........");
			pw.flush();
			pw.close();
			oos.writeObject(c.getIV());
			oos.close();
		} catch (Exception e) {
			System.out.println(e);
		}
		
		//read
		try {
			ObjectInputStream ois = new ObjectInputStream(
						new FileInputStream("keyfile"));
//			DESKeySpec ks = new DESKeySpec((byte[]) ois.readObject());
//			SecretKeyFactory skf = SecretKeyFactory.getInstance("AES");
//			SecretKey key = skf.generateSecret(ks);
			SecretKeySpec keySpec = (SecretKeySpec)ois.readObject();
			
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec("0123456789123456".getBytes()));
			//c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec((byte[]) ois.readObject()));
			CipherInputStream cis = new CipherInputStream(
						new FileInputStream("ciphertext"), c);
			
			//cis.read(new byte[8]);
			BufferedReader br = new BufferedReader(new InputStreamReader(cis));
			//System.out.println("Got message");
			System.out.println(br.readLine());
		} catch (Exception e) {
			System.out.println(e);
		}
	}
}
