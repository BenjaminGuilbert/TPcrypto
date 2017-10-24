
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

	public static void main(String[] args) {
	
		//Test of the provider
		Security.addProvider(new BouncyCastleProvider());
		if(Security.getProvider("BC") == null) {
			System.out.println("Provider not available");
		}
		else {
			System.out.println("Provider available");
		}
				 
		//Messages
		byte[] plainText1 = new byte[] {
				0x30, 0x01, 0x05, 0x3A, 0x00, 0x28, 0x45, 0x2F,
				0x1C, 0x6A, 0x4B, 0x05, 0x30, 0x20, 0x19, 0x0A
		};		
		byte[] plainText2 = new byte[] {
				0x30, 0x01, 0x05, 0x3A, 0x00, 0x28, 0x45, 0x2F
		};	
		byte[] plainText3 = new byte[] {
				0x30, 0x01, 0x05, 0x3A, 0x00, 0x28, 0x45, 0x2F,
				0x1C, 0x6A, 0x4B, 0x05, 0x30, 0x20, 0x19, 0x0A,
				(byte)0xCB, (byte)0x89, 0x1B, (byte)0xE5, (byte)0xFF, 0x10, 0x30, 0x4A
		};
		//System.out.println("PlainText : "+bytesToHex(plainText2));
		

		//Encrypt and Decrypt a byte array
		//rawBytesEncryptionDecryption(plainText2);
		
		//Encrypt and Decrypt a file to a file
		try {
			Path path = Paths.get("/Users/benjaminguilbert/travail/Télécom/3eme Année/PMS/Pres_Crypto/message.txt");
			byte[] data = Files.readAllBytes(path);
			System.out.println("Message : "+new String(data, StandardCharsets.UTF_8));
			System.out.println("PlainText of bytes : "+bytesToHex(data));
			rawBytesEncryptionDecryptionToFile(data, path);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}
	


	/**
	 * Cast bytes to Hexadecimal
	 * @param input
	 * @return
	 */
	public static String bytesToHex(byte[] input) {
	    StringBuilder sb = new StringBuilder();
	    
	    for (byte b : input) {
	        sb.append(String.format("%02X ", b));
	    }
		return sb.toString();
	}

	/**
	 * Encryption and Decryption of a byte array
	 * Display to the console
	 * @param input byte array
	 */
	public static void rawBytesEncryptionDecryption(byte[] input) {
		
		//Manually Key generating  
		/*byte[] keyBytes = new byte[] { 
				0x2F, 0x11, 0x1D, 0x00, 0x14, 0x0E, 0x14, 0x07, 
				0x18, 0x19, 0x0A, 0x0F, 0x1C, 0x11, 0x3A, 0x1F 
				};		
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		*/
		
						
		//Encrypt/Decrypt
		try {
			//Randomly Key Generating
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128,new SecureRandom());
			Key key = keyGen.generateKey();
			System.out.println("Key : "+bytesToHex(key.getEncoded()));
			
			//Algorithm of encryption
			//Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");
			//Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			Cipher ci = Cipher.getInstance("AES/CTR/PKCS5Padding");			
			byte[] ivOrCpt = new byte[16];
			SecureRandom random = new SecureRandom();
	        random.nextBytes(ivOrCpt);	        
			System.out.println("IvOrCpt : "+bytesToHex(ivOrCpt));			
			IvParameterSpec ivSpec = new IvParameterSpec(ivOrCpt);
						
			
			//Encrypt
			ci.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] cipherText = ci.doFinal(input);
			System.out.println("CipherText : "+bytesToHex(cipherText));
			
			
			//Decrypt
			ci.init(Cipher.DECRYPT_MODE, key, ivSpec);
			byte[] digest = ci.doFinal(cipherText);
			System.out.println("PlainText : "+bytesToHex(digest));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	
	/**
	 * Encryption and Decryption of a byte array to a file
	 * Display to the console
	 * @param input byte array
	 * @param path of the output file
	 */
	private static void rawBytesEncryptionDecryptionToFile(byte[] input, Path path) {
		//Encrypt/Decrypt
		try {
						
			// Randomly Key Generating
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128,new SecureRandom());
			Key key = keyGen.generateKey();
			System.out.println("Key : "+bytesToHex(key.getEncoded()));
			
			// GCM Algo
			Cipher ci = Cipher.getInstance("AES/GCM/PKCS5Padding");			
			final byte[] nonce = new byte[12];
			SecureRandom random = new SecureRandom();
	        random.nextBytes(nonce);System.out.println("nonce : "+bytesToHex(nonce));	        
	        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);        
			
	        
			
			//Encrypt
			ci.init(Cipher.ENCRYPT_MODE, key, spec);
			FileOutputStream fs = new FileOutputStream(path+"cipher.txt");
	        CipherOutputStream out = new CipherOutputStream(fs, ci);
	        out.write(input);
	        out.close();
			
			
			//Decrypt
			ci.init(Cipher.DECRYPT_MODE, key, spec);
			FileInputStream fis = new FileInputStream(path+"cipher.txt");
	        CipherInputStream in = new CipherInputStream(fis,ci);
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] b = new byte[1024];
            int numberOfBytedRead;
            while ((numberOfBytedRead = in.read(b)) >= 0) {
                baos.write(b, 0, numberOfBytedRead);
            }
            System.out.println(new String(baos.toByteArray()));            
			in.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
	}
	
}
