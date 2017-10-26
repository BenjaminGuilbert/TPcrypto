import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AsymetricEncryption {

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
		
		//System.out.println("PlainText : "+bytesToHex(plainText1));
		
		String message = "Comme je l’aime le vent d’automne\n" + 
						"quand je l’entends à ma fenêtre\n" + 
						"Et qu’il sonne";
		System.out.println("PlainText : "+message);
		
		//Generate Key Pair of RSA
		KeyPair keyPair = generateKeyPairRSA();
		
		//Encrypt Message
		byte[] cipherText = encryptMessage(message.getBytes(), keyPair.getPublic());
		
		//Decrypt Message
		byte[] plainText = decryptMessage(cipherText, keyPair.getPrivate());
		
		System.out.println(new String(plainText));
		
	}
	
	/**
	 * Generate Key pair of RSA
	 * @return Key Pair
	 */
	public static KeyPair generateKeyPairRSA() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048,  new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();
			
			System.out.println("Private Key : "+ keyPair.getPrivate());
			System.out.println("Public Key : "+ keyPair.getPublic());
			
			
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	
	public static byte[] encryptMessage(byte[] input, PublicKey key) {
		
		try {
			//Encrypt
			Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] cipherText = cipher.doFinal(input);
			System.out.println("cipher: " + bytesToHex(cipherText));
			return cipherText;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] decryptMessage(byte[] input, PrivateKey key) {
		
		try {
			//Decrypt
			Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] data = cipher.doFinal(input);
			System.out.println("message: " + bytesToHex(data));
			return data;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
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

}
