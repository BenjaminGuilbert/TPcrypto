import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class CheckIntegrity {

	public static void main(String[] args) {
		
		//Calculate Hash of a File
		try {
			Path path = Paths.get("/Users/benjaminguilbert/travail/Télécom/3eme Année/PMS/Pres_Crypto/message.txt");
			byte[] data = Files.readAllBytes(path);
			System.out.println("Message : "+new String(data, StandardCharsets.UTF_8));
			System.out.println("PlainText of bytes : "+bytesToHex(data));
			getHash(data);
			chechMAC(data);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Calculate Hash of a byte array
	 * @param input
	 */
	public static void getHash(byte[] input) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(input);
			System.out.println("Hash SHA-256 : "+bytesToHex(hash));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Calculate and Check the MAC of a byte array
	 * @param input
	 */
	public static void chechMAC(byte[] input) {
		
		try {
			//get a key generator
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
			//generate a secret key
			SecretKey key = keyGen.generateKey();
			//Create a Mac and initialize it with the above key
			Mac mac = Mac.getInstance(key.getAlgorithm());
			mac.init(key);
			
			//get the digest 
			byte[] digest = mac.doFinal(input);
			
			System.out.println("Mac SHA-256 : "+bytesToHex(digest));
			
		} catch (Exception e) {
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

}
