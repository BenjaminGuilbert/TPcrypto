import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class NumericSignature {

	public static void main(String[] args) {
		
		//Test of the provider
		Security.addProvider(new BouncyCastleProvider());
		if(Security.getProvider("BC") == null) {
			System.out.println("Provider not available");
		}
		else {
			System.out.println("Provider available");
		}
		
		//Sign the doc
		try {
			Path path = Paths.get("/Users/benjaminguilbert/travail/Télécom/3eme Année/PMS/Pres_Crypto/message.txt");
			byte[] data = Files.readAllBytes(path);
			System.out.println("Message : "+new String(data, StandardCharsets.UTF_8));
			
			//Generate Key pair
			KeyPair keyPair = generateKeyPair(path.getParent());
			
			//Sign the Doc
			byte[] signature = signDoc(path, keyPair.getPrivate());
			
			//Verify the signature of the doc
			Boolean result = verifySignatureOfDoc(path, keyPair.getPublic(), signature);
			System.out.println("Is signature correct ? "+result);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Generate a key pair
	 * Save each key in a file
	 * @param path where files will be saved
	 */
	public static KeyPair generateKeyPair(Path path) {
		System.out.println("Generating Key Pair:");
		try {
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
			
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
			keyGen.initialize(ecSpec, new SecureRandom());
			
			KeyPair keyPair = keyGen.generateKeyPair();
			
			//Save the private Key
			PrivateKey priv = keyPair.getPrivate();
			FileOutputStream writer = new FileOutputStream(path+"/private.key");
			writer.write(priv.getEncoded());
			writer.close();
			System.out.println("Private key saved in : "+path+"/private.key");
			
			//Save the public Key
			PublicKey pub = keyPair.getPublic();
			writer = new FileOutputStream(path+"/public.key");
			writer.write(pub.getEncoded());
			writer.close();
			System.out.println("Public key saved in : "+path+"/public.key");
			
			return keyPair;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
		
		
	}
	
	/**
	 * Sign a document with ECDSA Algorithm
	 * @param path of the document
	 * @param key the private key
	 */
	public static byte[] signDoc(Path path, PrivateKey key) {
		System.out.println("Sign the document:");
		try {
			byte[] data = Files.readAllBytes(path);
			
			Signature ecdsaSign = Signature.getInstance("ECDSA");
			ecdsaSign.initSign(key);
			ecdsaSign.update(data);
			byte[] signature = ecdsaSign.sign();
			System.out.println("Signature :"+bytesToHex(signature));
			return signature;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * Verify the signature of the document
	 * @param path of the document
	 * @param key the public key
	 * @param signature of the document
	 * @return
	 */
	public static Boolean verifySignatureOfDoc(Path path, PublicKey key, byte[] signature) {
		System.out.println("Verify the signature of the file:");
		try {
			byte[] data = Files.readAllBytes(path);
			
			Signature ecdsaVerify = Signature.getInstance("ECDSA");
			ecdsaVerify.initVerify(key);
			ecdsaVerify.update(data);
			
			return ecdsaVerify.verify(signature);			
			
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
