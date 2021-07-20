package Crypto;


import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException; 

public class RSAMode{
	static Scanner sc = new Scanner(System.in);
	
	// key generation
	public static void createRSAKey(String filePKey, String fileSKey, int bit) throws Exception{
		
		File filePK = new File(filePKey);
		File fileSK = new File(fileSKey);
		//Saving or Retrieving key
        if (filePK.createNewFile() && fileSK.createNewFile()) {
        	SecureRandom securerandom = new SecureRandom();
    		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    		keyPairGenerator.initialize(bit, securerandom);
    		KeyPair keyPair = keyPairGenerator.genKeyPair();
            RSAMode.saveKeyPair(keyPair, filePKey, fileSKey);
        }
        
	}
	
	// save keypair
	public static void saveKeyPair(KeyPair keyPair, String filePKey, String fileSKey) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(filePKey);
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		fos = new FileOutputStream(fileSKey);
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
		System.out.println("RSA Public and private Key File has been created...");
	}
	
	// RSA Encryption
	public byte[] do_RSAEncryption(String plainText, PublicKey publicKey) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
	}
	
	
	// RSA Decryption
	public String do_RSADecryption(byte[] cipherText, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
	}

	
	public static KeyPair loadKeyPair(String filePKey, String fileSKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		// Read Public Key.
		File filePublicKey = new File(filePKey);
		FileInputStream fis = new FileInputStream(filePKey);
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Read Private Key.
		File filePrivateKey = new File(fileSKey);
		fis = new FileInputStream(fileSKey);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		return new KeyPair(publicKey, privateKey);
	}
	
	
	
	public void startRSA() throws Exception {
		
		System.out.print("Enter bit 1024/2048/4096: ");
		int bit = sc.nextInt();
		
		long start, end, timeElapsed;
		
		createRSAKey("RSA_" + Integer.toString(bit) + "_PublicKey.txt", "RSA_" + Integer.toString(bit) + "_PrivateKey.txt", bit);
		KeyPair kpair = loadKeyPair("RSA_" + Integer.toString(bit) + "_PublicKey.txt", "RSA_" + Integer.toString(bit) + "_PrivateKey.txt");
		
		PublicKey pbKey = kpair.getPublic();
		PrivateKey sbKey = kpair.getPrivate();
	    System.out.println("The Public Key is :" + DatatypeConverter.printHexBinary(pbKey.getEncoded()));
	    System.out.println("The Private Key is :" + DatatypeConverter.printHexBinary(sbKey.getEncoded()));
	    
	    String plainText = Helper.readLines("Message.txt");
	    System.out.println("Original PlainText: " + plainText);
	    
	    System.out.print("Enter 1 for Encrytion and 2 for Decryption: ");
		int option = sc.nextInt();
		
		if(option == 1) {
		    System.out.println("Message.txt file is about to be encrypted");
		    
		    // Encrypting the message
		    start = System.currentTimeMillis();
		    byte[] cipherText = do_RSAEncryption(plainText, pbKey);
		    end = System.currentTimeMillis();
		    timeElapsed = end - start;
		    System.out.println("RSA encryption time "+ "for " + bit + " : " + timeElapsed + " millis");
		    
		    Helper.saveEncrypted(cipherText, "RSA_" + Integer.toString(bit) + "_Encrypted.txt");
		    System.out.println("Encrypted Message is: " + DatatypeConverter.printHexBinary(cipherText));
		}
		
		else if(option == 2) {
			// Decrypting the encrypted message
		    byte[] raw = Helper.readEncrypted("RSA_" + Integer.toString(bit) + "_Encrypted.txt");
		    System.out.println("File is about to be decrypted");
		    start = System.currentTimeMillis();
		    String decryptedText = do_RSADecryption(raw, sbKey);
		    end = System.currentTimeMillis();
		    timeElapsed = end - start;
		    System.out.println("RSA Decryption time "+ "for " + bit + " : " + timeElapsed + " millis");
		    System.out.println("Your decrypted message is: "+ decryptedText);
		}
		
	}
	

}
