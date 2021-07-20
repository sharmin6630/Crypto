package Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignature {
	
	static Scanner sc = new Scanner(System.in);
	
	public static byte[] sign(String plainText, PrivateKey privateKey) throws Exception {
	    Signature privateSignature = Signature.getInstance("SHA256withRSA");
	    privateSignature.initSign(privateKey);
	    privateSignature.update(plainText.getBytes(UTF_8));
	    byte[] signature = privateSignature.sign();
	    return signature;
	}
	
	public static void saveSign(byte[] sign, String fileName) throws IOException {
		File file = new File(fileName);
        if (file.createNewFile()) {
    	    try{   
    	        FileOutputStream fos = new FileOutputStream(fileName);
    	        fos.write(sign);   
    	        fos.close();
    	        System.out.println("Signature File has been created.");
    	    }catch(Exception e){
    	    	System.out.println(e);
    	    }       
       }  
       else {
           System.out.println("Signature file already exists. If you want to overwrite Enter 1, else Enter any other int:");
           Scanner overWrite = new Scanner(System.in);
           int opt = overWrite.nextInt();
           if(opt == 1) {
        	   try{      
        		   FileOutputStream fos = new FileOutputStream(fileName);
       	        	fos.write(sign);   
       	        	fos.close();
       	    	}catch(Exception e){
       	    		System.out.println(e);
       	    	}  
	       	    System.out.println("Signature file has been overwritten...");
           }
       }
	}
	
	public static byte[] readSign(String fileName) throws NullPointerException, Exception {
		File tempFile = new File(fileName);
		boolean exists = tempFile.exists();
		if (exists == false) {
			System.out.println("Signature file doesn't exist. First create one. System Exited.");
			Main.main(null);
		}
		FileInputStream fin = new FileInputStream(fileName);
        byte[] textbyte = new byte[fin.available()];
        fin.read(textbyte);
        fin.close();
        System.out.println("RSA Signature File has been read...");
        return textbyte;
	}
	
	public static boolean verify(String plainText, String signFile, PublicKey publicKey) throws Exception {
	    Signature publicSignature = Signature.getInstance("SHA256withRSA");
	    publicSignature.initVerify(publicKey);
	    publicSignature.update(plainText.getBytes(UTF_8));

	    //byte[] signatureBytes = Base64.getDecoder().decode(readSign(signFile));
	    byte[] signatureBytes = readSign(signFile);
	    System.out.println("Signature file has been verified...");
	    return publicSignature.verify(signatureBytes);
	}
	
	
	public KeyPair loadKeyPair(String filePKey, String fileSKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
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
	
	public void startRSASignature() throws Exception {
		System.out.print("Enter bit 1024/2048/4096: ");
		int bit = sc.nextInt();
		
		String plainText = Helper.readLines("Message.txt");
		System.out.println(plainText);
		RSAMode.createRSAKey("RSA_Signature" + "_PublicKey.txt", "RSA_Signature" +  "_PrivateKey.txt", bit);
		KeyPair kpair = RSAMode.loadKeyPair("RSA_Signature" + "_PublicKey.txt", "RSA_Signature" + "_PrivateKey.txt");
		
		PublicKey pbKey = kpair.getPublic();
		PrivateKey sbKey = kpair.getPrivate();
	    System.out.println("The Public Key is :" + DatatypeConverter.printHexBinary(pbKey.getEncoded()));
	    System.out.println("The Private Key is :" + DatatypeConverter.printHexBinary(sbKey.getEncoded()));
	    
	    System.out.print("Enter 1 to create signature, 2 for verfying signature: ");
		int opt = sc.nextInt();
		if (opt == 1) {
			long start = System.currentTimeMillis();
			byte[] signature = sign(plainText, sbKey);
			long end = System.currentTimeMillis();
			System.out.println("Time to create Signature "+ "of "+ bit+ " : "+ (end - start) + " millis");
			saveSign(signature, "RSA_Signature_" + Integer.toString(bit)+ "_File.txt");
			System.out.println("Signature is: " + DatatypeConverter.printHexBinary(readSign("RSA_Signature_" + Integer.toString(bit)+ "_File.txt")));
		
		}
		else if (opt == 2) {
			//Let's check the signature
			long start = System.currentTimeMillis();
			boolean isCorrect = verify(plainText, "RSA_Signature_" + Integer.toString(bit)+ "_File.txt", pbKey);
			long end = System.currentTimeMillis();
			System.out.println("Time to verify Signature "+ "of "+ bit + " : "+ (end - start) + " millis");
			System.out.println("Signature correct: " + isCorrect);
		}
	}
}
