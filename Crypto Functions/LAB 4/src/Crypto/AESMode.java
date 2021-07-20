package Crypto;

import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException; 

public class AESMode {
	static Scanner sc = new Scanner(System.in);
	// Secret key
	public static SecretKey createAESKey(String fileName, int bit) throws Exception{
		File file = new File(fileName);
		int byteSize = bit/8;
	    
	    //Saving or Retrieving key
        if (file.createNewFile()) {
            System.out.println("AES Key File has been created...");
            SecureRandom securerandom = new SecureRandom();
		    KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
		    keygenerator.init(bit, securerandom);
		    SecretKey key = keygenerator.generateKey();
    	    try{  
    	        byte[] data = key.getEncoded();
    	        FileOutputStream fos = new FileOutputStream(fileName);
    	        fos.write(data);   
    	        fos.close();
    	    }catch(Exception e){
    	    	System.out.println(e);}    
    	    System.out.println("AES key write Success...");   
    	    return key;
       }
        
       else {
           System.out.println("AES key file has been read.");
           byte[] keybyte = new byte[byteSize];
           FileInputStream fin = new FileInputStream(fileName);
           fin.read(keybyte);
           SecretKey retrieved_key = new SecretKeySpec(keybyte, 0, byteSize, "AES");
           fin.close();
           return retrieved_key;
       }
        
	}
	
	// initialize a vector with an arbitrary value
	public static byte[] createInitializationVector(int byteSize) {
	    byte[] initializationVector = new byte[byteSize];
	    SecureRandom secureRandom = new SecureRandom();
	    secureRandom.nextBytes(initializationVector);
	    return initializationVector;
	}
	
	// AES_ECB Encryption
	public static byte[] do_AESEncryption(String plainText, SecretKey secretKey, String AESMode) throws Exception{
		
	    Cipher cipher = Cipher.getInstance(AESMode);
	    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	    return cipher.doFinal(plainText.getBytes());
	}

	// AES_CFB Encryption
	public static byte[] do_AESEncryption(String plainText, SecretKey secretKey, 
			byte[] initializationVector, String AESMode) throws Exception{
		
	    Cipher cipher = Cipher.getInstance(AESMode);
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
	    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
	    return cipher.doFinal(plainText.getBytes());
	}
	
	// AES_ECB decryption
	public static String do_AESDecryption(byte[] cipherText, SecretKey secretKey, String AESMode) throws Exception {
	    
		Cipher cipher = Cipher.getInstance(AESMode);
	    cipher.init(Cipher.DECRYPT_MODE, secretKey);
	    byte[] result = cipher.doFinal(cipherText);
	    return new String(result);
	}

	// AES_CFB Decryption
	public static String do_AESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector, 
			String AESMode) throws Exception {
	    
		Cipher cipher = Cipher.getInstance(AESMode);
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
	    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
	    byte[] result = cipher.doFinal(cipherText);
	    return new String(result);
	}
	
	public static byte[] readIV(String fileName, int byteSize) throws IOException {
        File fin = new File(fileName);
        if(fin.createNewFile()) {
        	System.out.println("IV File has been created.");
        	byte[] iv = createInitializationVector(byteSize);
        	FileOutputStream fos = new FileOutputStream(fileName);
	        fos.write(iv);   
	        fos.close();
        }
        System.out.println("IV has been read from the file");
        FileInputStream fos = new FileInputStream(fileName);
        byte[] iv = new byte[fos.available()];
        fos.read(iv);
        fos.close();
        return iv;
	}
	
	public static void startECB(int bit, String AESMode) throws Exception {
		
		long start, end, timeElapsed;
		SecretKey Symmetrickey = createAESKey("ECB_" + Integer.toString(bit) + "_key.txt", bit);
		System.out.println("The Symmetric Key is :" + DatatypeConverter.printHexBinary(Symmetrickey.getEncoded()));
		String plainText = Helper.readLines("Message.txt");
		System.out.println("Original PlainText: "+ plainText);
		
		System.out.print("Enter 1 for Encrytion and 2 for Decryption: ");
		int option = sc.nextInt();
		
		if (option == 1) {
		    System.out.println("Message.txt file is about to be encrypted");
		    //Encrypting the message using the symmetric key
		    start = System.currentTimeMillis();
		    byte[] cipherText = do_AESEncryption(plainText, Symmetrickey, AESMode);
		    end = System.currentTimeMillis();
			timeElapsed = end - start;
			System.out.println("ECB encryption time "+ "for " + bit + " : " + timeElapsed + " millis");
			
		    Helper.saveEncrypted(cipherText, "ECB_" + Integer.toString(bit) + "_Encrypted.txt");
		    System.out.println("Encrypted Message is: " + DatatypeConverter.printHexBinary(cipherText));
		}
		
		else if(option == 2) {
		    // Decrypting the encrypted message
		    byte[] raw = Helper.readEncrypted("ECB_" + Integer.toString(bit) + "_Encrypted.txt");
		    System.out.println("File is about to be decrypted");
		    start = System.currentTimeMillis();
		    String decryptedText = do_AESDecryption(raw, Symmetrickey, AESMode);
		    end = System.currentTimeMillis();
		    timeElapsed = end - start;
			System.out.println("ECB decryption time "+ "for " + bit + " : " + timeElapsed + " millis");
		    System.out.println("Your decrypted message is: "+ decryptedText);
		}
		
	}
	
	public static void startCFB(int bit, String AESMode) throws Exception {
		
		long start, end, timeElapsed;
		
		SecretKey Symmetrickey = createAESKey("CFB_" + Integer.toString(bit) + "_key.txt", bit);
		byte[] initializationVector = readIV("CFB_" + Integer.toString(bit) + "_iv.txt", 16);
		
	    System.out.println("The Symmetric Key is :" + DatatypeConverter.printHexBinary(Symmetrickey.getEncoded()));
	    System.out.println("Initialization Vector is: " + DatatypeConverter.printHexBinary(initializationVector));
	    String plainText = Helper.readLines("Message.txt");
	    System.out.println("Original PlainText: " + plainText);
	    
	    System.out.print("Enter 1 for Encrytion and 2 for Decryption: ");
	    int option = sc.nextInt();
	    
	    if(option == 1) {
		    // Encrypting the message using the symmetric key
		    System.out.println("Message.txt file is about to be encrypted");
		    
		    start = System.currentTimeMillis();
		    byte[] cipherText = do_AESEncryption(plainText, Symmetrickey, initializationVector, AESMode);
		    end = System.currentTimeMillis();
		    timeElapsed = end - start;
			System.out.println("CFB Enryption time "+ "for " + bit + " : " + timeElapsed + " millis");
			
		    Helper.saveEncrypted(cipherText, "CFB_" + Integer.toString(bit) + "_Encrypted.txt");
		    System.out.println("Encrypted Message is: " + DatatypeConverter.printHexBinary(cipherText));
	    }
	    
	    else if(option == 2) {
	    	// Decrypting the encrypted message
		    byte[] raw = Helper.readEncrypted("CFB_" + Integer.toString(bit) + "_Encrypted.txt");
		    System.out.println("File is about to be decrypted");
		    
		    start = System.currentTimeMillis();
		    String decryptedText = do_AESDecryption(raw, Symmetrickey, initializationVector, AESMode);
		    end = System.currentTimeMillis();
		    timeElapsed = end - start;
			System.out.println("CFB Deryption time "+ "for " + bit + " : " + timeElapsed + " millis");
		    System.out.println("Your decrypted message is: "+ decryptedText);
	    }
		
	}
	
	public void AES() throws Exception{
		String AESMode;
		int bit, mode;
		Scanner sc = new Scanner(System.in);
		System.out.print("For ECB Enter 1, for CFB Enter 2: ");
		mode = sc.nextInt();
		System.out.print("Enter bit size 128/192/256: ");
		bit = sc.nextInt();
		if(mode == 1) {
			AESMode = "AES/ECB/PKCS5PADDING";
			startECB(bit, AESMode);
		}
		else {
			AESMode = "AES/CFB/PKCS5PADDING";
			startCFB(bit, AESMode);
		}
		
	}

}
