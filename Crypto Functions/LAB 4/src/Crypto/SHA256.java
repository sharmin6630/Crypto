package Crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;
import static java.nio.charset.StandardCharsets.UTF_8;

public class SHA256 {
	
	public static byte[] do_SHA(String input) throws NoSuchAlgorithmException, IOException{ 
        // Static getInstance method is called with hashing SHA 256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] data = input.getBytes(UTF_8);
        md.update(data);
        // digest() method called to calculate message digest of an input
        byte[] digest = md.digest();
        return digest;
    }
	
	public static void saveDigest(byte[] digest, String fileName) throws IOException {
		File file = new File(fileName);
        if (file.createNewFile()) {
            System.out.println("Hash File has been created.");
    	    try{      
    	        FileOutputStream fos = new FileOutputStream(fileName);
    	        fos.write(digest);   
    	        fos.close();
    	    }catch(Exception e){
    	    	System.out.println(e);
    	    }       
       }  
       else {
           System.out.print("Hash file already exists. If you want to overwrite Enter 1, else Enter any other int: ");
           Scanner overWrite = new Scanner(System.in);
           int opt = overWrite.nextInt();
           if(opt == 1) {
	       	    try{      
	       	        FileOutputStream fos = new FileOutputStream(fileName);
	       	        fos.write(digest);   
	       	        fos.close();
	       	    }catch(Exception e){
	       	    	System.out.println(e);
	       	    }    
	       	    System.out.println("Hash file has been overwritten...");
           }
       }
	}
	
	public static byte[] readDigest(String fileName) throws IOException {
		
		FileInputStream fin = new FileInputStream(fileName);
        byte[] textbyte = new byte[fin.available()];
        fin.read(textbyte);
        fin.close();
        System.out.println("Digest File has been read...");
        return textbyte;
	}
	
	public void startSHA() throws Exception {
		String plainText = Helper.readLines("Message.txt");
		System.out.println(plainText);
		long start = System.currentTimeMillis();
		byte[] digest= do_SHA(plainText);
		saveDigest(digest, "SHA_256" + "_Digest.txt");
		long end = System.currentTimeMillis();
		long elapsedTime = end - start;
		System.out.println("SHA-256 time " + elapsedTime + " millis");
		byte[] digestData = readDigest("SHA_256" + "_Digest.txt");
	    System.out.println("The Message Digest is :" + DatatypeConverter.printHexBinary(digestData));
	}

}
