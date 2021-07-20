package Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.stream.Stream;

public class Helper {
	
	public static String readLines(String filePath) {
        StringBuilder contentBuilder = new StringBuilder();
        try (Stream<String> stream = Files.lines( Paths.get(filePath), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }
	
	public static byte[] readEncrypted(String fileName) throws NullPointerException, Exception {
		File tempFile = new File(fileName);
		boolean exists = tempFile.exists();
		if (exists == false) {
			System.out.println("Encryption file doesn't exist. First create one. System Exited.");
			Main.main(null);
		}
		
        FileInputStream fin = new FileInputStream(fileName);
        byte[] textbyte = new byte[fin.available()];
        fin.read(textbyte);
        fin.close();
        System.out.println("Encrypted file has been read...");
        return textbyte;
	}
	
	public static void saveEncrypted(byte[] cipherText, String fileName) throws IOException{
		File file = new File(fileName);
		
        if (file.createNewFile()) {
    	    try{      
    	        FileOutputStream fos = new FileOutputStream(fileName);
    	        fos.write(cipherText);   
    	        fos.close();
    	    }catch(Exception e){
    	    	System.out.println(e);
    	    }    
    	    System.out.println("Encryption file Created...");    
       }  
       else {
           System.out.print("Encryption file already exists. If you want to overwrite Enter 1, else Enter any other int: ");
           Scanner overWrite = new Scanner(System.in);
           int opt = overWrite.nextInt();
           if(opt == 1) {
        	   //System.out.println(" Hye");
	       	    try{      
	       	    	file.delete();
	       	        FileOutputStream fos = new FileOutputStream(fileName);
	       	        fos.write(cipherText);   
	       	        fos.close();
	       	     System.out.println("Encryption file has been overwritten...");
	       	    }catch(Exception e){
	       	    	System.out.println(e);
	       	    }    
           }
       }
	}

}
