package Crypto;

import java.util.Scanner;

public class Main {
	
	public static AESMode aes = new AESMode();
	public static RSAMode rsa = new RSAMode();
	public static RSASignature sign = new RSASignature();
	public static SHA256 sha = new SHA256();
	public static void main(String[] args) throws Exception, NullPointerException{
		while(true) {
			System.out.println("--------------------------------------------------------------------------------------------------------------");
			System.out.println(" ");
			System.out.print("Enter 1 for AES, 2 for RSA, 3 for RSA Signature, 4 for SHA-256 hashing, 5 to quit: ");
			Scanner input = new Scanner(System.in);
			int opt = input.nextInt();
			
			if(opt == 1) {
				aes.AES();
			}
			else if(opt == 2)
				rsa.startRSA();
			
			else if (opt == 3){
				sign.startRSASignature();
			}
			
			else if(opt == 4) {
				sha.startSHA();
			}
			
			else if (opt == 5) {
				System.out.println("System Exited");
				System.exit(0);
			}
		}
	}

}