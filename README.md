# Security_Lab_Assignments

### Programming Symmetric & Asymmetric Crypto

1. Program Functionalities:
 - AES encryption and decryption ECB mode (128/192/256)
 - AES encryption and decryption CFB mode (128/192/256)
 - RSA encryption and decryption (1024/2048/4096)
 - RSA Signature and Verification (1024/2048/4096)
 - SHA256 HASH

2. Execution Details:
 - User will be given the option for AES/RSA/RSA Signature/SHA-256 Hash/quit for different keys (1-5). 
 
  ![](https://github.com/sharmin6630/Security_Lab_Assignments/blob/main/1.png)

 - Then if chosen an option he would asked for bit size (AES-128/192/256 | RSA-1024/2048/4096).
 - On the first instance of a selected option respective keys would be generated and saved in a file. Later the keys would be read from the respective files.
 - If Selected AES/RSA users will be asked for encryption or decryption option. If Selected RSA Signature then the user will be asked to generate Signature or Validate Signature.
 - Upon selection pre-existing 'Message.txt' file will be read and printed on the console.
 - If encryption is selected, the mentioned file text would be encrypted and resulted encryption would be saved in a file and printed on console. If an encryption file already existed user would be prompted to overwrite the encrypted file or not.
 - If decryption is selected, the program would read the existing encrypted file and execute decryption. The decrypted message would be printed on the console. But if the encryption file doesn't exist then the user would be asked to make encryption first. The user will be given the initial options again. 
  
  ![](https://github.com/sharmin6630/Security_Lab_Assignments/blob/main/2.png)

 - Same thing would happen for RSA Signature as well. If the signature generate option is selected a signature file for the 'Message.txt' file would be created and result would be printed. If the signature file already existed user would be prompted to overwrite the signature file or not.
 - If signature validation option is chosen then existed signature file would be validated and result would be printed. If a signature file doesn't exist then the user would be asked to generate a signature file first. The user will be given the initial options again. 

  ![](https://github.com/sharmin6630/Security_Lab_Assignments/blob/main/3.png)

 - If SHA256 hashing is selected then the 'Message.txt' file will be hashed and the resulted message digest would be saved and printed on the console. If the file existed already,  overwrite option will be prompted.

  ![](https://github.com/sharmin6630/Security_Lab_Assignments/blob/main/4.png)
  
 - Encryption, decryption, signature, validation, hash operation execution time would be printed as well.
 - If quit is chosen system will exit. Otherwise, the program would be executed in a loop.
 - Encrypted/hash outputs are printed as hexadecimal forms.

