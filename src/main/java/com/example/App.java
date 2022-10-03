package com.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class App {

    public static void main(String[] args) {
        String test = "9999999999999999";
        System.out.println("Input: " + test);

        try {
            // Generate AES Key
            KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");
            aesKeyGenerator.init(256);

            SecretKey aesKey = aesKeyGenerator.generateKey();

            // Initialize IV Vector
            byte[] iv = new byte[test.getBytes().length];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Encode AES
            Cipher cipherAES = Cipher.getInstance("AES");
            cipherAES.init(Cipher.ENCRYPT_MODE, aesKey);

            byte[] aesResult = cipherAES.doFinal(test.getBytes());

            // Generate RSA Key pair
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);     // MAX SIZE OF INPUT -> 256 bytes

            KeyPair keyPair = generator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Encode AES Key using RSA
            Cipher cipherRSA = Cipher.getInstance("RSA");
            cipherRSA.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            byte[] secretMessage = aesKey.getEncoded();
            byte[] encryptedAESKey = cipherRSA.doFinal(secretMessage);

            System.out.println("Raw String byte array: " + Arrays.toString(secretMessage));
            System.out.println("Raw String byte size: " + secretMessage.length);
            System.out.println("Encrypted String byte array: " + Arrays.toString(encryptedAESKey));
            System.out.println("Encrypted String byte size: " + encryptedAESKey.length);

            String aesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAESKey);

            // Decode AES Key
            Cipher decipher = Cipher.getInstance("RSA");
            decipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            byte[] decryptedAESKeyBase64 = Base64.getDecoder().decode(aesKeyBase64);

            byte[] decryptedMessage = decipher.doFinal(decryptedAESKeyBase64);
            System.out.println("Decrypted String byte array: " + Arrays.toString(decryptedMessage));

            String finalString = new String(decryptedMessage, StandardCharsets.UTF_8);
            System.out.println("Decrypted String: " + finalString);

            SecretKey finalAESKey = new SecretKeySpec(decryptedMessage, 0 , decryptedMessage.length, "AES");

            // Decode input with AES
            Cipher decipherAES = Cipher.getInstance("AES");
            decipherAES.init(Cipher.DECRYPT_MODE, finalAESKey);

            String result = new String(decipherAES.doFinal(aesResult));

            assert test.equals(result);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
