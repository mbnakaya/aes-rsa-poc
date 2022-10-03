package com.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class AppV2 {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String input = "9999999999999990";
        System.out.println("Input: " + input);

        try {
            Cipher cipher = configCipher(Cipher.ENCRYPT_MODE, publicKey);
            Cipher decipher = configCipher(Cipher.DECRYPT_MODE, privateKey);
            String encryptedInput = encrypt(cipher, input);
            String decryptedInput = decrypt(decipher,encryptedInput);

            if (!decryptedInput.equals(input)) throw new RuntimeException("ERROR: MISMATCH INPUT AND OUTPUT");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);     // MAX SIZE OF INPUT -> 256 bytes

        return generator.generateKeyPair();
    }

    private static Cipher configCipher(Integer cipherMode, Key key)throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(cipherMode, key);

        return cipher;
    }

    private static String encrypt(Cipher cipher, String input) throws IllegalBlockSizeException, BadPaddingException {
        byte[] secretMessage = input.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = cipher.doFinal(secretMessage);

        System.out.println("Raw String byte array: " + Arrays.toString(secretMessage));
        System.out.println("Raw String byte size: " + secretMessage.length);
        System.out.println("Encrypted String byte array: " + Arrays.toString(encryptedMessage));
        System.out.println("Encrypted String byte size: " + encryptedMessage.length);

        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    private static String decrypt(Cipher cipher, String encryptedInput) throws IllegalBlockSizeException, BadPaddingException {
        byte[] decodedBase64 = Base64.getDecoder().decode(encryptedInput);
        byte[] decryptedMessage = cipher.doFinal(decodedBase64);
        System.out.println("Decrypted String byte array: " + Arrays.toString(decryptedMessage));

        String result = new String(decryptedMessage, StandardCharsets.UTF_8);
        System.out.println("Decrypted String: " + result);

        return result;
    }
}
