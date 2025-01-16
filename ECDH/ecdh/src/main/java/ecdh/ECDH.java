package ecdh;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDH {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Method to generate ECC Key Pair
    public KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp521r1")); // Key size can be 256, 384, or 521 bits
        return keyPairGenerator.generateKeyPair();
    }

    // Method to generate ECDH shared secret
    public static byte[] generateECDHSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    // Method to encrypt data using ECC Public Key
    public static byte[] encryptWithECC(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC"); // ECIES is often used for ECC encryption
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Method to decrypt data using ECC Private Key
    public static byte[] decryptWithECC(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    // Generate PublicKey from encoded key bytes
    public static PublicKey getPublicKeyFromEncoded(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    // Generate PrivateKey from encoded key bytes
    public static PrivateKey getPrivateKeyFromEncoded(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        return keyFactory.generatePrivate(keySpec);
    }
}

