
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This tool will encrypt any plain file with AES encryption and then Base64 encode it into a text file. 
 * It will generate a symmetric secret key used for the AES encryption.
 * The secret key will be encrypted with RSA public encryption and stored in a key file.
 * To decrypt the file at a later date, the RSA private key will be required to decrypt the AES key file.
 * 
 * This tool will generate the public/private key pair files if none exists.
 * 
 * Optionally, to generate using OpenSSL: 
 * 
 * openssl genrsa -out private_rsa.pem 2048
 * openssl pkcs8 -topk8 -in private_rsa.pem -outform PEM -out private.pem -nocrypt
 * openssl rsa -in private.pem -pubout -outform PEM -out public.pem
 * 
 * If you prefer different key sizes or different ciphers, then modify this code to suite.
 * The chosen values are available in Java 8 without the need for any additional libraries. 
 * 
 * @author Darian Bridge.
 */
public class CryptoEncoder
{
    public static final int AES_KEY_SIZE = 128;
    public static final int RSA_KEY_SIZE = 2048;
    
    private static final int PEM_LINE_LENGTH = 62;
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");
    
    /**
     * http://www.macs.hw.ac.uk/~ml355/lore/pkencryption.htm
     *
     * https://stackoverflow.com/questions/11787571/how-to-read-pem-file-to-get-private-and-public-key
     * https://stackoverflow.com/questions/3313020/write-x509-certificate-into-pem-formatted-string-in-java
     */
    public static void main(final String[] args) throws Exception
    {
        String operation = args.length < 2 ? null : args[0];
        String secretKeyfile = args.length < 3 ? "keyfile.txt" : args[2];
        String publicKeyfile = args.length < 4 ? "public.pem" : args[3];
        String privateKeyfile = args.length < 5 ? "private.pem" : args[4];
        
        if ("encode".equalsIgnoreCase(operation))
        {
            SecretKey secretKey = getKey(operation, secretKeyfile, publicKeyfile, privateKeyfile);
            
            if (secretKey != null)
            {
                encode(args[1], secretKey);
            }
        }
        else if ("decode".equalsIgnoreCase(operation))
        {
            SecretKey secretKey = getKey(operation, secretKeyfile, publicKeyfile, privateKeyfile);
            
            if (secretKey != null)
            {
                decode(args[1], secretKey);
            }
        }
        else
        {
            System.out.println("usage: " + CryptoEncoder.class.getSimpleName() + " operation filename [keyfile.txt] [public.pem] [private.pem]");
            System.out.println("    operation := encode | decode");
        }
    }
    
    public static SecretKey getKey(final String operation, final String secretKeyfile, final String publicKeyfile, final String privateKeyfile) throws Exception
    {
        PublicKey publicKey = null;
        
        if (new File(publicKeyfile).exists())
        {
            publicKey = getPublicKey(publicKeyfile);
        }
        
        
        PrivateKey privateKey = null;
        
        if (new File(privateKeyfile).exists() && publicKey != null)
        {
            privateKey = getPrivateKey(privateKeyfile);
        }
        
        if (publicKey == null)
        {
            KeyPair pair = genKeyPair(publicKeyfile, privateKeyfile);
            
            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();
        }
        
        
        if (new File(secretKeyfile).exists() && privateKey != null)
        {
            SecretKey secretKey = getSecretKey(secretKeyfile, privateKey);
            return secretKey;
        }
        
        if (!new File(secretKeyfile).exists() && publicKey != null)
        {
            SecretKey secretKey = genSecretKey(secretKeyfile, publicKey);
            return secretKey;
        }
        
        return null;
    }
    
    public static void decode(final String filename, final SecretKey secretKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        try (InputStream input = Base64.getMimeDecoder().wrap(new FileInputStream(filename + ".txt"));
                OutputStream output = new CipherOutputStream(new FileOutputStream(filename), cipher))
        {
            System.out.println("Decrypting file     : " + filename);
            
            copy(input, output);
        }
    }
    
    public static void encode(final String filename, final SecretKey secretKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        try (InputStream input = new FileInputStream(filename);
                OutputStream output = new CipherOutputStream(Base64.getMimeEncoder().wrap(new FileOutputStream(filename + ".txt")), cipher))
        {
            System.out.println("Encrypting file     : " + filename);
            
            copy(input, output);
        }
    }
    
    public static PublicKey getPublicKey(final String publicKeyfile) throws Exception
    {
        System.out.println("Reading public key  : " + publicKeyfile);
        
        try (InputStream input = Base64.getMimeDecoder().wrap(new FileInputStream(publicKeyfile));
                ByteArrayOutputStream output = new ByteArrayOutputStream())
        {
            // Read public key.
            
            copy(input, output);
            byte[] bytes = output.toByteArray();
            
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        }
    }
    
    public static PrivateKey getPrivateKey(final String privateKeyfile) throws Exception
    {
        System.out.println("Reading private key : " + privateKeyfile);
        
        try (InputStream input = Base64.getMimeDecoder().wrap(new FileInputStream(privateKeyfile));
                ByteArrayOutputStream output = new ByteArrayOutputStream())
        {
            // Read private key.
            
            copy(input, output);
            byte[] bytes = output.toByteArray();
            
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        }
    }
    
    public static KeyPair genKeyPair(final String publicKeyfile, final String privateKeyfile) throws Exception
    {
        // Create public/private key pair.
        
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
        pairGen.initialize(RSA_KEY_SIZE);
        KeyPair pair = pairGen.genKeyPair();
        
        System.out.println("Writing public key  : " + publicKeyfile);
        
        try (InputStream input = new ByteArrayInputStream(pair.getPublic().getEncoded());
                OutputStream output = Base64.getMimeEncoder(PEM_LINE_LENGTH, LINE_SEPARATOR.getBytes()).wrap(new FileOutputStream(publicKeyfile)))
        {
            copy(input, output);
        }
        
        System.out.println("Writing private key : " + privateKeyfile);
        
        try (InputStream input = new ByteArrayInputStream(pair.getPrivate().getEncoded());
                OutputStream output = Base64.getMimeEncoder(PEM_LINE_LENGTH, LINE_SEPARATOR.getBytes()).wrap(new FileOutputStream(privateKeyfile)))
        {
            copy(input, output);
        }
        
        return pair;
    }
    
    public static SecretKey getSecretKey(final String secretKeyfile, final PrivateKey privateKey) throws Exception
    {
        // Load a saved Secret Key and decrypt it.
        
        System.out.println("Reading secret key  : " + secretKeyfile);
        
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        try (InputStream input = new CipherInputStream(Base64.getMimeDecoder().wrap(new FileInputStream(secretKeyfile)), cipher);
                ByteArrayOutputStream output = new ByteArrayOutputStream())
        {
            copy(input, output);
            byte[] bytes = output.toByteArray();
            return new SecretKeySpec(bytes, "AES");
        }
    }
    
    public static SecretKey genSecretKey(final String secretKeyfile, final PublicKey publicKey) throws Exception
    {
        // Generate a new Secret Key and encrypt and it.
        
        System.out.println("Writing secret key  : " + secretKeyfile);
        
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        SecretKey secretKey = keyGen.generateKey();
        
        byte[] bytes = secretKey.getEncoded();
        
        try (InputStream input = new ByteArrayInputStream(bytes);
                OutputStream output = new CipherOutputStream(Base64.getMimeEncoder(PEM_LINE_LENGTH, LINE_SEPARATOR.getBytes()).wrap(new FileOutputStream(secretKeyfile)), cipher))
        {
            copy(input, output);
            return new SecretKeySpec(bytes, "AES");
        }
    }
    
    public static void copy(final InputStream input, final OutputStream output) throws IOException
    {
        int i;
        byte[] bytes = new byte[1024];
        
        while ((i = input.read(bytes)) != -1) 
        {
            output.write(bytes, 0, i);
        }
    }
}
