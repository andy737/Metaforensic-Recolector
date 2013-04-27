package Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.NetworkInterface;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

/**
 * The Class AESCrypt.
 *
 * @author Vócali Sistemas Inteligentes
 */
public final class AESCrypt {

    /**
     * The Constant JCE_EXCEPTION_MESSAGE.
     */
    private static final String JCE_EXCEPTION_MESSAGE = "Por favor asegurate de tener instalado el "
            + "\"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files\" "
            + "(http://java.sun.com/javase/downloads/index.jsp) de aqui puedes descargarlo.";
    /**
     * The Constant RANDOM_ALG.
     */
    private static final String RANDOM_ALG = "SHA1PRNG";
    /**
     * The Constant DIGEST_ALG.
     */
    private static final String DIGEST_ALG = "SHA-256";
    /**
     * The Constant HMAC_ALG.
     */
    private static final String HMAC_ALG = "HmacSHA256";
    /**
     * The Constant CRYPT_ALG.
     */
    private static final String CRYPT_ALG = "AES";
    /**
     * The Constant CRYPT_TRANS.
     */
    private static final String CRYPT_TRANS = "AES/CBC/NoPadding";
    /**
     * The Constant DEFAULT_MAC.
     */
    private static final byte[] DEFAULT_MAC = {0x01, 0x23, 0x45, 0x67,
        (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
    /**
     * The Constant KEY_SIZE.
     */
    private static final int KEY_SIZE = 32;
    /**
     * The Constant BLOCK_SIZE.
     */
    private static final int BLOCK_SIZE = 16;
    /**
     * The Constant SHA_SIZE.
     */
    private static final int SHA_SIZE = 32;
    /**
     * The param.
     */
    private SecurityFile param = SecurityFile.getInstance();
    /**
     * The debug.
     */
    private final boolean DEBUG;
    /**
     * The password.
     */
    private byte[] password;
    /**
     * The cipher.
     */
    private Cipher cipher;
    /**
     * The hmac.
     */
    private Mac hmac;
    /**
     * The random.
     */
    private SecureRandom random;
    /**
     * The digest.
     */
    private MessageDigest digest;
    /**
     * The iv spec1.
     */
    private IvParameterSpec ivSpec1;
    /**
     * The aes key1.
     */
    private SecretKeySpec aesKey1;
    /**
     * The iv spec2.
     */
    private IvParameterSpec ivSpec2;
    /**
     * The aes key2.
     */
    private SecretKeySpec aesKey2;

    /**
     * ***************** PRIVATE METHODS * *****************.
     *
     * @param message the message
     */
    /**
     * Prints a debug message on standard output if DEBUG mode is turned on.
     */
    protected void debug(String message) {
        if (DEBUG) {
            System.out.println("[DEBUG] " + message);
        }
    }

    /**
     * Prints a debug message on standard output if DEBUG mode is turned on.
     *
     * @param message the message
     * @param bytes the bytes
     */
    protected void debug(String message, byte[] bytes) {
        if (DEBUG) {
            StringBuilder buffer = new StringBuilder("[DEBUG] ");
            buffer.append(message);
            buffer.append("[");
            for (int i = 0; i < bytes.length; i++) {
                buffer.append(bytes[i]);
                buffer.append(i < bytes.length - 1 ? ", " : "]");
            }
            System.out.println(buffer.toString());
        }
    }

    /**
     * Generates a pseudo-random byte array.
     *
     * @param len the len
     * @return pseudo-random byte array of <tt>len</tt> bytes.
     */
    protected byte[] generateRandomBytes(int len) {
        byte[] bytes = new byte[len];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * SHA256 digest over given byte array and random bytes.
     *
     * <tt>bytes.length</tt> * <tt>num</tt> random bytes are added to the
     * digest.
     *
     *
     * The generated hash is saved back to the original byte array.
     *
     * Maximum array size is {@link #SHA_SIZE} bytes.
     *
     * @param bytes the bytes
     * @param num the num
     */
    protected void digestRandomBytes(byte[] bytes, int num) {
        assert bytes.length <= SHA_SIZE;

        digest.reset();
        digest.update(bytes);
        for (int i = 0; i < num; i++) {
            random.nextBytes(bytes);
            digest.update(bytes);
        }
        System.arraycopy(digest.digest(), 0, bytes, 0, bytes.length);
    }

    /**
     * Generates a pseudo-random IV based on time and this computer's MAC.
     *
     *
     * This IV is used to crypt IV 2 and AES key 2 in the file.
     *
     * @return IV.
     */
    protected byte[] generateIv1() {
        byte[] iv = new byte[BLOCK_SIZE];
        long time = System.currentTimeMillis();
        byte[] mac = null;
        try {
            @SuppressWarnings("rawtypes")
            Enumeration ifaces = NetworkInterface.getNetworkInterfaces();
            while (mac == null && ifaces.hasMoreElements()) {
                mac = ((NetworkInterface) ifaces.nextElement())
                        .getHardwareAddress();
            }
        } catch (Exception e) {
            // Ignore.
        }
        if (mac == null) {
            mac = DEFAULT_MAC;
        }

        for (int i = 0; i < 8; i++) {
            iv[i] = (byte) (time >> (i * 8));
        }
        System.arraycopy(mac, 0, iv, 8, mac.length);
        digestRandomBytes(iv, 256);
        return iv;
    }

    /**
     * Generates an AES key starting with an IV and applying the supplied user
     * password.
     *
     *
     * This AES key is used to crypt IV 2 and AES key 2.
     *
     * @param iv the iv
     * @param password the password
     * @return AES key of {@link #KEY_SIZE} bytes.
     */
    protected byte[] generateAESKey1(byte[] iv, byte[] password) {
        byte[] aesKey = new byte[KEY_SIZE];
        System.arraycopy(iv, 0, aesKey, 0, iv.length);
        for (int i = 0; i < 8192; i++) {
            digest.reset();
            digest.update(aesKey);
            digest.update(password);
            aesKey = digest.digest();
        }
        return aesKey;
    }

    /**
     * Generates the random IV used to crypt file contents.
     *
     * @return IV 2.
     */
    protected byte[] generateIV2() {
        byte[] iv = generateRandomBytes(BLOCK_SIZE);
        digestRandomBytes(iv, 256);
        return iv;
    }

    /**
     * Generates the random AES key used to crypt file contents.
     *
     * @return AES key of {@link #KEY_SIZE} bytes.
     */
    protected byte[] generateAESKey2() {
        byte[] aesKey = generateRandomBytes(KEY_SIZE);
        digestRandomBytes(aesKey, 32);
        return aesKey;
    }

    /**
     * Utility method to read bytes from a stream until the given array is fully
     * filled.
     *
     * @param in the in
     * @param bytes the bytes
     * @throws IOException if the array can't be filled.
     */
    protected void readBytes(InputStream in, byte[] bytes) throws IOException {
        if (in.read(bytes) != bytes.length) {
            JOptionPane.showMessageDialog(null, "Fin de archivo inesperado",
                    "Error de archivo", JOptionPane.ERROR_MESSAGE);
            throw new IOException("Fin de archivo inesperado");
        }
    }

    /**
     * ************ PUBLIC API * ************.
     *
     * @param password the password
     * @throws GeneralSecurityException the general security exception
     * @throws UnsupportedEncodingException the unsupported encoding exception
     */
    /**
     * Builds an object to encrypt or decrypt files with the given password.
     *
     * @throws GeneralSecurityException if the platform does not support the
     * required cryptographic methods.
     * @throws UnsupportedEncodingException if UTF-16 encoding is not supported.
     */
    public AESCrypt(String password) throws GeneralSecurityException,
            UnsupportedEncodingException {
        this(false, password);
    }

    /**
     * Builds an object to encrypt or decrypt files with the given password.
     *
     * @param debug the debug
     * @param password the password
     * @throws GeneralSecurityException if the platform does not support the
     * required cryptographic methods.
     * @throws UnsupportedEncodingException if UTF-16 encoding is not supported.
     */
    public AESCrypt(boolean debug, String password)
            throws GeneralSecurityException, UnsupportedEncodingException {
        try {
            DEBUG = debug;
            setPassword(password);
            random = SecureRandom.getInstance(RANDOM_ALG);
            digest = MessageDigest.getInstance(DIGEST_ALG);
            cipher = Cipher.getInstance(CRYPT_TRANS);
            hmac = Mac.getInstance(HMAC_ALG);
        } catch (GeneralSecurityException e) {
            JOptionPane.showMessageDialog(null, JCE_EXCEPTION_MESSAGE,
                    "Error de Java ", JOptionPane.ERROR_MESSAGE);
            throw new GeneralSecurityException(JCE_EXCEPTION_MESSAGE, e);
        }
    }

    /**
     * Changes the password this object uses to encrypt and decrypt.
     *
     * @param password the new password
     * @throws UnsupportedEncodingException if UTF-16 encoding is not supported.
     */
    public void setPassword(String password)
            throws UnsupportedEncodingException {
        this.password = password.getBytes("UTF-16LE");
        debug("Password usado: ", this.password);
    }

    /**
     * The file at <tt>fromPath</tt> is encrypted and saved at <tt>toPath</tt>
     * location.
     *
     *
     * <tt>version</tt> can be either 1 or 2.
     *
     * @param version the version
     * @param fromPath the from path
     * @param toPath the to path
     * @throws IOException when there are I/O errors.
     * @throws GeneralSecurityException if the platform does not support the
     * required cryptographic methods.
     */
    public void encrypt(int version, String fromPath, String toPath)
            throws IOException, GeneralSecurityException {
        InputStream in = null;
        OutputStream out = null;
        @SuppressWarnings("UnusedAssignment")
        byte[] text = null;
        try {
            ivSpec1 = new IvParameterSpec(generateIv1());
            aesKey1 = new SecretKeySpec(generateAESKey1(ivSpec1.getIV(),
                    password), CRYPT_ALG);
            ivSpec2 = new IvParameterSpec(generateIV2());
            aesKey2 = new SecretKeySpec(generateAESKey2(), CRYPT_ALG);
            debug("IV1: ", ivSpec1.getIV());
            debug("AES1: ", aesKey1.getEncoded());
            debug("IV2: ", ivSpec2.getIV());
            debug("AES2: ", aesKey2.getEncoded());

            in = new FileInputStream(fromPath);
            debug("Abierto para la lectura: " + fromPath);
            out = new FileOutputStream(toPath);
            debug("Abierto para la escritura: " + toPath);

            out.write("AES".getBytes("UTF-8")); // Heading.
            out.write(version); // Version.
            out.write(0); // Reserved.
            if (version == 2) { // No extensions.
                out.write(0);
                out.write(0);
            }
            out.write(ivSpec1.getIV()); // Initialization Vector.

            text = new byte[BLOCK_SIZE + KEY_SIZE];
            cipher.init(Cipher.ENCRYPT_MODE, aesKey1, ivSpec1);
            cipher.update(ivSpec2.getIV(), 0, BLOCK_SIZE, text);
            cipher.doFinal(aesKey2.getEncoded(), 0, KEY_SIZE, text, BLOCK_SIZE);
            out.write(text); // Crypted IV and key.
            debug("IV2 + AES2 ciphertext: ", text);

            hmac.init(new SecretKeySpec(aesKey1.getEncoded(), HMAC_ALG));
            text = hmac.doFinal(text);
            out.write(text); // HMAC from previous cyphertext.
            debug("HMAC1: ", text);

            cipher.init(Cipher.ENCRYPT_MODE, aesKey2, ivSpec2);
            hmac.init(new SecretKeySpec(aesKey2.getEncoded(), HMAC_ALG));
            text = new byte[BLOCK_SIZE];
            int len, last = 0;
            while ((len = in.read(text)) > 0) {
                cipher.update(text, 0, BLOCK_SIZE, text);
                hmac.update(text);
                out.write(text); // Crypted file data block.
                last = len;
            }
            last &= 0x0f;
            out.write(last); // Last block size mod 16.
            debug("Último bloque de tamaño mod 16: " + last);

            text = hmac.doFinal();
            out.write(text); // HMAC from previous cyphertext.
            debug("HMAC2: ", text);
        } catch (InvalidKeyException e) {
            out.close();
            File tmp = new File(toPath);
            tmp.delete();
            JOptionPane.showMessageDialog(null, JCE_EXCEPTION_MESSAGE,
                    "Error de Java ", JOptionPane.ERROR_MESSAGE);
            throw new GeneralSecurityException(JCE_EXCEPTION_MESSAGE, e);
        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }
    }

    /**
     * Proceso encriptación
     *
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws GeneralSecurityException the general security exception
     */
    public void ProcessEn() throws IOException, GeneralSecurityException {
        encrypt(2, param.getIn(), param.getOut());
    }
}
