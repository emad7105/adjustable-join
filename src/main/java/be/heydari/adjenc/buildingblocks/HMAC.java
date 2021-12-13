package be.heydari.adjenc.buildingblocks;

import com.google.common.base.Charsets;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 *
 * This HMAC implementation is based on the
 *  Blake2b construction.
 *
 * @author Emad Heydari Beni
 */
public class HMAC {

    private SecureRandom random;
    private int keyLength;
    private int digestSize;

    public HMAC(String secureRandomAlg, int keyLength, int digestSize) {
        addSecurityProvider(secureRandomAlg);
        this.keyLength = keyLength;
        this.digestSize = digestSize;
    }

    public byte[] generateKey(int length) {
        byte[] ivBytes = new byte[length];
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    public byte[] getKeyFromHex(String hex) {
        return Hex.decode(hex);
    }

    public byte[] generateKey() {
        byte[] ivBytes = new byte[keyLength];
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    public byte[] hash(String message, String key) {
        return hash(message.getBytes(Charsets.UTF_8), key.getBytes(Charsets.UTF_8));
    }

    public byte[] hash(byte[] message, byte[] key) {
        HMac hmac = new HMac(new Blake2bDigest(digestSize));
        hmac.init(new KeyParameter(key));
        byte[] result = new byte[hmac.getMacSize()];

        hmac.update(message, 0, message.length);
        hmac.doFinal(result, 0);

        return result;
    }

    public byte[] hash(String message, byte[] key) {
        return hash(message.getBytes(Charsets.UTF_8), key);
    }

    private void addSecurityProvider(String secureRandomAlg) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
