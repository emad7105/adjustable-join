package be.heydari.adjenc.buildingblocks;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * @author Emad Heydari Beni
 */
public class Random {

    private SecureRandom random;

    public Random() {
    }

    public Random(String secureRandomAlg) {
        addSecurityProvider(secureRandomAlg);
    }

    public byte[] generate(int size) {
        byte[] randomBytes = new byte[size];
        random.nextBytes(randomBytes);
        return randomBytes;
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
