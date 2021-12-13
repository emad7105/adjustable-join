package be.heydari.adjenc.buildingblocks;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author Emad Heydari Beni
 */
public class Hash {

    public Hash() {
    }

    public byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        return shaXXX(data, "256");
    }

    public byte[] sha512(byte[] data) throws NoSuchAlgorithmException {
        return shaXXX(data, "512");
    }

    private byte[] shaXXX(byte[] data, String size) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-" + size);
        md.update(data);
        return md.digest();
    }
}
