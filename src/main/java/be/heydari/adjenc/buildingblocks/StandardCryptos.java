package be.heydari.adjenc.buildingblocks;


/**
 * @author Emad Heydari Beni
 */
public class StandardCryptos {

    public HMAC hmac;
    public AES aes;
    public Hash hash;
    public Random random;

    public StandardCryptos(AES aes, Hash hash, HMAC hmac, Random random) {
        this.aes = aes;
        this.hash = hash;
        this.hmac = hmac;
        this.random = random;
    }

    public AES aes() {
        return aes;
    }


    public Hash hash() {
        return hash;
    }


    public HMAC hmac() {
        return hmac;
    }

    public Random random() {
        return random;
    }

    public AES getAes() {
        return aes;
    }

    public void setAes(AES aes) {
        this.aes = aes;
    }


    public Hash getHash() {
        return hash;
    }

    public void setHash(Hash hash) {
        this.hash = hash;
    }


    public HMAC getHmac() {

        return hmac;
    }

    public void setHmac(HMAC hmac) {
        this.hmac = hmac;
    }

    public Random getRandom() {
        return random;
    }

    public void setRandom(Random random) {
        this.random = random;
    }
}
