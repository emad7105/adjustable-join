package be.heydari.adjenc;

import be.heydari.adjenc.buildingblocks.HMAC;
import be.heydari.adjenc.buildingblocks.Hash;
import be.heydari.adjenc.buildingblocks.MapToCurveSecP256k1;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @Author Emad Heydari Beni
 */
public class AdjustableScheme implements AdjustableSchemeInterface {

    private static final String DEFAULT_CURVE = "secp256k1";
    private static final int HMAC_KEY_SIZE = 256;
    private static final int HMAC_DIGEST_SIZE = 256;
    private static final String SECURE_RANDOM_ALG = "NativePRNG";


    private ECDomainParameters domainParams;
    MapToCurveSecP256k1 mapToCurveSecP256k1;
    HMAC hmac;

    public AdjustableScheme() {
        init(DEFAULT_CURVE);
    }


    private void init(String curve) {
        // preparing the curve
        hmac = new HMAC(SECURE_RANDOM_ALG, HMAC_KEY_SIZE, HMAC_DIGEST_SIZE);
        X9ECParameters ecp = SECNamedCurves.getByName(curve);
        domainParams = new ECDomainParameters(
                ecp.getCurve(),
                ecp.getG(),
                ecp.getN(),
                ecp.getH(),
                ecp.getSeed());
        mapToCurveSecP256k1 = new MapToCurveSecP256k1(hmac, new Hash(), DEFAULT_CURVE);
    }

    public byte[] genMessagePrfKey() {
        return hmac.generateKey();
    }

    public BigInteger genSecretKey() {
        return generateR(domainParams.getN(), CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Compute P <-- MapToCurve(PRF(message, prf-key)
     * Compute (sk)P
     */
    public ECPoint encrypt(byte[] message, byte[] messagePrfKey, BigInteger secretKey) throws NoSuchAlgorithmException {
        ECPoint P = mapToCurveSecP256k1.hmacToCurveECPoint(message, messagePrfKey);
        return P.multiply(secretKey).normalize();
    }

    public BigInteger genDeltaToken(BigInteger oldSecretKey, BigInteger newSecretKey) {
        BigInteger inverseOldSecretKey = oldSecretKey.modInverse(domainParams.getN());
        return inverseOldSecretKey.multiply(newSecretKey).mod(domainParams.getN());
    }

    /**
     * We know: deltaToken = newSk/oldSK; ciphertext = (oldSk)P
     * Computes (oldSk)(newSk/oldSk)P
     */
    public ECPoint adjust(BigInteger deltaToken, ECPoint ciphertext) {
        return ciphertext.multiply(deltaToken).normalize();
    }

    private static BigInteger generateR(BigInteger n, SecureRandom random) {
        int nBitLength = n.bitLength();
        BigInteger r;
        do {
            r = BigIntegers.createRandomBigInteger(nBitLength, random);
        }
        while (r.equals(ECConstants.ZERO) || (r.compareTo(n) >= 0));
        return r;
    }

    public ECPoint decodeEcPoint(byte[] encodedPoint) {
        return domainParams.getCurve().decodePoint(encodedPoint);
    }

    public byte[] encodeEcPoint(ECPoint p) {
        return p.getEncoded(true);
    }

}
