package be.heydari.adjenc.buildingblocks;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.miracl.core.SECP256K1.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

/**
 * Supported curve: secp256k1
 * Under the hood, the mapping is done by using MIRACL (https://github.com/miracl/core)
 *
 * @Author Emad Heydari Beni
 */
public class MapToCurveSecP256k1 {

    private static final String DEFAULT_CURVE_NAME = "secp256k1";
    private HMAC hmac;
    private Hash hash;
    private ECDomainParameters ecDomainParameters;

    public MapToCurveSecP256k1(HMAC hmac, Hash hash) {
        this.hmac = hmac;
        this.hash = hash;
        this.ecDomainParameters = prepareCurve(DEFAULT_CURVE_NAME);
    }

    public MapToCurveSecP256k1(HMAC hmac, Hash hash, String curveName) {
        this.hmac = hmac;
        this.hash = hash;
        this.ecDomainParameters = prepareCurve(curveName);
    }

    public ECDomainParameters prepareCurve(String curve) {
        X9ECParameters ecp = SECNamedCurves.getByName(curve);
        return new ECDomainParameters(
                ecp.getCurve(),
                ecp.getG(),
                ecp.getN(),
                ecp.getH(),
                ecp.getSeed());
    }

    public ECP mapToPoint(byte[] digest){
        // q (modulus) of secp256k1
        BIG q=new BIG(ROM.Modulus);

        // map to field
        DBIG dx = DBIG.fromBytes(digest);
        FP h = new FP(dx.mod(q));

        return ECP.map2point(h);
    }

    /*public byte[] toBytes(ECP p) {
        BIG x = p.getX();
        p.getx().
    }*/

    public ECP hashToCurve(byte[] message) throws NoSuchAlgorithmException {
        byte[] digest = hash.sha256(message);
        ECP ecp = mapToPoint(digest);
        return ecp;
    }

    public ECPoint hashToCurveECPoint(byte[] message) throws NoSuchAlgorithmException {
        ECP ecp = hashToCurve(message);
        return convertToECPoint(ecp);
    }

    public ECP hmacToCurve(byte[] message, byte[] hmacKey) {
        byte[] mac = hmac.hash(message, hmacKey);
        return mapToPoint(mac);
    }

    public ECPoint hmacToCurveECPoint(byte[] message, byte[] hmacKey) {
        ECP ecp = hmacToCurve(message, hmacKey);
        return convertToECPoint(ecp);
    }

    public ECPoint convertToECPoint(ECP point) {
        byte[] xBytes = new byte[CONFIG_BIG.MODBYTES];
        point.getX().toBytes(xBytes);
        BigInteger x = BigIntegers.fromUnsignedByteArray(xBytes);//new BigInteger(xBytes);
        byte[] yBytes = new byte[CONFIG_BIG.MODBYTES];
        point.getY().toBytes(yBytes);
        BigInteger y = BigIntegers.fromUnsignedByteArray(yBytes);//new BigInteger(yBytes);
        return ecDomainParameters.getCurve().createPoint(x,y);
    }

    public ECP convertToECP(ECPoint ecPoint) {
        BIG ix = BIG.fromBytes(ecPoint.getXCoord().getEncoded());
        BIG iy = BIG.fromBytes(ecPoint.getYCoord().getEncoded());
        return new ECP(ix, iy);
    }

    public HMAC getHmac() {
        return hmac;
    }

    public void setHmac(HMAC hmac) {
        this.hmac = hmac;
    }

    public Hash getHash() {
        return hash;
    }

    public void setHash(Hash hash) {
        this.hash = hash;
    }
}
