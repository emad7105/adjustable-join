package be.heydari.adjenc;

import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public interface AdjustableSchemeInterface {

    byte[] genMessagePrfKey();
    BigInteger genSecretKey();

    ECPoint encrypt(byte[] message, byte[] messagePrfKey, BigInteger secretKey) throws NoSuchAlgorithmException;
    BigInteger genDeltaToken(BigInteger oldSecretKey, BigInteger newSecretKey);


}
