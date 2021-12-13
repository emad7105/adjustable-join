package be.heydari.adjenc;


import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EllipticCurve;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class AdjustableSchemeTest {

    AdjustableScheme adjustableScheme = new AdjustableScheme();

    @Test
    public void encryptAdjust() throws NoSuchAlgorithmException {
        // secret PRF key to internally HMAC the message
        // to use in HMAC(prfKey, data)
        byte[] prfKey = adjustableScheme.genMessagePrfKey();

        // secret Key to hide the HMAC(prfKey, data)
        // sk1 for column A
        BigInteger sk1 = adjustableScheme.genSecretKey();
        // sk2 for column B
        BigInteger sk2 = adjustableScheme.genSecretKey();

        ECPoint ciphertext1 = adjustableScheme.encrypt("My data".getBytes(), prfKey, sk1);
        ECPoint ciphertext2 = adjustableScheme.encrypt("My data".getBytes(), prfKey, sk2);

        assertNotEquals(ciphertext1, ciphertext2);

        BigInteger newSk = adjustableScheme.genSecretKey();
        BigInteger deltaTokenForSk1 = adjustableScheme.genDeltaToken(sk1, newSk);
        BigInteger deltaTokenForSk2 = adjustableScheme.genDeltaToken(sk2, newSk);

        ECPoint ciphertext1Adjusted = adjustableScheme.adjust(deltaTokenForSk1, ciphertext1);
        ECPoint ciphertext2Adjusted = adjustableScheme.adjust(deltaTokenForSk2, ciphertext2);

        assertEquals(ciphertext1Adjusted, ciphertext2Adjusted);
    }


    @Test
    public void encodingAndDecodingForDB() throws NoSuchAlgorithmException {
        byte[] prfKey = adjustableScheme.genMessagePrfKey();
        BigInteger sk1 = adjustableScheme.genSecretKey();
        ECPoint ciphertext1 = adjustableScheme.encrypt("My data".getBytes(), prfKey, sk1);

        byte[] bytes = adjustableScheme.encodeEcPoint(ciphertext1);
        ECPoint decodeEcPoint = adjustableScheme.decodeEcPoint(bytes);

        assertEquals(ciphertext1, decodeEcPoint);
    }


}