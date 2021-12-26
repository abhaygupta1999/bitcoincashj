package org.bitcoinj.crypto;

import org.bitcoinj.core.ECKey;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Random;

public class SchnorrBlindSigner {
    protected static final BigInteger order = ECKey.CURVE.getN();
    private byte[] R;
    private BigInteger k;

    public SchnorrBlindSigner() {
        BigInteger k = nextRandomBigInteger(order);
        ECPoint Rpoint = ECKey.CURVE.getG().multiply(k);
        this.R = Rpoint.getEncoded(true);
    }

    public BigInteger getK() {
        return k;
    }

    public byte[] getR() {
        return R;
    }

    public static BigInteger getOrder() {
        return order;
    }

    private BigInteger nextRandomBigInteger(BigInteger n) {
        Random rand = new Random();
        BigInteger result = new BigInteger(n.bitLength(), rand);
        while( result.compareTo(n) >= 0 ) {
            result = new BigInteger(n.bitLength(), rand);
        }
        return result;
    }
}
