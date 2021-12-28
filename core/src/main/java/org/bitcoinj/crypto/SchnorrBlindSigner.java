package org.bitcoinj.crypto;

import com.google.common.base.Preconditions;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Utils;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class SchnorrBlindSigner {
    public static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static final BigInteger[] G = {
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    };
    private byte[] R;
    private BigInteger k;

    public SchnorrBlindSigner() {
        BigInteger k = new ECKey().getPrivKey();
        BigInteger[] Rpoint = SchnorrSignature.point_mul(G, k);
        this.R = SchnorrSignature.bytes_from_point(Rpoint);
        this.k = k;
    }

    public BigInteger getK() {
        return k;
    }

    public byte[] getR() {
        return R;
    }

    public static BigInteger getOrder() {
        return n;
    }

    public byte[] sign(ECKey privKey, byte[] eBytes) {
        Preconditions.checkState(privKey.getPrivKeyBytes().length == 32);
        Preconditions.checkState(eBytes.length == 32);

        BigInteger k = getK();

        BigInteger x = privKey.getPrivKey();
        BigInteger e = SchnorrSignature.toBigInteger(eBytes);

        BigInteger s = (e.multiply(x).add(k)).mod(n);
        return Utils.bigIntegerToBytes(s, 32);
    }
}
