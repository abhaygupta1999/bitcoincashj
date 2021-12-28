package org.bitcoinj.crypto;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bitcoinj.core.Utils;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class SchnorrBlindSignatureRequest {
    public static final BigInteger[] G = {
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    };
    public static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private byte[] pubKey;
    private byte[] pubKeyCompressed;
    private byte[] R;
    private byte[] messageHash;
    private byte[] Rxnew;
    private BigInteger y;
    private BigInteger c;
    private BigInteger e;
    private BigInteger a;
    private BigInteger b;

    public SchnorrBlindSignatureRequest(byte[] pubKey, byte[] R, byte[] messageHash) throws IOException {
        this.pubKey = pubKey;
        this.R = R;
        this.messageHash = messageHash;

        BigInteger a = new ECKey().getPrivKey();
        BigInteger b = new ECKey().getPrivKey();
        this.a = a;
        this.b = b;

        BigInteger[] Rpoint = SchnorrSignature.point_from_bytes(R);
        BigInteger[] pubPoint = SchnorrSignature.point_from_bytes(pubKey);
        this.pubKeyCompressed = ECKey.fromPublicOnly(pubKey).getPubKeyPoint().getEncoded(true);

        BigInteger[] Rnew = SchnorrSignature.point_add(SchnorrSignature.point_add(Rpoint, SchnorrSignature.point_mul(G, a)), SchnorrSignature.point_mul(pubPoint, b));
        this.Rxnew = Utils.bigIntegerToBytes(Rnew[0], 32);
        this.y = Rnew[1];
        this.c = jacobi(y, p);

        ByteBuffer eBuffer = ByteBuffer.allocate(32 + 33 + 32);
        eBuffer.put(Rxnew);
        eBuffer.put(pubKeyCompressed);
        eBuffer.put(messageHash);
        byte[] eHash = Sha256Hash.hash(eBuffer.array());
        this.e = (this.c.multiply(SchnorrSignature.toBigInteger(eHash)).add(b)).mod(n);
    }

    private BigInteger jacobi(BigInteger a, BigInteger n) {
        BigInteger seven = BigInteger.valueOf(7);
        BigInteger three = BigInteger.valueOf(3);

        a = a.mod(n);
        BigInteger s = BigInteger.ONE;
        while(a.compareTo(BigInteger.ONE) > 0) {
            BigInteger a1 = a;
            BigInteger e = BigInteger.ZERO;
            while(a1.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
                a1 = a1.shiftRight(1);
                e = e.add(BigInteger.ONE);
            }

            if(!(e.and(BigInteger.ONE).equals(BigInteger.ZERO) || n.and(seven).equals(BigInteger.ONE) || n.and(seven).equals(seven))) {
                s = s.multiply(BigInteger.valueOf(-1));
            }

            if(a1.equals(BigInteger.ONE)) {
                return s;
            }

            if(n.and(three).equals(three) && a1.and(three).equals(three)) {
                s = s.multiply(BigInteger.valueOf(-1));
            }

            a = n.mod(a1);
            n = a1;
        }

        if(a.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }

        if(a.equals(BigInteger.ONE)) {
            return s;
        }

        return null;
    }

    public byte[] blindFinalize(byte[] sBytes) throws IOException {
        if(sBytes.length != 32) {
            System.out.println("sBytes not 32");
            return null;
        }

        BigInteger s = SchnorrSignature.toBigInteger(sBytes);

        BigInteger sNew = this.c.multiply(s.add(this.a)).mod(n);
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
        bos.write(Rxnew);
        bos.write(Utils.bigIntegerToBytes(sNew, 32));
        return bos.toByteArray();
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }

    public byte[] getRequest() {
        return Utils.bigIntegerToBytes(this.e, 32);
    }
}
