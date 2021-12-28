package org.bitcoinj.crypto;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class SchnorrBlindSignatureRequest {
    protected static final BigInteger order = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    protected static final BigInteger fieldSize = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663");
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

        BigInteger a = nextRandomBigInteger(order);
        BigInteger b = nextRandomBigInteger(order);
        this.a = a;
        this.b = b;

        ECPoint Rpoint = ECKey.fromPublicOnly(R).getPubKeyPoint();
        ECPoint pubPoint = ECKey.fromPublicOnly(pubKey).getPubKeyPoint();
        this.pubKeyCompressed = pubPoint.getEncoded(true);

        ECPoint Rnew = Rpoint.add(ECKey.CURVE.getG().multiply(a)).add((pubPoint.multiply(b)));
        this.Rxnew = Rnew.getXCoord().toBigInteger().toByteArray();
        this.y = Rnew.getYCoord().toBigInteger();
        this.c = jacobi(y, fieldSize);

        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
        bos.write(Rxnew);
        bos.write(pubKeyCompressed);
        bos.write(messageHash);
        byte[] eHash = Sha256Hash.hash(bos.toByteArray());
        this.e = (this.c.multiply(new BigInteger(eHash)).add(b)).mod(order);
        System.out.println("e len " + this.e.toByteArray().length);
        System.out.println("jacobi " + this.c);
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
            return null;
        }

        BigInteger s = new BigInteger(sBytes);

        BigInteger sNew = this.c.multiply(s.add(this.a)).mod(order);
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
        bos.write(Rxnew);
        bos.write(sNew.toByteArray());
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
        byte[] array = this.e.toByteArray();
        int length = array.length;
        if(length == 33) {
            array = Arrays.copyOfRange(array, 1, 33);
        }
        return array;
    }

    private BigInteger nextRandomBigInteger(BigInteger n) {
        Random rand = new Random();
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(n.bitLength()-8, rand);
        } while (randomNumber.compareTo(n) >= 0);
        ByteBuffer byteBuffer = ByteBuffer.allocate(32);
        byteBuffer.put(randomNumber.toByteArray());
        return new BigInteger(byteBuffer.array());
    }
}
