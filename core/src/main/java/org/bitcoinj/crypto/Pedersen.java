package org.bitcoinj.crypto;

import org.apache.commons.lang3.ArrayUtils;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class Pedersen {
    protected static final BigInteger order = ECKey.CURVE.getN();
    private ECPoint Hpoint;
    private ECPoint HGpoint;
    private byte[] H;
    private byte[] HG;

    public Pedersen(byte[] H) {
        ECPoint Hpoint = ECKey.fromPublicOnly(H).getPubKeyPoint();
        ECPoint HGpoint = Hpoint.add(ECKey.CURVE.getG());
        this.Hpoint = Hpoint;
        this.HGpoint = HGpoint;

        this.H = Hpoint.getEncoded(false);
        this.HG = HGpoint.getEncoded(false);
    }

    public Commitment commit(BigInteger amount) throws Exception {
        return new Commitment(this, amount, null);
    }

    public Commitment commit(long amount) throws Exception {
        return new Commitment(this, BigInteger.valueOf(amount), null);
    }

    public Commitment commit(long amount, BigInteger nonce) throws Exception {
        return new Commitment(this, BigInteger.valueOf(amount), nonce, null);
    }

    public BigInteger getOrder() {
        return order;
    }

    public byte[] addPoints(List<byte[]> points) {
        ArrayList<ECPoint> pList = new ArrayList<>();
        for(byte[] pSer : points) {
            pList.add(new LazyECPoint(ECKey.CURVE.getCurve(), pSer).get());
        }

        if(pList.isEmpty()) {
            return null;
        }

        ArrayList<ECPoint> subPList = new ArrayList<>();
        for(int x = 1; x < pList.size(); x++) {
            subPList.add(pList.get(x));
        }
        ECPoint pSum = pList.get(0);
        for(ECPoint point : subPList) {
            pSum = pSum.add(point);
        }
        return pSum.getEncoded(false);
    }

    public Commitment addCommitments(Pedersen.Commitment... commitments) throws Exception {
        BigInteger kTotal = BigInteger.ZERO;
        long aTotal = 0;
        ArrayList<byte[]> points = new ArrayList<>();
        ArrayList<Pedersen> setups = new ArrayList<>();
        for(Commitment commitment : commitments) {
            kTotal = kTotal.add(commitment.getNonce());
            aTotal += commitment.getAmount();
            points.add(commitment.getpUncompressed());
            setups.add(commitment.setup);
        }

        if(points.isEmpty()) {
            System.out.println("points empty");
        }

        Pedersen setup = setups.get(0);
        kTotal = kTotal.mod(order);

        byte[] pUncompressed = null;
        if(points.size() < 512) {
            try {
                pUncompressed = addPoints(points);
            }catch (Exception ignored) {
            }
        }

        return new Commitment(setup, BigInteger.valueOf(aTotal), kTotal, pUncompressed);
    }

    public static class Commitment {
        private byte[] pUncompressed;
        private byte[] pCompressed;
        private long amount;
        private BigInteger amountMod;
        private BigInteger nonce;
        private Pedersen setup;

        public Commitment(Pedersen setup, long amount) throws Exception {
            this(setup, BigInteger.valueOf(amount), null);
        }

        public Commitment(Pedersen setup, BigInteger amount, @Nullable byte[] pUncompressed) throws Exception {
            this.setup = setup;
            this.amount = amount.longValue();
            this.amountMod = amount.mod(order);
            this.nonce = nextRandomBigInteger(order);
            if(nonce.compareTo(BigInteger.ZERO) < 0 || nonce.compareTo(order) > 0) {
                return;
            }

            if(pUncompressed != null) {
                if(pUncompressed.length != 65) {
                    throw new Exception("pUncompressed not 65 size");
                }
                if(pUncompressed[0] != 0x04) {
                    throw new Exception("pUncompressed byte 0 is not 4");
                }

                this.pUncompressed = pUncompressed;
                this.pCompressed = ECKey.fromPublicOnly(this.pUncompressed).getPubKeyPoint().getEncoded(true);
                return;
            }

            calcInitial();
        }

        public Commitment(Pedersen setup, BigInteger amount, BigInteger nonce, @Nullable byte[] pUncompressed) throws Exception {
            this.setup = setup;
            this.amount = amount.longValue();
            this.amountMod = amount.mod(order);
            this.nonce = nonce;
            if(nonce.compareTo(BigInteger.ZERO) < 0 || nonce.compareTo(order) > 0) {
                throw new Exception("nonce out of range");
            }

            if(pUncompressed != null) {
                if(pUncompressed.length != 65) {
                    throw new Exception("pUncompressed not 65 size");
                }
                if(pUncompressed[0] != 0x04) {
                    throw new Exception("pUncompressed byte 0 is not 4");
                }

                this.pUncompressed = pUncompressed;
                this.pCompressed = ECKey.fromPublicOnly(this.pUncompressed).getPubKeyPoint().getEncoded(true);
                return;
            }

            calcInitial();
        }

        private void calcInitial() throws Exception {
            ECPoint Hpoint = this.setup.Hpoint;
            ECPoint HGpoint = this.setup.HGpoint;

            BigInteger k = this.nonce;
            BigInteger a = this.amountMod;
            ECPoint Ppoint = Hpoint.multiply((a.subtract(k)).mod(Pedersen.order)).add(HGpoint.multiply(k));
            if(Ppoint.isInfinity()) {
                throw new Exception("Ppoint at infinity");
            }
            this.pCompressed = Ppoint.getEncoded(true);
            this.pUncompressed = Ppoint.getEncoded(false);
        }

        private BigInteger nextRandomBigInteger(BigInteger n) {
            Random rand = new Random();
            BigInteger randomNumber;
            do {
                randomNumber = new BigInteger(n.bitLength()-8, rand);
            } while (randomNumber.compareTo(n) >= 0);
            return randomNumber;
        }

        public byte[] getpCompressed() {
            return pCompressed;
        }

        public byte[] getpUncompressed() {
            return pUncompressed;
        }

        public BigInteger getNonce() {
            return nonce;
        }

        public BigInteger getAmountMod() {
            return amountMod;
        }

        public long getAmount() {
            return amount;
        }
    }
}
