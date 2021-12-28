package org.bitcoinj.crypto;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class PedersenTests {
    @Test
    public void setup() throws Exception {
        BigInteger order = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        Pedersen setup = new Pedersen(Hex.decode("02546865207363616c617220666f722074686973207820697320756e6b6e6f776e"));
        assertEquals(order, setup.getOrder());
        Pedersen.Commitment commit0 = setup.commit(0);
        Pedersen.Commitment commit5 = new Pedersen.Commitment(setup, 5);
        Pedersen.Commitment commit10m = setup.commit(-10);

        BigInteger sumnonce = (commit0.getNonce().add(commit5.getNonce()).add(commit10m.getNonce())).mod(order);

        Pedersen.Commitment sumA = setup.addCommitments(commit0, commit5, commit10m);
        Pedersen.Commitment sumB = new Pedersen.Commitment(setup, BigInteger.valueOf(-5), sumnonce, null);

        assertEquals(sumA.getAmount(), sumB.getAmount());
        assertEquals(sumA.getAmountMod(), sumB.getAmountMod());
        assertEquals(sumA.getNonce(), sumB.getNonce());
        assertEquals(Hex.toHexString(sumA.getpCompressed()), Hex.toHexString(sumB.getpCompressed()));
        assertEquals(Hex.toHexString(sumA.getpUncompressed()), Hex.toHexString(sumB.getpUncompressed()));
    }
}
