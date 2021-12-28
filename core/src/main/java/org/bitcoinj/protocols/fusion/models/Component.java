package org.bitcoinj.protocols.fusion.models;

import com.google.protobuf.ByteString;
import fusion.Fusion;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

public class Component implements Comparable<Component> {
    private byte[] commitSer;
    private int cNum;
    private byte[] compSer;
    private Fusion.Proof.Builder proof;
    private ECKey privKey;

    public Component(byte[] commitSer, int cNum, byte[] compSer, Fusion.Proof.Builder proof, ECKey privKey) {
        this.commitSer = commitSer;
        this.cNum = cNum;
        this.compSer = compSer;
        this.proof = proof;
        this.privKey = privKey;
    }

    public Fusion.Proof setComponentIdx(int value) {
        this.proof.setComponentIdx(value);
        return this.proof.build();
    }

    public byte[] getCompSer() {
        return compSer;
    }

    public byte[] getCommitSer() {
        return commitSer;
    }

    @Override
    public int compareTo(Component comparestu) {
        byte[] compareCommitSer = comparestu.getCommitSer();
        String compareByteString = Hex.toHexString(compareCommitSer);
        String thisByteString = Hex.toHexString(this.getCommitSer());
        return thisByteString.compareTo(compareByteString);
    }
}
