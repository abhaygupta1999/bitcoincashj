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
    private Fusion.Proof proof;
    private ECKey privKey;

    public Component(byte[] commitSer, int cNum, byte[] compSer, Fusion.Proof proof, ECKey privKey) {
        this.commitSer = commitSer;
        this.cNum = cNum;
        this.compSer = compSer;
        this.proof = proof;
        this.privKey = privKey;
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
