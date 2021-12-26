package org.bitcoinj.protocols.fusion.models;

public class Tier {
    private long tierSize;
    public Tier(long size) {
        this.tierSize = size;
    }

    public long getTierSize() {
        return tierSize;
    }
}
