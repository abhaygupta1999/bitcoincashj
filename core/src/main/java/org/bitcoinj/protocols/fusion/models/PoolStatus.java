package org.bitcoinj.protocols.fusion.models;

public class PoolStatus {
    private long tier;
    private long players;
    private long minPlayers;

    public PoolStatus(long tier, long players, long minPlayers) {
        this.tier = tier;
        this.players = players;
        this.minPlayers = minPlayers;
    }

    public long getMinPlayers() {
        return minPlayers;
    }

    public long getPlayers() {
        return players;
    }

    public long getTier() {
        return tier;
    }
}
