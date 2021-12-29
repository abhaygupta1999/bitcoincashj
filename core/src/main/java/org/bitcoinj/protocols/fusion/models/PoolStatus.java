package org.bitcoinj.protocols.fusion.models;

public class PoolStatus {
    private long tier;
    private long players;
    private long minPlayers;
    private long timeUntilStart;

    public PoolStatus(long tier, long players, long minPlayers, long timeUntilStart) {
        this.tier = tier;
        this.players = players;
        this.minPlayers = minPlayers;
        this.timeUntilStart = timeUntilStart;
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

    public long getTimeUntilStart() {
        return timeUntilStart;
    }
}
