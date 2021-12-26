package org.bitcoinj.protocols.fusion.models;

import java.math.BigInteger;
import java.util.ArrayList;

public class GeneratedComponents {
    private ArrayList<Component> components;
    private BigInteger sumAmounts;
    private byte[] pedersenTotalNonce;

    public GeneratedComponents(ArrayList<Component> resultList, BigInteger sumAmounts, byte[] pedersenTotalNonce) {
        this.components = resultList;
        this.sumAmounts = sumAmounts;
        this.pedersenTotalNonce = pedersenTotalNonce;
    }

    public ArrayList<Component> getComponents() {
        return components;
    }

    public BigInteger getSumAmounts() {
        return sumAmounts;
    }

    public byte[] getPedersenTotalNonce() {
        return pedersenTotalNonce;
    }
}
