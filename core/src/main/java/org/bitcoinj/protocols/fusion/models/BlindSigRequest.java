package org.bitcoinj.protocols.fusion.models;

import com.google.protobuf.ByteString;
import org.bitcoinj.crypto.SchnorrBlindSignatureRequest;

public class BlindSigRequest {
    private ByteString blindNoncePoint = null;
    private ByteString commitment = null;
    private ByteString component = null;
    private SchnorrBlindSignatureRequest request = null;

    public BlindSigRequest(ByteString blindNoncePoint, ByteString commitment, ByteString component, SchnorrBlindSignatureRequest request) {
        this.blindNoncePoint = blindNoncePoint;
        this.commitment = commitment;
        this.component = component;
        this.request = request;
    }

    public ByteString getBlindNoncePoint() {
        return blindNoncePoint;
    }

    public ByteString getCommitment() {
        return commitment;
    }

    public SchnorrBlindSignatureRequest getRequest() {
        return request;
    }

    public ByteString getComponent() {
        return component;
    }
}
