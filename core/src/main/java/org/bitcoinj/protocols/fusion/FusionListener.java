package org.bitcoinj.protocols.fusion;

import org.bitcoinj.protocols.fusion.models.FusionStatus;
import org.bitcoinj.protocols.fusion.models.PoolStatus;

import java.util.List;

public interface FusionListener {
    void onPoolStatus(List<PoolStatus> poolStatusList);
    void onFusionStatus(FusionStatus status);
}
