package org.bitcoinj.protocols.fusion;

import fusion.Fusion;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

public class CovertSubmitter {
    private ArrayList<CovertClient> connections = new ArrayList<>();
    private ArrayList<CovertClient> spareConnections = new ArrayList<>();

    public CovertSubmitter(String covertDomain, int covertPort, long numComponents, int numSpares) {

        for(long x = 0; x < numSpares; x++) {
            CovertClient sleepingClient = new CovertClient(covertDomain, covertPort);
            spareConnections.add(sleepingClient);
        }

        for(long x = 0; x < numComponents; x++) {
            CovertClient sleepingClient = new CovertClient(covertDomain, covertPort);
            connections.add(sleepingClient);
        }

        connections.addAll(spareConnections);
    }

    public void scheduleConnections() {
        for(CovertClient client : connections) {
            client.runConnection();
        }
    }

    public void scheduleSubmissions(final ArrayList<Fusion.CovertMessage> covertMessages, final long startTime) {
        new Thread() {
            @Override
            public void run() {
                while(true) {
                    long currentTime = System.currentTimeMillis()/1000L;
                    if(currentTime >= startTime) {
                        ArrayList<CovertClient> connectionsCopy = new ArrayList<>(connections);
                        for(Fusion.CovertMessage covertMessage : covertMessages) {
                            int index = new Random().nextInt(connectionsCopy.size());
                            CovertClient covertClient = connectionsCopy.get(index);
                            try {
                                covertClient.submit(covertMessage);
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        break;
                    }
                }
            }
        }.start();

    }
}
