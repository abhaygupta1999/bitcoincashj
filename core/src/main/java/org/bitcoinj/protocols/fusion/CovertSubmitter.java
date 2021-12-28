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
        for(CovertClient client : connections) {
            client.done = false;
        }
        new Thread() {
            @Override
            public void run() {
                int messageIndex = 0;
                ArrayList<CovertClient> connectionsCopy = new ArrayList<>(connections);
                ArrayList<Fusion.CovertMessage> messagesCopy = new ArrayList<>(covertMessages);
                for(Fusion.CovertMessage covertMessage : messagesCopy) {
                    while (true) {
                        CovertClient covertClient = connectionsCopy.get(messageIndex);
                        try {
                            if (!covertClient.done) {
                                covertClient.submit(covertMessage);
                                Fusion.CovertResponse response = covertClient.receiveMessage(3);
                                if (response.hasOk()) {
                                    System.out.println("response ok");
                                    covertClient.done = true;
                                    messageIndex++;
                                    break;
                                }
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }.start();
    }
}
