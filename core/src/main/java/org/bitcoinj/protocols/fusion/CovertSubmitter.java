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
    }

    public ArrayList<CovertClient> getConnections() {
        return connections;
    }

    public ArrayList<CovertClient> getSpareConnections() {
        return spareConnections;
    }

    public void scheduleConnections() {
        new Thread() {
            @Override
            public void run() {
                ArrayList<CovertClient> connectionsCopy = new ArrayList<>(connections);
                connectionsCopy.addAll(spareConnections);
                for(CovertClient client : connectionsCopy) {
                    client.runConnection();
                    try {
                        Thread.sleep(new Random().nextInt(5) * 100L);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }.start();
    }

    public void scheduleSubmissions(final ArrayList<Fusion.CovertMessage> covertMessages, final double startTime, final double endTime) {
        int size = Math.min(covertMessages.size(), connections.size());

        for(int x = 0; x < size; x++) {
            CovertClient client = this.connections.get(x);
            client.done = false;
            client.brokenPipe = false;
            client.msg = covertMessages.get(x);
        }

        new Thread() {
            @Override
            public void run() {
                while ((System.currentTimeMillis()/1000D) < endTime) {
                    double currentTime = System.currentTimeMillis()/1000D;
                    if(currentTime >= startTime) {
                        for (CovertClient covertClient : connections) {
                            Fusion.CovertMessage cachedMsg = covertClient.msg;
                            while (covertClient.brokenPipe) {
                                System.out.println("BROKEN PIPE");
                                covertClient.restartConnection();
                                int randSpare = new Random().nextInt(spareConnections.size());
                                covertClient = spareConnections.get(randSpare);
                                covertClient.msg = cachedMsg;
                            }
                            if (!covertClient.done && covertClient.msg != null) {
                                covertClient.submit(covertClient.msg);
                                double remTime = (endTime)-(System.currentTimeMillis()/1000D);
                                if(remTime < 0) {
                                    System.out.println("too slow for covert submission");
                                    break;
                                }
                                Fusion.CovertResponse response = covertClient.receiveMessage(remTime);
                                if (response != null) {
                                    if (response.hasOk()) {
                                        System.out.println("response ok");
                                        covertClient.done = true;
                                        covertClient.msg = null;
                                    } else {
                                        System.out.println(response);
                                    }
                                } else {
                                    System.out.println("response NULL");
                                }
                            }
                        }
                    }
                }
            }
        }.start();
    }

    public void closeConnections() {
        ArrayList<CovertClient> connectionsCopy = new ArrayList<>(connections);
        connectionsCopy.addAll(spareConnections);
        for(CovertClient client : connectionsCopy) {
            try {
                client.getSocket().close();
                Thread.sleep(500L);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
