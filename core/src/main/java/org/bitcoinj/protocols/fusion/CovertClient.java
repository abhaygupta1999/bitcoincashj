package org.bitcoinj.protocols.fusion;

import fusion.Fusion;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bouncycastle.util.encoders.Hex;

import javax.net.SocketFactory;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class CovertClient {
    public boolean done = true;
    private String host;
    private int port;
    private Socket socket;
    private BufferedOutputStream out;
    private BufferedInputStream in;

    public CovertClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void runConnection() {
        new Thread() {
            @Override
            public void run() {
                try {
                    SocketAddress proxyAddr = new InetSocketAddress("127.0.0.1", 9150);
                    Proxy proxy = new Proxy(Proxy.Type.SOCKS, proxyAddr);
                    Socket socket = new Socket(proxy);
                    socket.setTcpNoDelay(true);
                    socket.setKeepAlive(true);
                    socket.connect(new InetSocketAddress(host, port));
                    BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
                    BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
                    setSocket(socket, out, in);
                    ping();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }

    private void ping() throws IOException {
        Fusion.Ping ping = Fusion.Ping.newBuilder()
                .build();
        Fusion.CovertMessage covertMessage = Fusion.CovertMessage.newBuilder()
                .setPing(ping)
                .build();
        this.submit(covertMessage);
    }

    private void setSocket(Socket socket, BufferedOutputStream out, BufferedInputStream in) {
        this.socket = socket;
        this.out = out;
        this.in = in;
    }

    public void submit(Fusion.CovertMessage covertMessage) throws IOException {
        System.out.println("Still connected?? " + this.socket.isConnected());
        byte[] magicBytes = Hex.decode("765be8b4e4396dcf");

        int size = covertMessage.toByteArray().length;

        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
        bos.write(magicBytes);

        ByteBuffer sizeBuf = ByteBuffer.allocate(4);
        sizeBuf.putInt(size);
        bos.write(sizeBuf.array());

        bos.write(covertMessage.toByteArray());
        out.write(bos.toByteArray());
        out.flush();
    }

    public Fusion.CovertResponse receiveMessage(int timeout) {
        int maxTime = (int)(System.currentTimeMillis()/1000)+timeout;
        while(true) {
            try {
                int remTime = maxTime-(int)(System.currentTimeMillis()/1000);
                if(remTime < 0) {
                    return null;
                }
                this.socket.setSoTimeout(remTime*1000);
                byte[] prefixBytes = in.readNBytes(12);
                if (prefixBytes.length == 0) return null;
                byte[] sizeBytes = Arrays.copyOfRange(prefixBytes, 8, 12);
                int bufferSize = ByteBuffer.wrap(sizeBytes).getInt();
                return Fusion.CovertResponse.parseFrom(in.readNBytes(bufferSize));
            } catch (Exception e) {
            }
        }
    }
}
