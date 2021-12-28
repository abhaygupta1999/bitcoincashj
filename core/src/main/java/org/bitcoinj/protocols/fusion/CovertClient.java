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

public class CovertClient {
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
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }

    private void setSocket(Socket socket, BufferedOutputStream out, BufferedInputStream in) {
        this.socket = socket;
        this.out = out;
        this.in = in;
    }

    public void submit(Fusion.CovertMessage covertMessage) throws IOException {
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

        System.out.println("covert submit: " + Hex.toHexString(bos.toByteArray()));
    }
}
