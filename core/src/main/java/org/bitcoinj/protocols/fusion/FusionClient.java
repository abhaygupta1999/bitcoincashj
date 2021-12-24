package org.bitcoinj.protocols.fusion;

import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bouncycastle.util.encoders.Hex;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;

public class FusionClient {
    private SSLSocket socket;
    private String host;
    private int port;
    private PrintWriter out;
    private BufferedReader in;
    private byte[] magicBytes;

    public FusionClient(String host, int port) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
        socket.startHandshake();
        this.socket = socket;
        this.magicBytes = Hex.decode("765be8b4e4396dcf");
        this.host = host;
        this.port = port;
        out = new PrintWriter(socket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    public String sendMessage(String msg) throws IOException {
        int lengthBytes = msg.getBytes().length;
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(lengthBytes);
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(8);
        bos.write(magicBytes);
        bos.write(buffer.array());
        bos.write(msg.getBytes());
        byte[] frame = bos.toByteArray();
        out.println(frame);
        return in.readLine();
    }

    public SSLSocket getSocket() {
        return socket;
    }

    public void stopConnection() throws IOException {
        in.close();
        out.close();
        socket.close();
    }
}
