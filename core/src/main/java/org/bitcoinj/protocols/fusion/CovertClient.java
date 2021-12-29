package org.bitcoinj.protocols.fusion;

import fusion.Fusion;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bouncycastle.util.encoders.Hex;

import javax.net.SocketFactory;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class CovertClient {
    public boolean brokenPipe = false;
    public boolean done = true;
    public Fusion.CovertMessage msg;
    private String host;
    private int port;
    private Socket socket;
    private BufferedOutputStream out;
    private BufferedInputStream in;
    public Thread socketThread = null;

    public CovertClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void runConnection() {
        socketThread = new Thread() {
            @Override
            public void run() {
                try {
                    SocketAddress proxyAddr = new InetSocketAddress("127.0.0.1", 9050);
                    Proxy proxy = new Proxy(Proxy.Type.SOCKS, proxyAddr);
                    Socket socket = new Socket(proxy);
                    socket.setTcpNoDelay(true);
                    socket.setKeepAlive(true);
                    socket.connect(new InetSocketAddress(host, port));
                    BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
                    BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
                    setSocket(socket, out, in);
                    if(!brokenPipe)
                        ping();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };
        socketThread.start();
    }

    public void restartConnection() {
        try {
            out.close();
            in.close();
            socket.close();
            socketThread = null;
            runConnection();
            brokenPipe = false;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Socket getSocket() {
        return socket;
    }

    private void ping() throws IOException {
        Fusion.Ping ping = Fusion.Ping.newBuilder()
                .build();
        Fusion.CovertMessage covertMessage = Fusion.CovertMessage.newBuilder()
                .setPing(ping)
                .build();
        this.msg = covertMessage;
        this.submit(msg);
    }

    private void setSocket(Socket socket, BufferedOutputStream out, BufferedInputStream in) {
        this.socket = socket;
        this.out = out;
        this.in = in;
    }

    public void submit(Fusion.CovertMessage covertMessage) {
        System.out.println("Still connected?? " + this.socket.isConnected());
        byte[] magicBytes = Hex.decode("765be8b4e4396dcf");

        int size = covertMessage.toByteArray().length;
        try {
            UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
            bos.write(magicBytes);

            ByteBuffer sizeBuf = ByteBuffer.allocate(4);
            sizeBuf.putInt(size);
            bos.write(sizeBuf.array());

            bos.write(covertMessage.toByteArray());
            out.write(bos.toByteArray());
            out.flush();
            msg = null;
        } catch(IOException e) {
            e.printStackTrace();
            brokenPipe = true;
        }
    }

    public Fusion.CovertResponse receiveMessage(double timeout) {
        try {
            this.socket.setSoTimeout((int)(timeout*1000D));
            byte[] prefixBytes = readNBytes(in, 12);
            if (prefixBytes.length == 0) return null;
            byte[] sizeBytes = Arrays.copyOfRange(prefixBytes, 8, 12);
            int bufferSize = ByteBuffer.wrap(sizeBytes).getInt();
            return Fusion.CovertResponse.parseFrom(readNBytes(in, bufferSize));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] readNBytes(BufferedInputStream in, int len) throws IOException {
        if (len < 0) {
            throw new IllegalArgumentException("len < 0");
        } else {
            List<byte[]> bufs = null;
            byte[] result = null;
            int total = 0;
            int remaining = len;

            int n;
            do {
                byte[] buf = new byte[Math.min(remaining, 8192)];

                int nread;
                for(nread = 0; (n = in.read(buf, nread, Math.min(buf.length - nread, remaining))) > 0; remaining -= n) {
                    nread += n;
                }

                if (nread > 0) {
                    if (2147483639 - total < nread) {
                        throw new OutOfMemoryError("Required array size too large");
                    }

                    total += nread;
                    if (result == null) {
                        result = buf;
                    } else {
                        if (bufs == null) {
                            bufs = new ArrayList();
                            bufs.add(result);
                        }

                        bufs.add(buf);
                    }
                }
            } while(n >= 0 && remaining > 0);

            if (bufs == null) {
                if (result == null) {
                    return new byte[0];
                } else {
                    return result.length == total ? result : Arrays.copyOf(result, total);
                }
            } else {
                result = new byte[total];
                int offset = 0;
                remaining = total;

                int count;
                for(Iterator var12 = bufs.iterator(); var12.hasNext(); remaining -= count) {
                    byte[] b = (byte[])var12.next();
                    count = Math.min(b.length, remaining);
                    System.arraycopy(b, 0, result, offset, count);
                    offset += count;
                }

                return result;
            }
        }
    }
}
