package lab.netstrazh;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * A SOCKS5 proxy (CONNECT and UDP ASSOCIATE, no login) that runs in the test APK's own process, so
 * under another UID than the app: what a separate proxy app such as v2rayNG is to NetStrazh. Its
 * sockets are ordinary ones, routed by Android like any app's.
 *
 * Plain Java on purpose: this process has neither the app's classes nor the Kotlin library.
 */
public class OtherAppProxy extends Service {
    /** Transaction codes of the binder returned by {@link #onBind}. */
    public static final int GET_PORT = 1;
    public static final int GET_UID = 2;
    public static final int GET_LOG = 3;

    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final List<String> log = new ArrayList<>();
    private ServerSocket server;

    private static InetAddress loopback() throws IOException {
        return InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            server = new ServerSocket(0, 64, loopback());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        final ServerSocket s = server;
        pool.execute(() -> {
            while (!s.isClosed()) {
                final Socket c;
                try {
                    c = s.accept();
                } catch (IOException e) {
                    break;
                }
                pool.execute(() -> handle(c));
            }
        });
    }

    @Override
    public void onDestroy() {
        try {
            server.close();
        } catch (IOException ignored) {
        }
        pool.shutdownNow();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                switch (code) {
                    case GET_PORT:
                        reply.writeInt(server.getLocalPort());
                        return true;
                    case GET_UID:
                        reply.writeInt(android.os.Process.myUid());
                        return true;
                    case GET_LOG:
                        synchronized (log) {
                            reply.writeStringList(new ArrayList<>(log));
                        }
                        return true;
                    default:
                        return super.onTransact(code, data, reply, flags);
                }
            }
        };
    }

    private void note(String s) {
        synchronized (log) {
            log.add(s);
        }
    }

    private void handle(Socket c) {
        try {
            DataInputStream in = new DataInputStream(c.getInputStream());
            OutputStream out = c.getOutputStream();
            in.readUnsignedByte();
            in.readFully(new byte[in.readUnsignedByte()]);
            out.write(new byte[] {5, 0});
            in.readUnsignedByte();
            int cmd = in.readUnsignedByte();
            in.readUnsignedByte();
            String name = null;
            InetAddress addr = null;
            switch (in.readUnsignedByte()) {
                case 1: {
                    byte[] a = new byte[4];
                    in.readFully(a);
                    addr = InetAddress.getByAddress(a);
                    break;
                }
                case 4: {
                    byte[] a = new byte[16];
                    in.readFully(a);
                    addr = InetAddress.getByAddress(a);
                    break;
                }
                case 3: {
                    byte[] n = new byte[in.readUnsignedByte()];
                    in.readFully(n);
                    name = new String(n, "US-ASCII");
                    break;
                }
                default:
                    throw new IOException("unsupported address type");
            }
            int port = in.readUnsignedShort();
            if (cmd == 1) {
                connect(c, out, name, addr, port);
            } else if (cmd == 3) {
                associate(in, out);
            } else {
                out.write(new byte[] {5, 7, 0, 1, 0, 0, 0, 0, 0, 0});
            }
        } catch (Exception e) {
            // The client sees its connection closed.
        } finally {
            close(c);
        }
    }

    private void connect(final Socket c, OutputStream out, String name, InetAddress addr, int port) throws Exception {
        note("CONNECT " + (name != null ? name : addr.getHostAddress()) + ":" + port);
        InetAddress target = addr != null ? addr : InetAddress.getByName(name);
        final Socket up = new Socket();
        try {
            up.connect(new InetSocketAddress(target, port), 10_000);
            out.write(new byte[] {5, 0, 0, 1, 0, 0, 0, 0, 0, 0});
            Future<?> back = pool.submit(() -> pump(up, c));
            pump(c, up);
            back.get();
        } finally {
            close(up);
        }
    }

    private static void pump(Socket from, Socket to) {
        try {
            byte[] b = new byte[16384];
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(b)) >= 0) {
                out.write(b, 0, n);
            }
            to.shutdownOutput();
        } catch (IOException e) {
            close(to);
            close(from);
        }
    }

    private void associate(InputStream in, OutputStream out) throws IOException {
        final DatagramSocket relay = new DatagramSocket(0, loopback());
        final DatagramSocket ext = new DatagramSocket();
        try {
            int p = relay.getLocalPort();
            out.write(new byte[] {5, 0, 0, 1, 0, 0, 0, 0, (byte) (p >>> 8), (byte) p});
            final InetSocketAddress[] client = new InetSocketAddress[1];
            pool.execute(() -> {
                byte[] b = new byte[65535];
                try {
                    while (true) {
                        DatagramPacket d = new DatagramPacket(b, b.length);
                        relay.receive(d);
                        synchronized (client) {
                            client[0] = new InetSocketAddress(d.getAddress(), d.getPort());
                        }
                        if (d.getLength() < 10 || b[3] != 1) continue;
                        InetAddress dst = InetAddress.getByAddress(new byte[] {b[4], b[5], b[6], b[7]});
                        int dport = ((b[8] & 0xFF) << 8) | (b[9] & 0xFF);
                        note("UDP " + dst.getHostAddress() + ":" + dport);
                        ext.send(new DatagramPacket(b, 10, d.getLength() - 10, dst, dport));
                    }
                } catch (IOException ignored) {
                }
            });
            pool.execute(() -> {
                byte[] b = new byte[65535];
                try {
                    while (true) {
                        DatagramPacket d = new DatagramPacket(b, 10, b.length - 10);
                        ext.receive(d);
                        byte[] a = d.getAddress().getAddress();
                        if (a.length != 4) continue;
                        b[0] = 0;
                        b[1] = 0;
                        b[2] = 0;
                        b[3] = 1;
                        System.arraycopy(a, 0, b, 4, 4);
                        b[8] = (byte) (d.getPort() >>> 8);
                        b[9] = (byte) d.getPort();
                        InetSocketAddress to;
                        synchronized (client) {
                            to = client[0];
                        }
                        if (to == null) continue;
                        relay.send(new DatagramPacket(b, 0, 10 + d.getLength(), to));
                    }
                } catch (IOException ignored) {
                }
            });
            // The association lives as long as the control connection.
            while (in.read() >= 0) {
                // nothing is expected on it
            }
        } finally {
            relay.close();
            ext.close();
        }
    }

    private static void close(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }
}
