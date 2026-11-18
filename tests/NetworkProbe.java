import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URI;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;

/** Пробы для заранее доступных контрольных TCP и HTTPS узлов. */
public final class NetworkProbe {
    private static final int TIMEOUT_MS = 5000;

    public static void main(String[] args) throws InterruptedException {
        if (args.length == 4 && args[0].equals("hold")) {
            System.exit(hold(endpoint(args[1], args[2]), Integer.parseInt(args[3])));
        } else if ((args.length == 2 || args.length == 4) && args[0].equals("https")) {
            Proxy proxy = args.length == 2 ? Proxy.NO_PROXY
                    : new Proxy(Proxy.Type.HTTP, endpoint(args[2], args[3]));
            System.exit(https(URI.create(args[1]), proxy));
        } else if (args.length == 2) {
            System.exit(connect(endpoint(args[0], args[1])));
        } else {
            throw new IllegalArgumentException("<IP> <port> | hold <IP> <port> <seconds> | https <URL> [<proxy-IP> <port>]");
        }
    }

    private static InetSocketAddress endpoint(String ip, String portText) {
        InetAddress address = InetAddress.ofLiteral(ip);
        int port = Integer.parseInt(portText);
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port: 1..65535");
        }
        return new InetSocketAddress(address, port);
    }

    private static int connect(InetSocketAddress endpoint) {
        try (Socket socket = new Socket(Proxy.NO_PROXY)) {
            socket.connect(endpoint, TIMEOUT_MS);
        } catch (IOException error) {
            System.out.println("CONNECT_FAILED " + error.getClass().getName() + ": " + error.getMessage());
            return 1;
        }
        System.out.println("CONNECTED");
        return 0;
    }

    private static int hold(InetSocketAddress endpoint, int seconds) throws InterruptedException {
        if (seconds < 1 || seconds > 3600) {
            throw new IllegalArgumentException("seconds: 1..3600");
        }
        int sequence = 0;
        // Сервер возвращает полученные байты в том же TCP-соединении.
        try (Socket socket = new Socket(Proxy.NO_PROXY)) {
            socket.connect(endpoint, TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            DataInputStream input = new DataInputStream(socket.getInputStream());
            for (long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
                    System.nanoTime() < end; sequence++) {
                output.writeInt(sequence);
                output.flush();
                if (input.readInt() != sequence) {
                    System.out.println("HOLD_BAD_ECHO " + Instant.now() + " sequence=" + sequence);
                    return 2;
                }
                String marker = sequence == 0 ? "HOLD_READY" : "HOLD_ECHO";
                System.out.println(marker + " " + Instant.now() + " sequence=" + sequence);
                TimeUnit.SECONDS.sleep(1);
            }
        } catch (IOException error) {
            System.out.println("HOLD_FAILED " + Instant.now() + " sequence=" + sequence + " " + error);
            return 1;
        }
        System.out.println("HOLD_COMPLETE " + Instant.now() + " echoes=" + sequence);
        return 0;
    }

    private static int https(URI uri, Proxy proxy) {
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Expected an HTTPS URL without user info");
        }
        try {
            HttpsURLConnection connection = (HttpsURLConnection) uri.toURL().openConnection(proxy);
            try {
                connection.setConnectTimeout(TIMEOUT_MS);
                connection.setReadTimeout(TIMEOUT_MS);
                connection.setInstanceFollowRedirects(false);
                int status = connection.getResponseCode();
                System.out.println("HTTPS_STATUS " + status);
                return status >= 200 && status < 300 ? 0 : 2;
            } finally {
                connection.disconnect();
            }
        } catch (IOException error) {
            System.out.println("HTTPS_FAILED " + error.getClass().getName() + ": " + error.getMessage());
            return 1;
        }
    }
}
