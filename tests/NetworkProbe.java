import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

/** Один TCP connect; отказ сам по себе не доказывает блокировку firewall. */
public final class NetworkProbe {
    public static void main(String[] args) {
        if (args.length != 2) {
            throw new IllegalArgumentException("<literal IPv4/IPv6> <port>");
        }
        InetAddress address = InetAddress.ofLiteral(args[0]);
        int port = Integer.parseInt(args[1]);
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port: 1..65535");
        }
        try (Socket socket = new Socket(Proxy.NO_PROXY)) {
            socket.connect(new InetSocketAddress(address, port), 5000);
        } catch (IOException error) {
            System.out.println("CONNECT_FAILED " + error.getClass().getName() + ": " + error.getMessage());
            System.exit(1);
            return;
        }
        System.out.println("CONNECTED");
    }
}
