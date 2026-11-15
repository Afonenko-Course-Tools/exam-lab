import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Чтение одного известного файла; само по себе не доказывает USB/файловую изоляцию. */
public final class WindowsProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !args[0].equals("file") ||
                !(args[2].equals("read") || args[2].equals("deny"))) {
            throw new IllegalArgumentException("file <путь контрольного файла> read|deny");
        }
        try {
            byte[] data = Files.readAllBytes(Path.of(args[1]));
            System.out.println("READ bytes=" + data.length + " sha256=" +
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)));
            if (args[2].equals("deny")) throw new AssertionError("USB_READ_ALLOWED");
        } catch (AccessDeniedException denied) {
            System.out.println("ACCESS_DENIED " + args[1]);
            if (args[2].equals("read")) throw denied;
        }
    }
}
