import SecureKeyExchange.DiffieHellman;
import SecureKeyExchange.Enums.DHSecurityLevel;

public class Main {

    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        try {
            DiffieHellman dh = new DiffieHellman(DHSecurityLevel.Extreme);
            dh.GenerateKeys();

            dh.GenerateSharedKey(dh.getPublicKey());

            System.err.println(dh.getSharedKey().toString(16));
            System.err.println(dh.getSharedKeyHash().toString(16));

        } catch (Exception lowSecurityLevel) {
            lowSecurityLevel.printStackTrace();
        }
        long endTime = System.currentTimeMillis();

        long duration = (endTime - startTime)/1000;
        System.err.println(duration);

    }
}
