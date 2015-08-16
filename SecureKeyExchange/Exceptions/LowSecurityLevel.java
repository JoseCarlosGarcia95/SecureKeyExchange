package SecureKeyExchange.Exceptions;

public class LowSecurityLevel extends Exception {
    private String ExInformation;

    public LowSecurityLevel(String Ex) {
        this.ExInformation = Ex;
    }
}
