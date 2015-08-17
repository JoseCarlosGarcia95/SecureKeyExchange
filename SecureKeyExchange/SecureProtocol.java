package SecureKeyExchange;

import SecureKeyExchange.Enums.DHSecurityLevel;
import SecureKeyExchange.Exceptions.LowSecurityLevel;
import SecureKeyExchange.Math.NumberTheory;

import java.math.BigInteger;
import java.util.ArrayList;

/**
 * Created by Jose on 16/08/2015.
 */
public class SecureProtocol {

    private DiffieHellman diffieHellman;
    private RSAKey rsaKey;

    /**
     * Start RSAKey and Diffie Hellman class, will be useful! 
     */
    public SecureProtocol() {
        this.diffieHellman = new DiffieHellman(DHSecurityLevel.High);
        this.rsaKey = new RSAKey();
    }

    /**
     * This function must be used by the server to generate random keys securely.
     */
    public void GenerateKeys() {
        try {
            this.diffieHellman.GenerateKeys();
        } catch (LowSecurityLevel lowSecurityLevel) {
            lowSecurityLevel.printStackTrace();
        }
    }

    /**
     * Initialize Diffie Hellman with values from the server.
     *
     * @param p
     * @param g
     * @param pk
     * @throws LowSecurityLevel
     */
    public void SetDHPublicKeys(BigInteger p, BigInteger g, BigInteger pk) throws LowSecurityLevel {
        byte[] generator, prime, publicKey;
        long checksum, x0, x1;
        int i;

        /* At first, we don't need extra security for our generator because the groups depends of prime */
        generator = g.toByteArray();
        generator = this.rsaKey.Verify(generator, generator.length);

        g = new BigInteger(generator);

        /* Add an extra security because an attacker could use again the prime number. */
        prime = p.toByteArray();
        prime = this.rsaKey.Verify(prime, prime.length);

        p = new BigInteger(prime);

        ArrayList<BigInteger> factors = NumberTheory.factorize(p);
        checksum = 1;
        i = 0;

        while (factors.get(i).compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0)
            checksum *= factors.get(i++).longValue();

        p = factors.get(i);

        x1 = System.currentTimeMillis() + 20000;
        x0 = x1 - 40000;

        if (!(x0 < checksum && x1 > checksum))
            throw new LowSecurityLevel("User try to make an specialized Diffie Hellman attack");
        /* We don't need an extra security */
        publicKey = pk.toByteArray();
        publicKey = this.rsaKey.Verify(publicKey, publicKey.length);

        pk = new BigInteger(publicKey);

        this.diffieHellman.Init(p, g);
        this.diffieHellman.GenerateSharedKey(pk);
    }
    public void SetDHPublicKeys(BigInteger pk) throws  LowSecurityLevel {
        byte[] publicKey = pk.toByteArray();
        publicKey = this.rsaKey.Decrypt(publicKey, publicKey.length);

        pk = new BigInteger(publicKey);

        this.diffieHellman.GenerateSharedKey(pk);
    }

    /**
     * Get Diffie Hellman prime with extra security.
     * @return
     */
    public BigInteger getDHGroup() {
        byte[] prime = this.diffieHellman.getPrime()
                .multiply(BigInteger.valueOf(System.currentTimeMillis()))
                .toByteArray();

        prime = this.rsaKey
                .Sign(prime, prime.length);

        return new BigInteger(prime);
    }

    /**
     * Get Diffie Hellman generator.
     * @return
     */
    public BigInteger getDHGenerator() {
        byte[] generator = this.diffieHellman.getGenerator()
                .toByteArray();

        generator = this.rsaKey
                .Sign(generator, generator.length);

        return new BigInteger(generator);
    }



    /**
     * Verify shared key hash to avoid man in the middle attack.
     * @param bi
     * @return
     */
    public Boolean verifySharedKey(BigInteger bi) {
        byte[] sharedKeyHash;
        sharedKeyHash = bi.toByteArray();
        sharedKeyHash = this.rsaKey.Verify(sharedKeyHash, sharedKeyHash.length);

        bi = new BigInteger(sharedKeyHash);

        try {
            return bi.compareTo(this.diffieHellman.getSharedKeyHash()) == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
