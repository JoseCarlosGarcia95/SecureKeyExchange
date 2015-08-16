package SecureKeyExchange;

import SecureKeyExchange.Enums.DHSecurityLevel;
import SecureKeyExchange.Exceptions.LowSecurityLevel;
import SecureKeyExchange.Math.NumberTheory;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Created by Jose on 15/08/2015.
 */
public class DiffieHellman {

    private BigInteger prime;
    private BigInteger generator;
    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger sharedKey;

    private DHSecurityLevel securityLevel;

    public DiffieHellman(DHSecurityLevel securityLevel) {
        this.securityLevel = securityLevel;
    }

    /**
     * Generate Diffie Hellman keys.
     */
    public void GenerateKeys() throws LowSecurityLevel {
        switch (this.securityLevel) {
            case Extreme:
                this.prime = NumberTheory.GenerateSafePrime(512);
                this.generator = NumberTheory.GenerateGeneratorBasedInSafePrime(this.prime);
                this.privateKey = NumberTheory.GenerateRandom(this.prime.bitLength() - 3);
                this.publicKey = this.generator.modPow(this.privateKey, this.prime);
                break;
            case High:
                this.prime = NumberTheory.GenerateSafePrime(256);
                this.generator = NumberTheory.GenerateGeneratorBasedInSafePrime(this.prime);
                this.privateKey = NumberTheory.GenerateRandom(this.prime.bitLength() - 3);
                this.publicKey = this.generator.modPow(this.privateKey, this.prime);

                break;
        }
    }

    public void Init(BigInteger prime, BigInteger generator) throws LowSecurityLevel {
        if (this.securityLevel == DHSecurityLevel.Extreme && (!NumberTheory.TestGeneratorIntegrity(generator, prime) || prime.bitLength() < 512))
            throw new LowSecurityLevel("Diffie Hellman keys aren't secures");

        if (this.securityLevel == DHSecurityLevel.High && (!NumberTheory.TestGeneratorIntegrity(generator, prime) || prime.bitLength() < 256))
            throw new LowSecurityLevel("Diffie Hellman keys aren't secures");

        this.prime = prime;
        this.generator = generator;
        this.privateKey = NumberTheory.GenerateRandom(this.prime.bitLength() - 3);
        this.publicKey = this.generator.modPow(this.privateKey, this.prime);
    }

    public void GenerateSharedKey(BigInteger publicKey) throws LowSecurityLevel {

        if (publicKey.equals(BigInteger.ONE) || publicKey.equals(BigInteger.ZERO) || publicKey.mod(prime).equals(BigInteger.ZERO))
            throw new LowSecurityLevel("Unsafe public key");

        this.sharedKey = publicKey.modPow(this.privateKey, this.prime);

        this.publicKey = this.prime = this.generator = this.privateKey = null;
    }

    public BigInteger getSharedKeyHash() throws Exception {
        byte[] sharedKeyBytes = this.sharedKey.toByteArray();

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(sharedKeyBytes);

        byte[] hashed = md.digest();

        return new BigInteger(hashed).abs();
    }

    public BigInteger getSharedKey() {
        return this.sharedKey;
    }

    public BigInteger getPublicKey() {
        return this.publicKey;
    }
}
