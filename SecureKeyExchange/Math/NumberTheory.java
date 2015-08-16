package SecureKeyExchange.Math;

import SecureKeyExchange.Exceptions.LowSecurityLevel;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Jose on 15/08/2015.
 */
public class NumberTheory {

    protected static BigInteger two = new BigInteger("2", 10);
    protected static BigInteger six = new BigInteger("6", 10);
    protected static SecureRandom sr = new SecureRandom();

    /**
     * Check if our prime is secure
     *
     * @param prime
     * @return
     */
    public static Boolean TestSafePrime(BigInteger prime) {
        return NumberTheory.TestSafePrime(prime, 10);
    }

    public static Boolean TestSafePrime(BigInteger prime, int confidence) {
        return prime
                .subtract(BigInteger.ONE)
                .divide(two)
                .isProbablePrime(confidence);
    }

    /**
     * Check if our generator is a real generator.
     *
     * @param generator
     * @param safePrime
     * @return
     */
    public static Boolean TestGeneratorIntegrity(BigInteger generator, BigInteger safePrime) {
        if (!TestSafePrime(safePrime)) return false;

        if (generator.compareTo(safePrime) >= 0) return false;

        BigInteger primeMinusOne, factor1, factor2;

        primeMinusOne = safePrime.subtract(BigInteger.ONE);
        factor1 = two;
        factor2 = primeMinusOne.divide(two);

        if (generator.modPow(factor1, safePrime).equals(BigInteger.ONE) || generator.modPow(factor2, safePrime).equals(BigInteger.ONE))
            return false;


        return true;
    }


    /**
     * Generate a safe prime number that avoid Pollard's algorithm (No factorization - No discrete logarithm)
     *
     * @param minBitLength
     * @return
     * @throws LowSecurityLevel
     */
    public static BigInteger GenerateSafePrime(int minBitLength) throws LowSecurityLevel {
        return GenerateSafePrime(minBitLength, 10);
    }

    public static BigInteger GenerateSafePrime(int minBitLength, int confidence) throws LowSecurityLevel {
        BigInteger m, p;

        do {
            // Sophie Germain neccesary condition.
            m = new BigInteger(minBitLength, sr);
            p = m.multiply(six).subtract(BigInteger.ONE);
        } while (!p.isProbablePrime(confidence) || !TestSafePrime(p, confidence));
        return p;
    }

    /**
     * Generate a secure generator
     *
     * @param safePrime
     * @return
     * @throws LowSecurityLevel
     */

    public static BigInteger GenerateGeneratorBasedInSafePrime(BigInteger safePrime) throws LowSecurityLevel {
        if (!TestSafePrime(safePrime))
            throw new LowSecurityLevel("You can't generate a safe generator for a non-secure prime");

        BigInteger x;
        do {
            x = new BigInteger(safePrime.bitLength() - 1, sr);
        } while (TestGeneratorIntegrity(x, safePrime));

        return x;
    }

    public static BigInteger GenerateRandom(int bitLength) {
        return new BigInteger(bitLength, sr);
    }
}
