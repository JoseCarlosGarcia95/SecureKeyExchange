package SecureKeyExchange.Math;

import SecureKeyExchange.Exceptions.LowSecurityLevel;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

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

    /**
     * Generate a random BigInteger
     *
     * @param bitLength
     * @return
     */
    public static BigInteger GenerateRandom(int bitLength) {
        return new BigInteger(bitLength, sr);
    }

    /**
     * Factorice a number "n" with Pollard's rho function.
     *
     * @param n
     * @return
     */
    public static ArrayList<BigInteger> factorize(BigInteger n) {
        ArrayList<BigInteger> factors = new ArrayList<BigInteger>();

        BigInteger divisor;
        do {
            divisor = rho(n);
            factors.add(divisor);
            n = n.divide(divisor);
        } while (n.equals(BigInteger.ONE));

        return factors;
    }

    /**
     * Pollard's rho function.
     *
     * @param n
     * @return
     */
    public static BigInteger rho(BigInteger n) {
        if (n.isProbablePrime(10)) return n;
        BigInteger divisor;
        BigInteger c = new BigInteger(n.bitLength(), sr);
        BigInteger x = new BigInteger(n.bitLength(), sr);
        BigInteger xx = x;

        // check divisibility by 2
        if (n.mod(two).compareTo(BigInteger.ZERO) == 0) return two;

        do {
            x = x.multiply(x).add(c).mod(n);
            xx = xx.multiply(xx).add(c).mod(n);
            xx = xx.multiply(xx).add(c).mod(n);
            divisor = x.subtract(xx).gcd(n);
        } while ((divisor.compareTo(BigInteger.ONE)) == 0);

        return divisor;

    }
}
