package SecureKeyExchange;

import SecureKeyExchange.Exceptions.LowSecurityLevel;
import SecureKeyExchange.Math.NumberTheory;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Random;

/**
 * Created by Jose on 15/08/2015.
 */
public class RSAKey {

    public BigInteger p;
    public BigInteger q;
    public BigInteger N;
    public BigInteger E;
    public BigInteger d;
    public BigInteger dP;
    public BigInteger dQ;
    public BigInteger qInv;

    public void SetPublicKeys(BigInteger N, BigInteger E) {
        this.N = N;
        this.E = E;
    }

    public void SetPrivateKeys(BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv) {
        this.p = p;
        this.q = q;
        this.dP = dP;
        this.dQ = dQ;
        this.qInv = qInv;
    }

    public void GenerateKeys(int minBitLength) throws LowSecurityLevel {
        BigInteger phi;

        this.p = NumberTheory.GenerateSafePrime(minBitLength);
        this.q = NumberTheory.GenerateSafePrime(minBitLength);
        this.N = p.multiply(q);

        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        this.E = new BigInteger("65537", 10);

        while (!E.gcd(phi).equals(BigInteger.ONE))
            E.add(BigInteger.ONE);

        this.d = E.modInverse(phi);

        this.dP = d.mod(p.subtract(BigInteger.ONE));
        this.dQ = d.mod(q.subtract(BigInteger.ONE));
        this.qInv = q.modInverse(p);

    }

    public int getBlockSize() {
        return (this.N.bitLength() + 7) / 8;
    }

    public byte[] Decrypt(byte[] src, int length) {
        byte[] pad = PKCS1Unpad(src, getBlockSize(), 0x02);
        BigInteger biPad = new BigInteger(pad);

        return this.doPrivate(biPad).toByteArray();
    }

    public byte[] Sign(byte[] src, int length) {
        byte[] pad = PKCS1Pad(src, getBlockSize());
        BigInteger biPad = new BigInteger(pad);

        return this.doPrivate(biPad).toByteArray();
    }

    public byte[] Verify(byte[] src, int length) {
        BigInteger bi = new BigInteger(src);
        byte[] padded = this.doPublic(bi).toByteArray();

        return PCKS1Unpad(padded, getBlockSize());
    }

    public byte[] Encrypt(byte[] src, int length) {
        byte[] padded = PKCS1Pad(src, getBlockSize());
        BigInteger bi = new BigInteger(padded);
        return this.doPublic(bi).toByteArray();
    }

    private byte[] PKCS1Pad(byte[] src, int n) {
        return PKCS1Pad(src, n, 0x02);
    }

    private byte[] PCKS1Unpad(byte[] src, int n) {
        return PKCS1Unpad(src, n, 0x02);
    }

    private byte[] PKCS1Unpad(byte[] src, int n, int type) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int i = 0;

        while (i < src.length && src[i] == 0) i++;

        if (src.length - i != n - 1 || src[i] > 2) return null;
        i++;

        while (src[i] != 0) if (++i >= src.length) return null;

        while (++i < src.length) out.write(src[i]);
        return out.toByteArray();
    }

    public BigInteger doPrivate(BigInteger bi) {
        BigInteger xp, xq;
        xp = bi.mod(p).modPow(dP, p);
        xq = bi.mod(p).modPow(dQ, q);

        while (xp.compareTo(xq) < 0) {
            xp = xp.add(p);
        }
        return xp.subtract(xq).multiply(qInv).mod(p).multiply(q).add(xq);
    }

    public BigInteger doPublic(BigInteger bi) {
        return bi.modPow(E, N);
    }

    private byte[] PKCS1Pad(byte[] src, int n, int type) {
        byte[] out = new byte[n];
        int i = src.length;
        while (i >= 0 && n > 11) out[--n] = src[i--];
        out[--n] = 0;

        Random rng = new Random();

        while (n > 2) out[--n] = (byte) ((type == 0x02) ? (rng.nextInt() % 256) : 0xFF);

        out[--n] = (byte) type;
        out[--n] = 0;

        return out;
    }
}
