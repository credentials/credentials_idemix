package org.irmacard.credentials.idemix.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

public class Crypto {
	public static final BigInteger TWO = new BigInteger("2");

	/**
	 * Creates a random integer in the range [-2^bitlength + 1, 2^bitlength - 1]
	 *
	 * TODO: Check random number generator
	 *
	 * @param bitlength		the bitlength of the resulting integer
	 * @return				a random signed integer in the given range
	 */
	public static BigInteger randomSignedInteger(int bitlength) {
		Random rnd = new Random();
		bitlength = 10;

		BigInteger maximum = TWO.pow(bitlength).subtract(BigInteger.ONE);
		BigInteger unsigned_maximum = maximum.multiply(TWO);

		BigInteger attempt = unsigned_maximum.add(BigInteger.ONE);
		while (attempt.compareTo(unsigned_maximum) > 0) {
			attempt = new BigInteger(bitlength + 1, rnd);
		}
		return attempt.subtract(maximum);
	}

	/**
	 * Computes the ASN.1 encoding (as used in IRMA) of a sequence of BigIntegers.
	 *
	 * Note that the number of elements is added as a first number in the sequence.
	 *
	 * @param values	The BigIntegers to include inthe ASN.1 encoding
	 */
	public static byte[] asn1Encode(BigInteger... values) {
		ASN1EncodableVector vector = new ASN1EncodableVector();

		// Store the number of values in the sequence too
		vector.add(new ASN1Integer(values.length));

		for(BigInteger value : values) {
			vector.add(new ASN1Integer(value));
		}

		DERSequence seq = new DERSequence(vector);
		byte[] encoding = null;

		try {
			encoding = seq.getEncoded();
		} catch (IOException e) {
			// IOException indicates encoding failure, this should never happen;
			e.printStackTrace();
		}

		return encoding;
	}

	/**
	 * The BigInteger representation of the SHA-256 hash of a byte array. The integer
	 * is always positive.
	 *
	 * @param input		A byte array of data to be hashed
	 * @return			The unsigned integer representing the hash value
	 */
	public static BigInteger sha256Hash(byte[] input) {
		byte[] hash = null;
		try {
			hash = MessageDigest.getInstance("SHA-256").digest(input);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Interpret the value as a _positive_ integer
		return new BigInteger(1, hash);
	}
}
