/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.credentials.idemix.util;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

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
		SecureRandom rnd = new SecureRandom();

		BigInteger maximum = TWO.pow(bitlength).subtract(BigInteger.ONE);
		BigInteger unsigned_maximum = maximum.multiply(TWO);

		BigInteger attempt = unsigned_maximum.add(BigInteger.ONE);
		while (attempt.compareTo(unsigned_maximum) > 0) {
			attempt = new BigInteger(bitlength + 1, rnd);
		}
		return attempt.subtract(maximum);
	}

	public static BigInteger randomUnsignedInteger(int bitlength) {
		SecureRandom rnd = new SecureRandom();
		return new BigInteger(bitlength, rnd);
	}

	/**
	 * Creates a random element in the multiplicative group Z_{modulus}^*.
	 *
	 * @param modulus
	 *            The modulus of the group
	 * @return An elemement in Z_{modulus}^*
	 */
	public static BigInteger randomElementMultiplicativeGroup(BigInteger modulus) {
		SecureRandom rnd = new SecureRandom();
		BigInteger result = BigInteger.ZERO;

		while(result.compareTo(BigInteger.ZERO) <= 0 ||
				result.gcd(modulus).compareTo(BigInteger.ONE) != 0) {
			result = new BigInteger(modulus.bitLength(), rnd);
		}

		return result;
	}

	/**
	 * Computes the ASN.1 encoding (as used in IRMA) of a sequence of BigIntegers.
	 *
	 * Note that the number of elements is added as a first number in the sequence.
	 *
	 * @param values	The BigIntegers to include in the ASN.1 encoding
	 */
	public static byte[] asn1Encode(BigInteger... values) {
		return asn1Encode(Arrays.asList(values));
	}

	public static byte[] asn1Encode(List<BigInteger> values) {
		ASN1EncodableVector vector = new ASN1EncodableVector();

		// Store the number of values in the sequence too
		vector.add(new ASN1Integer(values.size()));

		for(BigInteger value : values) {
			vector.add(new ASN1Integer(value));
		}

		return finishAsn1Encoding(new DERSequence(vector));
	}

	/**
	 * @param values	The BigIntegers to include in the ASN.1 encoding
	 *
	 * @return asn1 encoded signature that can be used as a challenge
	 */
	public static byte[] asn1SigEncode(BigInteger... values) {
		return asn1SigEncode(Arrays.asList(values));
	}

	public static byte[] asn1SigEncode(List<BigInteger> values) {
		ASN1EncodableVector vector = new ASN1EncodableVector();

		// Start with a boolean set to true to indicate that this is a signature
		vector.add(ASN1Boolean.getInstance(true));

		// Store the number of values in the sequence too
		vector.add(new ASN1Integer(values.size()));

		for(BigInteger value : values) {
			vector.add(new ASN1Integer(value));
		}

		return finishAsn1Encoding(new DERSequence(vector));
	}

	/**
	 * Convert DERSequence into byte array
	 * @throws RuntimeException if something goes completely wrong
	 */
	private static byte[] finishAsn1Encoding(DERSequence seq) {
		try {
			return seq.getEncoded();
		} catch (IOException e) {
			// IOException indicates encoding failure, this should never happen;
			e.printStackTrace();
			throw new RuntimeException("DER encoding failed");
		}
	}

	/**
	 * The BigInteger representation of the SHA-256 hash of a byte array. The integer
	 * is always positive.
	 *
	 * @param input		A byte array of data to be hashed
	 * @return			The unsigned integer representing the hash value
	 */
	public static BigInteger sha256Hash(byte[]... input) {
		byte[] hash = null;
		try {
			for (byte[] arr : input)
				if (arr != null)
					hash = MessageDigest.getInstance("SHA-256").digest(arr);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("Algorithm SHA-256 not found");
		}

		// Interpret the value as a _positive_ integer
		return new BigInteger(1, hash);
	}

	/**
	 * Returns a BigInteger in the range [2^start, 2^start + 2^length] that is
	 * probably prime. The probability that the number is not prime is no more
	 * than 2^(-100).
	 *
	 * TODO: Make sure this code is correct
	 *
	 * @param start_in_bits
	 *            The start of the interval (in bits)
	 * @param length_in_bits
	 *            The length of the interval (non-inclusive) (in bits)
	 * @return A number in the given range that is probably prime
	 */
	public static BigInteger probablyPrimeInBitRange(int start_in_bits, int length_in_bits) {
		SecureRandom rnd = new SecureRandom();
		BigInteger start = TWO.pow(start_in_bits);
		BigInteger end = start.add(TWO.pow(length_in_bits));
		BigInteger prime = end;

		// Ensure that the generated prime is never too big
		while (prime.compareTo(end) >= 0) {
			BigInteger offset = new BigInteger(length_in_bits, rnd);
			prime = start.add(offset).nextProbablePrime();
		}

		return prime;
	}

	/**
	 * A representation of the given exponents in terms of the given bases. For
	 * given bases bases[1],...,bases[k]; exponents exps[1],...,exps[k] and
	 * modulus this function returns bases[k]^{exps[1]}*...*bases[k]^{exps[k]}
	 * (mod modulus)
	 *
	 * @param bases		bases to represent exponents in
	 * @param exps		exponents to represent
	 * @param modulus	the modulus
	 * @return			representation of the exponents in terms of the bases
	 */
	public static BigInteger representToBases(List<BigInteger> bases,
			List<BigInteger> exps, BigInteger modulus, int maxMessageLength) {

		if (bases.size() < exps.size()) {
			throw new RuntimeException("Not enough bases to represent exponents");
		}

		BigInteger r = BigInteger.ONE;
		BigInteger tmp;
		BigInteger exponent;
		for (int i = 0; i < exps.size(); i++) {
			exponent = exps.get(i);
			if (exponent.bitLength() > maxMessageLength)
				exponent = Crypto.sha256Hash(exponent.toByteArray());

			// tmp = bases_i ^ exps_i (mod modulus), with exps_i hashed if it exceeds maxMessageLength
			tmp = bases.get(i).modPow(exponent, modulus);

			// r = r * tmp (mod modulus)
			r = r.multiply(tmp).mod(modulus);
		}
		return r;
	}
}
