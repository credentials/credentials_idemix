/**
 * IdemixSecretKey.java
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2014.
 */

package org.irmacard.credentials.idemix;

import java.math.BigInteger;

/**
 * Represents an Idemix private key
 *
 * TODO: This class is erroneously named, it should be IdemixPrivateKey,
 * but that causes too many conflicts for now.
 *
 */
public class IdemixSecretKey {
	private BigInteger p;
	private BigInteger q;

	private BigInteger p_prime;
	private BigInteger q_prime;

	public IdemixSecretKey(BigInteger p, BigInteger q) {
		this.p = p;
		this.q = q;

		this.p_prime = p.subtract(BigInteger.ONE).shiftRight(1);
		this.q_prime = q.subtract(BigInteger.ONE).shiftRight(1);
	}

	public BigInteger get_p() {
		return p;
	}

	public BigInteger get_q() {
		return q;
	}

	public BigInteger get_p_prime() {
		return p;
	}

	public BigInteger get_q_prime() {
		return q;
	}

	public BigInteger get_p_prime_q_prime() {
		return p_prime.multiply(q_prime);
	}
}
