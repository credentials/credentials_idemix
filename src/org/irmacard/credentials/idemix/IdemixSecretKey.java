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

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;

import org.irmacard.credentials.info.ConfigurationParser;
import org.irmacard.credentials.info.InfoException;
import org.w3c.dom.Document;

/**
 * Represents an Idemix private key
 *
 * TODO: This class is erroneously named, it should be IdemixPrivateKey,
 * but that causes too many conflicts for now.
 *
 */
public class IdemixSecretKey extends ConfigurationParser {
	private BigInteger p;
	private BigInteger q;

	private BigInteger p_prime;
	private BigInteger q_prime;

	public IdemixSecretKey(BigInteger p, BigInteger q) throws InfoException {
		super();

		this.p = p;
		this.q = q;

		this.p_prime = p.subtract(BigInteger.ONE).shiftRight(1);
		this.q_prime = q.subtract(BigInteger.ONE).shiftRight(1);
	}

	/**
	 * Secret key constructed from the given file
	 * @param file Input XML file.
	 * @throws InfoException on error with XML parsing
	 */
	public IdemixSecretKey(URI file) throws InfoException {
		super();
		Document d = parse(file);
		init(d);
	}

	/**
	 * Secret key constructed from InputStream.
	 * @param stream InputStream for XML file.
	 * @throws InfoException on error with XML parsing
	 */
	public IdemixSecretKey(InputStream stream) throws InfoException {
		super();
		Document d = parse(stream);
		init(d);
	}

	private void init(Document d) {
		p = new BigInteger(getFirstTagText(d, "p"));
		q = new BigInteger(getFirstTagText(d, "q"));
		p_prime = new BigInteger(getFirstTagText(d, "pPrime"));
		q_prime = new BigInteger(getFirstTagText(d, "qPrime"));
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
