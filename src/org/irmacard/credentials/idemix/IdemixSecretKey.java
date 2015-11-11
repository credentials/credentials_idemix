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

	private void init(Document d) throws InfoException {
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
