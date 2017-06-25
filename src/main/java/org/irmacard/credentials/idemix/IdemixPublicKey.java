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

import org.irmacard.credentials.PublicKey;
import org.irmacard.credentials.info.ConfigurationParser;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.PublicKeyIdentifier;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.util.*;

/**
 * Represents an Idemix public key.
 */
@SuppressWarnings("unused")
public class IdemixPublicKey extends ConfigurationParser implements PublicKey {
	private BigInteger n;
	private BigInteger Z;
	private BigInteger S;

	private List<BigInteger> R;

	private transient IdemixSystemParameters systemParameters;
	private IssuerIdentifier issuer;

	private int counter;
	private Date expiryDate;

	public IdemixPublicKey(BigInteger n, BigInteger Z, BigInteger S,
			List<BigInteger> R) {

		super();

		this.n = n;
		this.Z = Z;
		this.S = S;
		this.R = R;
	}

	public IdemixPublicKey(int size) {
		R = new ArrayList<>();
		for(int i = 0; i < size; i++) {
			R.add(null);
		}
	}

	public void set_n(BigInteger n) {
		this.n = n;
	}

	public void set_Z(BigInteger Z) {
		this.Z = Z;
	}

	public void set_S(BigInteger S) {
		this.S = S;
	}

	public void set_Ri(int i, BigInteger Ri) {
		System.out.println("Setting R" + i + ": " + Ri);
		R.set(i, Ri);
	}

	/**
	 * Public key constructed from the given file
	 * @param file Input XML file.
	 * @throws InfoException on error with XML parsing
	 */
	public IdemixPublicKey(URI file) throws InfoException {
		super();
		Document d = parse(file);
		init(d);
	}

	/**
	 * Public key constructed from InputStream.
	 * @param stream InputStream for XML file.
	 * @throws InfoException on error with XML parsing
	 */
	public IdemixPublicKey(InputStream stream) throws InfoException {
		super();
		Document d = parse(stream);
		init(d);
	}

	public IdemixPublicKey(String xml) throws InfoException {
		this(new ByteArrayInputStream(xml.getBytes()));
	}

	public IdemixPublicKey(String xml, IssuerIdentifier issuer) throws InfoException {
		this(new ByteArrayInputStream(xml.getBytes()));
		this.issuer = issuer;
	}

	public IdemixPublicKey(InputStream retrieveFile, IssuerIdentifier issuer)
			throws InfoException {
		this(retrieveFile);
		this.issuer = issuer;
	}

	private void init(Document d) throws InfoException {
		n = new BigInteger(getFirstTagText(d, "n"));
		Z = new BigInteger(getFirstTagText(d, "Z"));
		S = new BigInteger(getFirstTagText(d, "S"));

		counter = Integer.valueOf(getFirstTagText(d, "Counter"));
		expiryDate = new Date(Long.valueOf(getFirstTagText(d, "ExpiryDate")) * 1000);

		Element bases = ((Element) d.getElementsByTagName("Bases").item(0));
		int num_bases = Integer.parseInt(bases.getAttribute("num"));
		R = new Vector<>();
		for(int i = 0; i < num_bases; i++) {
			String base = bases.getElementsByTagName("Base_" + i).item(0).getTextContent().trim();
			R.add(new BigInteger(base));
		}
	}

	public int getBitsize() {
		return n.bitLength();
	}

	public BigInteger getModulus() {
		return n;
	}

	public BigInteger getGeneratorZ() {
		return Z;
	}

	public BigInteger getGeneratorS() {
		return S;
	}

	public BigInteger getGeneratorR(int i) {
		return R.get(i);
	}

	public List<BigInteger> getGeneratorsR() {
		return R;
	}

	public IdemixSystemParameters getSystemParameters() {
		if (systemParameters == null) {
			try {
				systemParameters = IdemixSystemParameters.get(getBitsize());
			} catch (InfoException e) {
				throw new RuntimeException(e);
			}
		}

		return systemParameters;
	}

	public String toString() {
		return "Public key: " + R.get(0);
	}

	public void setCounter(int counter) {
		this.counter = counter;
	}

	@Override
	public int getCounter() {
		return counter;
	}

	public Date getExpiryDate() {
		return expiryDate;
	}

	public boolean isValid() {
		return isValidOn(Calendar.getInstance().getTime());
	}

	@Override
	public boolean isValidOn(Date date) {
		return expiryDate.after(date);
	}

	public void setIssuerIdentifier(IssuerIdentifier issuer) {
		this.issuer = issuer;
	}

	public IssuerIdentifier getIssuerIdentifier() {
		return issuer;
	}

	public PublicKeyIdentifier getIdentifier() {
		return new PublicKeyIdentifier(issuer, counter);
	}
}
