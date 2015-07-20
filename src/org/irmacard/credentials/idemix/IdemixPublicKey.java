/**
 * IdemixPublicKey.java
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
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import org.irmacard.credentials.info.ConfigurationParser;
import org.irmacard.credentials.info.InfoException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Represents an Idemix public key.
 */
public class IdemixPublicKey extends ConfigurationParser {
	private BigInteger n;
	private BigInteger Z;
	private BigInteger S;

	private List<BigInteger> R;

	private IdemixSystemParameters systemParameters = new IdemixSystemParameters();

	public IdemixPublicKey(BigInteger n, BigInteger Z, BigInteger S,
			List<BigInteger> R) {

		super();

		// Enable serialization
		this.db = null;

		this.n = n;
		this.Z = Z;
		this.S = S;
		this.R = R;
	}

	public IdemixPublicKey(int size) {
		R = new ArrayList<BigInteger>();
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

	private void init(Document d) throws InfoException {
		n = new BigInteger(getFirstTagText(d, "n"));
		Z = new BigInteger(getFirstTagText(d, "Z"));
		S = new BigInteger(getFirstTagText(d, "S"));

		Element bases = ((Element) d.getElementsByTagName("Bases").item(0));
		int num_bases = Integer.parseInt(bases.getAttribute("num"));
		R = new Vector<BigInteger>();
		for(int i = 0; i < num_bases; i++) {
			String base = bases.getElementsByTagName("Base_" + i).item(0).getTextContent().trim();
			R.add(new BigInteger(base));
		}
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
		return systemParameters;
	}

	public String toString() {
		return "Public key: " + R.get(0);
	}
}
