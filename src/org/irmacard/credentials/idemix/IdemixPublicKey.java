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

import java.math.BigInteger;
import java.util.List;

/**
 * Represents an Idemix public key.
 */
public class IdemixPublicKey {
	private BigInteger n;
	private BigInteger Z;
	private BigInteger S;

	private List<BigInteger> R;

	public IdemixPublicKey(BigInteger n, BigInteger Z, BigInteger S, List<BigInteger> R) {
		this.n = n;
		this.Z = Z;
		this.S = S;
		this.R = R;
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
}
