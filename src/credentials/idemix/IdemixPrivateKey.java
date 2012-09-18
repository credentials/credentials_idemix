/**
 * IdemixPrivateKey.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package credentials.idemix;

import java.net.URI;

import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.key.IssuerPrivateKey;
import com.ibm.zurich.idmx.utils.StructureStore;

import credentials.keys.PrivateKey;

public class IdemixPrivateKey implements PrivateKey {
	private IssuerPrivateKey privateKey;

	public IdemixPrivateKey(IssuerPrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	/**
	 * Create an IdemixPrivateKey based on an Idemix Private Key Specification
	 * XML file.
	 * 
	 * Note: for now we assume that the system parameters, group parameters and
	 * issuer public key have already been loaded. Things do seem to work when
	 * this is not the case, but keep in mind that the private key cannot be
	 * used by the library until the public key and system and group parameters
	 * have also been loaded.
	 */
	public static IdemixPrivateKey fromIdemixPrivateKey(URI privateKeyLoc) {
		IssuerKeyPair ikp = (IssuerKeyPair) StructureStore.getInstance().get(
				privateKeyLoc);
		
		return new IdemixPrivateKey(ikp.getPrivateKey());
	}

	public IssuerPrivateKey getPrivateKey() {
		return privateKey;
	}

	public IssuerKeyPair getIssuerKeyPair() {
		return new IssuerKeyPair(privateKey);
	}
}
