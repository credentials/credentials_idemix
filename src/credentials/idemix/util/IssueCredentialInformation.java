/**
 * IssuerCredentialInformation.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, September 2012.
 */

package credentials.idemix.util;

import java.net.URI;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.issuance.Issuer;
import com.ibm.zurich.idmx.key.IssuerKeyPair;

import credentials.Attributes;
import credentials.idemix.IdemixPrivateKey;
import credentials.idemix.spec.IdemixIssueSpecification;

public class IssueCredentialInformation extends CredentialInformation {
	URI issuerSKLocation;
	
	public IssueCredentialInformation(String issuer, String credName) {
		super(issuer, credName);

		issuerSKLocation = baseLocation.resolve("private/isk.xml");
		System.out.println("HELLO: set issuerSKLoc to: " + issuerSKLocation.toString());

		setupIssuer();
	}
	
	public IdemixIssueSpecification getIdemixIssueSpecification() {
		return IdemixIssueSpecification.fromIdemixIssuanceSpec(
				issuerPKLocation, credStructID, credNr);
	}
	
	public IdemixPrivateKey getIdemixPrivateKey() {
		IssuerKeyPair ikp = (IssuerKeyPair) Locations.init(issuerSKLocation);
		return new IdemixPrivateKey(ikp.getPrivateKey());
	}
	
    public void setupIssuer() {
    	Locations.initIssuer(baseLocation, issuerBaseID.toString(),
    			issuerSKLocation, issuerPKLocation, issuerBaseID.resolve("ipk.xml"));
    }
    
    public Issuer getIssuer(Attributes attributes) {
		return new Issuer(getIdemixPrivateKey().getIssuerKeyPair(),
				getIdemixIssueSpecification().getIssuanceSpec(), null, null,
				getIdemixIssueSpecification().getValues(attributes));
	}
}
