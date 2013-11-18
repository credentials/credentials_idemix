/**
 * CredentialInformation.java
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

package org.irmacard.credentials.idemix.util;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import org.irmacard.credentials.idemix.spec.IdemixIssueSpecification;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.TreeWalker;
import org.irmacard.credentials.info.TreeWalkerI;

import com.ibm.zurich.idmx.utils.StructureStore;

public class CredentialInformation {
	static TreeWalkerI treeWalker;
	
	protected URI baseLocation;
	private URI issuerPKLocation;
	
	private URI issuerBaseID;
	private URI credStructID;

	private CredentialDescription cd;

	short credNr;
	
	public static void setCoreLocation(URI coreLocation) {
		treeWalker = new TreeWalker(coreLocation);
	}
	
	public static void setTreeWalker(TreeWalkerI tw) {
		treeWalker = tw;
	}
	
	public CredentialInformation(String issuer, String credName) throws InfoException {
		this.cd = DescriptionStore.getInstance().getCredentialDescriptionByName(issuer, credName);
		completeSetup();
	}
	
	public CredentialInformation(CredentialDescription cd) {
		this.cd = cd;
		completeSetup();
	}
	
	private void completeSetup() {
		try {
			baseLocation = new URI(cd.getIssuerID() + "/");

			issuerPKLocation = baseLocation.resolve("ipk.xml");

			issuerBaseID = new URI(cd.getIssuerDescription().getBaseURL());
			credNr = cd.getId();

			credStructID = issuerBaseID.resolve(cd.getCredentialID() + "/structure.xml");

			setupSystem();

			setupCredentialStructure();
		} catch (InfoException e) {
			/* FIXME propagate exceptions further up the chain */
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (URISyntaxException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	public IdemixIssueSpecification getIdemixIssueSpecification() {
		return IdemixIssueSpecification.fromIdemixIssuanceSpec(
				issuerBaseID.resolve("ipk.xml"), credStructID, credNr);
	}

	private void setupSystem() throws InfoException {
	    init(issuerBaseID.resolve("sp.xml"), baseLocation.resolve("sp.xml"));
	    init(issuerBaseID.resolve("gp.xml"), baseLocation.resolve("gp.xml"));
	    init(issuerBaseID.resolve("ipk.xml"), issuerPKLocation);
	}
    
	private void setupCredentialStructure() throws InfoException {
		// init(credStructID, credStructLocation);
		init(credStructID,
				IdemixCredentialStructureCreator.createCredentialStructure(cd));
    }
    
    /**
     * Add an object to the IdemixLibrary from URI.
     * @param id
     * @param file
     * @throws InfoException
     */
    protected Object init(URI id, URI file) throws InfoException {
    	return init(id, treeWalker.retrieveFile(file));
    }

    /**
     * Add an object to the Idemix Library from InputStream.
     */
    protected Object init(URI id, InputStream stream) {
    	return StructureStore.getInstance().get(id.toString(), stream);
    }
}
