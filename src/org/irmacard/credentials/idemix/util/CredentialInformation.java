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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Scanner;

import org.irmacard.credentials.idemix.spec.IdemixIssueSpecification;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.TreeWalker;
import org.irmacard.credentials.info.TreeWalkerI;

import com.ibm.zurich.idmx.utils.StructureStore;

public class CredentialInformation {
	static TreeWalkerI treeWalker;
	
	URI baseLocation;
	URI issuerPKLocation;

	URI credStructBaseLocation;
	URI credStructLocation;
	
	URI issuerBaseID;
	URI credStructID;
	
	short credNr;
	
	public static void setCoreLocation(URI coreLocation) {
		treeWalker = new TreeWalker(coreLocation);
	}
	
	public static void setTreeWalker(TreeWalkerI tw) {
		treeWalker = tw;
	}
	
	public CredentialInformation(String issuer, String credName) {
		completeSetup(issuer, credName);
	}
	
	public CredentialInformation(CredentialDescription cd) {
		completeSetup(cd.getIssuerID(),cd.getCredentialID());
	}
	
	private void completeSetup(String issuer, String credName) {
		try {
			baseLocation = new URI(issuer + "/");

			issuerPKLocation = baseLocation.resolve("ipk.xml");

			credStructBaseLocation = baseLocation.resolve("Issues/" + credName
					+ "/");
			credStructLocation = credStructBaseLocation
					.resolve("structure.xml");

			readBaseURL();
			readCredID();

			credStructID = issuerBaseID.resolve(credName + "/structure.xml");

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
	
	private void readBaseURL() {
		Scanner sc = null;
		try {
			sc = new Scanner(treeWalker.retrieveFile(baseLocation.resolve("baseURL.txt")));
			issuerBaseID = new URI(sc.nextLine());
			sc.close();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.toString());
		}
	}
	
	private void readCredID() {
		Scanner sc = null;
		try {
			sc = new Scanner(treeWalker.retrieveFile(credStructBaseLocation.resolve("id.txt")));
			credNr = (short) sc.nextInt();
			sc.close();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.toString());
		}
	}

	private void setupSystem() throws InfoException {
	    //Locations.initSystem(baseLocation, issuerBaseID.toString());
	    init(issuerBaseID.resolve("sp.xml"), baseLocation.resolve("sp.xml"));
	    init(issuerBaseID.resolve("gp.xml"), baseLocation.resolve("gp.xml"));
	    
	    //Locations.init(issuerBaseID.resolve("ipk.xml"), issuerPKLocation);
	    init(issuerBaseID.resolve("ipk.xml"), issuerPKLocation);
	}
    
    private void setupCredentialStructure() throws InfoException {
    	//Locations.init(credStructID, credStructLocation);
    	init(credStructID, credStructLocation);
    }
    
    /**
     * Add an object to the IdemixLibrary
     * @param id
     * @param file
     * @throws InfoException
     */
    protected Object init(URI id, URI file) throws InfoException {
    	return StructureStore.getInstance().get(id.toString(), treeWalker.retrieveFile(file));
    }
}
