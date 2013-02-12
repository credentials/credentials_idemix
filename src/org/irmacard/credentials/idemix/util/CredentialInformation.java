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
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.irmacard.credentials.idemix.spec.IdemixIssueSpecification;

import com.ibm.zurich.credsystem.utils.Locations;

public class CredentialInformation {
	static URI CORE_LOCATION;
	
	URI baseLocation;
	URI issuerPKLocation;

	URI credStructBaseLocation;
	URI credStructLocation;
	
	URI issuerBaseID;
	URI credStructID;
	
	short credNr;
	
	public static void setCoreLocation(URI coreLocation) {
		CORE_LOCATION = coreLocation;
	}
	
	public CredentialInformation(String issuer, String credName) {
		completeSetup(issuer, credName);
	}
	
	public CredentialInformation(URI path) {
		// FIXME: this is a bit of a hack, as it is not really robust,
		// but for now it serves our purpose
		String p = path.toString();
		
		Matcher m = Pattern.compile(".*/([^/]*)/([^/]*)/([^/]*)/$").matcher(p);
		completeSetup(m.replaceFirst("$1"), m.replaceFirst("$3"));
	}
	
	private void completeSetup(String issuer, String credName) {
		baseLocation = CORE_LOCATION.resolve(issuer + "/");
		issuerPKLocation = baseLocation.resolve("ipk.xml");

		credStructBaseLocation = baseLocation.resolve("Issues/" + credName + "/");
		credStructLocation = credStructBaseLocation.resolve("structure.xml");

		readBaseURL();
		readCredID();

		credStructID = issuerBaseID.resolve(credName + "/structure.xml");
		
		setupSystem();
		setupCredentialStructure();
	}

	public IdemixIssueSpecification getIdemixIssueSpecification() {
		return IdemixIssueSpecification.fromIdemixIssuanceSpec(
				issuerPKLocation, credStructID, credNr);
	}
	
	private void readBaseURL() {
		Scanner sc = null;
		try {
			sc = new Scanner(baseLocation.resolve("baseURL.txt").toURL().openStream());
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
			sc = new Scanner(credStructBaseLocation.resolve("id.txt").toURL().openStream());
			credNr = (short) sc.nextInt();
			sc.close();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.toString());
		}
	}

	private void setupSystem() {
	    Locations.initSystem(baseLocation, issuerBaseID.toString());
	    Locations.init(issuerBaseID.resolve("ipk.xml"), issuerPKLocation);
	}
    
    private void setupCredentialStructure() {
    	Locations.init(credStructID, credStructLocation);
    }
}
