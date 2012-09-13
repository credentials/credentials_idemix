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

package credentials.idemix.util;

import java.net.URI;
import java.util.Scanner;

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
	
	public void readBaseURL() {
		Scanner sc = null;
		try {
			sc = new Scanner(baseLocation.resolve("baseURL.txt").toURL().openStream());
			issuerBaseID = new URI(sc.nextLine());
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.toString());
		}
	}
	
	public void readCredID() {
		Scanner sc = null;
		try {
		sc = new Scanner(credStructBaseLocation.resolve("id.txt").toURL().openStream());
		credNr = (short) sc.nextInt();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e.toString());
		}
	}

	public void setupSystem() {
	    Locations.initSystem(baseLocation, issuerBaseID.toString());
	    Locations.init(issuerBaseID.resolve("ipk.xml"), issuerPKLocation);
	}
    
    public void setupCredentialStructure() {
    	Locations.init(credStructID, credStructLocation);
    }
    
    /**
     * You should use this. It is here only for testing. TODO
     * @param nr
     */
    public void setCredentialNr(short nr) {
    	credNr = nr;
    }
}
