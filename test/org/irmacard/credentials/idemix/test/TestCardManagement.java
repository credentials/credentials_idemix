package org.irmacard.credentials.idemix.test;

import java.io.File;
import java.net.URI;
import java.util.List;

import javax.smartcardio.CardException;

import net.sourceforge.scuba.smartcards.CardServiceException;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixCredentials;
import org.irmacard.credentials.idemix.util.CredentialInformation;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.util.log.LogEntry;
import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.IdemixSmartcard;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestCardManagement {
	@BeforeClass
	public static void initializeInformation() {
		URI core = new File(System.getProperty("user.dir")).toURI().resolve(
				"irma_configuration/");
		CredentialInformation.setCoreLocation(core);
		DescriptionStore.setCoreLocation(core);
	}
	
	@Test
	public void testGetCredentials() throws CredentialsException, CardServiceException, InfoException, CardException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		
		List<CredentialDescription> credentials = ic.getCredentials();
		
		System.out.println("Found the following credentials on the card:");
		for(CredentialDescription ds : credentials) {
			System.out.println(" * " + ds.toString());
		}
	}
	
	/**
	 * For now we assume that at least one credential has been loaded on the card.
	 * @throws CredentialsException
	 * @throws CardServiceException
	 * @throws InfoException
	 * @throws CardException
	 */
	@Test
	public void testGetAttributes() throws CredentialsException, CardServiceException, InfoException, CardException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		
		List<CredentialDescription> credentials = ic.getCredentials();
		
		System.out.println("Found the following credentials on the card:");
		for(CredentialDescription ds : credentials) {
			System.out.println(" * " + ds.toString());
			Attributes attr = ic.getAttributes(ds);
			attr.print();
		}
	}

	@Test
	public void testGetLogs() throws CardException, CredentialsException, CardServiceException, InfoException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);

		List<LogEntry> logs = ic.getLog();
		for(LogEntry log_entry : logs) {
			System.out.println(log_entry.toString());
		}
	}
}
