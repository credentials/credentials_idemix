/**
 * TestSecureMessaging.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, September 2012.
 */

package org.ru.irma.api.tests.idemix;

import static org.junit.Assert.fail;

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.IResponseAPDU;
import net.sourceforge.scuba.smartcards.TerminalCardService;
import net.sourceforge.scuba.smartcards.WrappingCardService;
import net.sourceforge.scuba.util.Hex;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.BeforeClass;
import org.junit.Test;

import service.IdemixService;
import service.IdemixSmartcard;
import service.ProtocolCommand;
import service.ProtocolResponse;
import service.ProtocolResponses;

import credentials.Attributes;
import credentials.CredentialsException;
import credentials.Nonce;
import credentials.idemix.IdemixCredentials;
import credentials.idemix.spec.IdemixVerifySpecification;
import credentials.idemix.util.CredentialInformation;
import credentials.idemix.util.VerifyCredentialInformation;
import credentials.util.CardHolderVerificationService;
import credentials.util.SecureMessagingWrapper;

public class TestSecureMessaging {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
	private static final IvParameterSpec ZERO_IV_PARAM_SPEC = 
			new IvParameterSpec(new byte[8]);
	
	@BeforeClass
	public static void initializeInformation() {
		CredentialInformation.setCoreLocation(new File(System
				.getProperty("user.dir")).toURI()
				.resolve("irma_configuration/"));
		java.security.Security.addProvider(new com.sun.crypto.provider.SunJCE());
	}
	
	SecretKey getKey () {
		byte[] key = new byte[16];//{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
		SecretKey ksMac = new SecretKeySpec(key, "DESEDE");
		return ksMac;
	}
	
	@Test
	public void testMac() throws InvalidKeyException, NoSuchAlgorithmException {
		Mac mac = Mac.getInstance("DESEDEMAC64WITHISO7816-4PADDING");
		SecretKey ksMac = getKey();
		mac.init(ksMac);
		byte[] in = new byte[]{ 0x02 };
		byte[] out = mac.doFinal(in);
		System.out.println(Hex.toHexString(out));
	}
	
	@Test
	public void testEnc() throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
		SecretKey ksEnc = getKey();
		byte[] in = new byte[]{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
		cipher.init(Cipher.ENCRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
		byte[] out2 = cipher.doFinal(in);
		System.out.println(Hex.toHexString(out2));
	}
	
	@Test
	public void verifyRootWithWrapping() throws CardException,
			CredentialsException, GeneralSecurityException, CardServiceException {
		System.out.println("Running wrapping test");
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
	"Surfnet", "root", "Surfnet", "rootAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		TerminalCardService terminal = TestSetup.getCardService();
		CardHolderVerificationService pinpad = new CardHolderVerificationService(terminal);
		SecureMessagingWrapper sm = new SecureMessagingWrapper(getKey() , getKey() );
		WrappingCardService wrapper = new WrappingCardService(pinpad, sm);
		
		IdemixCredentials ic = new IdemixCredentials(wrapper);
		wrapper.open();

		// Select Applet
		List<ProtocolCommand> select_applet = new ArrayList<ProtocolCommand>();
		select_applet.add(IdemixSmartcard.selectAppletCommand);
		executeCommands(select_applet, wrapper);

		// Enable Secure Messaging
		wrapper.enable();
		
		// FIXME: We are using async here as well, since we need control over
		// the open command. This should actually be fixed in the API.
		Nonce nonce = ic.generateNonce(vspec);
		List<ProtocolCommand> commands = ic.requestProofCommands(vspec, nonce);
		ProtocolResponses responses = executeCommands(commands, wrapper);
		Attributes attr = ic.verifyProofResponses(vspec, nonce, responses);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}
	
	@Test
	public void verifyRootAsyncWrapping() throws CardException,
			CredentialsException, GeneralSecurityException, CardServiceException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
	"Surfnet", "root", "Surfnet", "rootAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		TerminalCardService terminal = TestSetup.getCardService();
		CardHolderVerificationService pinpad = new CardHolderVerificationService(terminal);
		SecureMessagingWrapper sm = new SecureMessagingWrapper(getKey() , getKey() );
		
		IdemixCredentials ic = new IdemixCredentials(pinpad);
		pinpad.open();

		// Select Applet
		List<ProtocolCommand> select_applet = new ArrayList<ProtocolCommand>();
		select_applet.add(IdemixSmartcard.selectAppletCommand);
		executeCommands(select_applet, pinpad);
	
		System.out.println("Applet selected");

		Nonce nonce = ic.generateNonce(vspec);
		List<ProtocolCommand> commands = ic.requestProofCommands(vspec, nonce);
		
		// Store send sequence counter
		long ssc = sm.getSendSequenceCounter();
		
		//Wrap the commands
		sm.wrapAsync(commands);
		
		List<ProtocolResponse> responsesList = executeCommandsList(commands, pinpad);
		
		// Unwrap the commands, here we need the send sequence counter
		sm.unWrapAsync(responsesList, ssc + 1);
		
		// Convert responses back for now
		ProtocolResponses responses = new ProtocolResponses();
		for(ProtocolResponse r : responsesList) {
			responses.put(r.getKey(), r.getResponse());
		}
		
		Attributes attr = ic.verifyProofResponses(vspec, nonce, responses);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}
	
	private ProtocolResponses executeCommands(List<ProtocolCommand> commands, CardService service)
			throws CardServiceException, CardException {

		ProtocolResponses responses = new ProtocolResponses();
		for (ProtocolCommand c : commands) {
			IResponseAPDU response = executeCommand(c, service);
			responses.put(c.key, response);
		}

		return responses;
	}
	
	private List<ProtocolResponse> executeCommandsList(
			List<ProtocolCommand> commands, CardService service)
			throws CardServiceException {
		List<ProtocolResponse> responses = new LinkedList<ProtocolResponse>();
		for (ProtocolCommand c : commands) {
			IResponseAPDU response = executeCommand(c, service);
			responses.add(new ProtocolResponse(c.key, response));
		}

		return responses;
	}
	
	private IResponseAPDU executeCommand(ProtocolCommand c, CardService service)
			throws CardServiceException {
		IResponseAPDU response = IdemixService.transmit(service, c.command);
		if (response.getSW() != 0x00009000) {
			// don't bother with the rest of the commands...
			// TODO: get error message from global table
			String errorMessage = c.errorMap != null
					&& c.errorMap.containsKey(response.getSW()) ? c.errorMap
					.get(response.getSW()) : "";
			throw new CardServiceException(String.format(
					"Command failed: \"%s\", SW: %04x (%s)", c.description,
					response.getSW(), errorMessage));
		}
		return response;
	}
}
