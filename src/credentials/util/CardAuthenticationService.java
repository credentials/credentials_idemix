package credentials.util;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ICommandAPDU;
import net.sourceforge.scuba.smartcards.IResponseAPDU;

public class CardAuthenticationService extends CardService {

	private static final long serialVersionUID = -7992986822145276116L;

	private static final byte CLA_ISO7816 = 0x00;
	private static final byte INS_ISO7816_INTERNAL_AUTHENTICATE = (byte) 0x88;
	private CardService service;

	public CardAuthenticationService(CardService service) {
		this.service = service;
	}

	public void open() throws CardServiceException {
		service.open();
	}

	public boolean isOpen() {
		return service.isOpen();
	}

	public IResponseAPDU transmit(ICommandAPDU capdu)
	throws CardServiceException {
		return service.transmit(capdu);
	}

	public void close() {
		service.close();
	}

    public SecureMessagingWrapper authenticateCard(BigInteger modulus, BigInteger exponent) 
    throws CardServiceException {
    	SecretKey encKey, macKey; long ssc = 0;
    	BigInteger terminalSeedInt = new BigInteger(modulus.bitLength(), new Random());
    	terminalSeedInt.mod(modulus);
    	byte[] terminalSeedBytes = terminalSeedInt.toByteArray();
    	byte[] terminalSeed = new byte[128];
    	System.arraycopy(terminalSeedBytes, 0, terminalSeed, terminalSeed.length - terminalSeedBytes.length, terminalSeedBytes.length);
    	ICommandAPDU command = new CommandAPDU(CLA_ISO7816, INS_ISO7816_INTERNAL_AUTHENTICATE, 0x00, 0x00, terminalSeed);
    	IResponseAPDU response = service.transmit(command);
    	if (response.getSW() != 0x9000) {
    		throw new CardServiceException("Card authentication failed.");
    	}
    	byte[] cardSeed = response.getData();
    	
    	try{
			MessageDigest shaDigest = MessageDigest.getInstance("SHA1");
			SecretKeyFactory desKeyFactory = SecretKeyFactory.getInstance("DESede");
			byte[] sscBytes = new byte[8], hash = new byte[20], key = new byte[24];
		
			shaDigest.update(cardSeed);
			shaDigest.update(terminalSeed);			
			shaDigest.update(new byte[]{ 0x00, 0x00, 0x00, 0x01 }); // ENC_MODE
			hash = shaDigest.digest();
			System.arraycopy(hash, 0, key, 0, 8);
			System.arraycopy(hash, 8, key, 8, 8);
			System.arraycopy(hash, 0, key, 16, 8);
			encKey = desKeyFactory.generateSecret(new DESedeKeySpec(key));			
			System.arraycopy(hash, 16, sscBytes, 0, 4);
		
			shaDigest.update(cardSeed);
			shaDigest.update(terminalSeed);			
			shaDigest.update(new byte[]{ 0x00, 0x00, 0x00, 0x02 }); // ENC_MODE
			hash = shaDigest.digest();
			System.arraycopy(hash, 0, key, 0, 8);
			System.arraycopy(hash, 8, key, 8, 8);
			System.arraycopy(hash, 0, key, 16, 8);
			macKey = desKeyFactory.generateSecret(new DESedeKeySpec(key));			
			System.arraycopy(hash, 16, sscBytes, 4, 4);
			
			for (int i = 0; i < sscBytes.length; i++) {
				ssc = (ssc << 8) | (sscBytes[i] & 0x000000ff);
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new CardServiceException("Key derivation failed: " + e.getMessage());
		}
    	
    	try {
			return new SecureMessagingWrapper(encKey, macKey, ssc);
		} catch (Exception e) {
			e.printStackTrace();
    		throw new CardServiceException("Secure messaging setup failed: " + e.getMessage());
		}
    }
}
