package credentials;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.sourceforge.scuba.util.Hex;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.key.IssuerKeyPair;

import service.IdemixService;

import credentials.util.SecureMessagingWrapper;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.DummyAcceptingCardService;
import net.sourceforge.scuba.smartcards.WrappingCardService;

public class Test {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final IvParameterSpec ZERO_IV_PARAM_SPEC = 
			new IvParameterSpec(new byte[8]);
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			Mac mac = Mac.getInstance("DESEDEMAC64WITHISO7816-4PADDING");
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			byte[] key = new byte[16];//{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
			SecretKey ksMac = new SecretKeySpec(key, "DESEDE");
			mac.init(ksMac);
			byte[] in = new byte[]{ 0x02 };
			byte[] out = mac.doFinal(in);
			System.out.println(Hex.toHexString(out));
			byte[] in2 = new byte[]{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
			cipher.init(Cipher.ENCRYPT_MODE, ksMac, ZERO_IV_PARAM_SPEC);
			byte[] out2 = cipher.doFinal(in2);
			System.out.println(Hex.toHexString(out2));
			
			String credStruct = "CredStructCard4";
			URI BASE_LOCATION = new File(System.getProperty("user.dir")).toURI().resolve("files/parameter/");
			System.out.println("got base");
	        URI CRED_LOCATION = BASE_LOCATION.resolve("../issuerData/" + credStruct + ".xml");
	        System.out.println("got cred");
	        URI ISSUER_LOCATION = BASE_LOCATION.resolve("../issuerData/ipk.xml");
	        System.out.println("got issuer");
	        URI credStructId = new URI("http://www.ngo.org/" + credStruct + ".xml");
	        System.out.println("got struct");
	        // loading credential structure linked to a URI
	        Locations.init(credStructId, CRED_LOCATION);
	        System.out.println("got init");
	        // create the issuance specification
	        IssuanceSpec issuanceSpec = new IssuanceSpec(ISSUER_LOCATION, credStructId);
	        System.out.println("got spec");
	        URI iskLocation = BASE_LOCATION.resolve("../private/isk.xml");
	        URI ipkLocation = ISSUER_LOCATION.resolve("ipk.xml");
	        URI BASE_ID = new URI("http://www.zurich.ibm.com/security/idmx/v2/");
	        URI ISSUER_ID = new URI("http://www.issuer.com/");
	        IssuerKeyPair issuerKey = Locations.initIssuer(BASE_LOCATION, BASE_ID.toString(),
	                iskLocation, ipkLocation, ISSUER_ID.resolve("ipk.xml"));

			Values values = new Values(issuerKey.getPublicKey().getGroupParams().getSystemParams());
	        System.out.println("got val");
	        values.add("attr1", BigInteger.valueOf(1313));
	        values.add("attr2", BigInteger.valueOf(1314));
	        values.add("attr3", BigInteger.valueOf(1315));
	        values.add("attr4", BigInteger.valueOf(1316));
			System.out.println("test");
			CardService dummy = new DummyAcceptingCardService(System.out);
			SecureMessagingWrapper sm = new SecureMessagingWrapper(ksMac, ksMac);
			WrappingCardService wrapper = new WrappingCardService(dummy, sm);
			IdemixService service = new IdemixService(wrapper);			
            service.open();
            wrapper.enable();
            service.setIssuanceSpecification(issuanceSpec);
            service.setAttributes(issuanceSpec, values);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (CardServiceException e) {
			e.printStackTrace();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
	}

}
