import java.util.ArrayList;
import java.util.List;
import org.umu.https.contextmanager.client.HTTPContextManagerClient;
import org.umu.https.contextmanager.messages.ContextManagerMessage;
import org.umu.https.contextmanager.messages.QueryContextMessage;
import org.umu.https.contextmanager.messages.QueryContextResponse;
import org.umu.https.contextmanager.messages.UpdateContextMessage;
import org.umu.https.groupmanager.client.GroupManagerClient;
import org.umu.https.groupmanager.client.GroupManagerClientUtils;
import org.umu.https.groupmanager.client.Settings;
import org.umu.https.groupmanager.cpabe.CPABEObject;
import org.umu.https.groupmanager.cpabe.CPABEOperator;
import org.umu.https.groupmanager.cpabe.CPABEPolicy;

import es.um.security.idm.tokens.Token;
import es.um.security.idm.user.IdMUser;
import es.um.security.idm.user.IdMUserException;
import es.um.security.idm.user.implementation.KeyRockIdMUserClient;
import es.um.security.utilities.Protocols;


public class HTTPSGroupManagerClientTestSimple {
	private static final String CPABEKEY_FILE = "sharing_material_folder\\cpabe_key.txt";
	private static final String PUBLICPARAMETERS_FILE = "sharing_material_folder\\public_parameters.txt";
	private static final String AA_IP = "https://platform.sociotal.eu:8443/AttributeAuthorityServlet/AttributeAuthority";
	private static final String CERTS_FOLDER = "certs_sociotal/";
	private static final String [] TRUSTEDCERTS = {"PrivateRootCA.cer", "ca.cer", "UniversidaddeCantabria.cer", "UC.crt"};

	private static final String KEYROCK_IP = "platform.sociotal.eu";
	private static final String KEYROCK_PORT = "8443";
	private static final String CONTEXTMANAGER_IP = "http://platform.sociotal.eu:3500";
	private static final String QUERYCONTEXT_URI = "/SocIoTal_CM_REST_V3/NGSI10_API/queryContext";
	private static final String UPDATECONTEXT_URI = "/SocIoTal_CM_REST_V3/NGSI10_API/updateContext";


	public static void main(String[] args) {
		String client_id = "joseluis";
		String client_password = "joseluispass";
		Token auth_token = null;
		try {
			IdMUser identityManagerUSer = new KeyRockIdMUserClient(Protocols.HTTPS, null, KEYROCK_IP, KEYROCK_PORT);
			auth_token = identityManagerUSer.authenticateById(client_id, client_password);
			System.out.println("**********************************");
		} catch (IdMUserException e1) {
			e1.printStackTrace();
		}
		String token_id = auth_token.getToken_id();

		Settings settings = new Settings(CERTS_FOLDER, TRUSTEDCERTS, CPABEKEY_FILE, PUBLICPARAMETERS_FILE);
		GroupManagerClient gm = new GroupManagerClient(settings, client_id, token_id);

		/* REQUESTING A CP-ABE KEY TO THE AA*/
		CPABEObject cpabeObject = gm.requestCPABEKey(AA_IP);
		System.out.println("************************: " + cpabeObject.getCpabeKey());
		System.out.println("************************: " + cpabeObject.getPublicParameters());
		System.out.println("************************: " + cpabeObject.getAttributesKey());

		GroupManagerClientUtils.storeCPABEKey(cpabeObject.getCpabeKey(), CPABEKEY_FILE);
		GroupManagerClientUtils.storePublicParameters(cpabeObject.getPublicParameters(), PUBLICPARAMETERS_FILE);
		GroupManagerClientUtils.storeMyAttributes(cpabeObject.getAttributesKey(), "myAttributes.txt");

		/************************/
		/****Encrypting data****/
		/************************/
		List<String> attributes = new ArrayList<>();
		attributes.add("department=diic");
		attributes.add("organization=umu");

		CPABEPolicy cpabepolicy = new CPABEPolicy(attributes, CPABEOperator.AND);

		String message = "This is a test";
		String encryptedData = null;
		try {
			encryptedData = gm.encryptData(PUBLICPARAMETERS_FILE, cpabepolicy, message);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("ENCRYPTED DATA:" + encryptedData);
		/************************/
		/****Decrypting data****/
		/************************/

		String decryptedData = gm.decryptData(PUBLICPARAMETERS_FILE, CPABEKEY_FILE, encryptedData);
		System.out.println("Decrypted data: " + decryptedData);

		HTTPContextManagerClient cmc = new HTTPContextManagerClient();
		boolean isPattern = false;
		ContextManagerMessage queryContextMessage = QueryContextMessage.buildQueryContextMessage("entityID", "entityType", "attribute", isPattern);
		String s = cmc.getAccess(CONTEXTMANAGER_IP + QUERYCONTEXT_URI, queryContextMessage, "communityToken");
		
		QueryContextResponse qcr = new QueryContextResponse(s);

		ContextManagerMessage updateContextmessage = UpdateContextMessage.buildUpdateContextMessage("entityID", "entitytype", "attributename", "attributetype", "attributevalue", "UPDATE");

		String answer = cmc.getAccess(CONTEXTMANAGER_IP + UPDATECONTEXT_URI, updateContextmessage, "communityToken");
	}
}