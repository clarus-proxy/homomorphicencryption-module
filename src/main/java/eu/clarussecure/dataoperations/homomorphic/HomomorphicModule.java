package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.encryption.paillier.EncryptedInteger;
import eu.clarussecure.encryption.paillier.KeyPair;
import eu.clarussecure.encryption.paillier.Paillier;
import eu.clarussecure.encryption.paillier.PublicKey;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class HomomorphicModule implements DataOperation{
    
    // This string is a flag to identify attributes that are not covered in the security policy
    // It is used actively by the HEAD function.
    protected static final String TO_BE_FILTERED_FLAG = "NOT_COVERED";
    
    // Data extracted from the security policy
    protected Map<String, String> attributeTypes = new HashMap<>(); // qualifName->type
    protected Map<String, String> typesProtection = new HashMap<>(); // type->protectionModule
    protected Map<String, String> typesDataIDs = new HashMap<>(); // type->idKey
    protected KeyStore keyStore = KeyStore.getInstance();

    // Map of the fully-qualified Attribute Names
    protected List<String> qualifiedAttributes = new ArrayList<>();

    // Mapping to determine where to store each qualified name
    protected int cloudsNumber;
    protected Map<String, Integer> attributeClouds = new HashMap<>();
    
    public HomomorphicModule(Document policy){
        // TODO - Extract the number of "endpoints" (aka Clouds) from the policy.
        // At this point this number WILL BE HARD CODED!!!
        this.cloudsNumber = 1;

        // First, get the types of each attribute and build the map
        NodeList nodes = policy.getElementsByTagName("attribute");
        for (int i = 0; i < nodes.getLength(); i++) {
            // Get the node and the list of its attributes
            Node node = nodes.item(i);
            NamedNodeMap attributes = node.getAttributes();
            // Extract the required attributes
            String attributeName = attributes.getNamedItem("name").getNodeValue();
            String attributeType = attributes.getNamedItem("attribute_type").getNodeValue();
            // Add the information to the map
            this.attributeTypes.put(attributeName, attributeType);
        }

        /*
        // Fully qualify the attribute Names
        this.qualifiedAttributes = AttributeNamesUtilities.fullyQualified(attributeNames);

        // Replace the keys of the attributeTypes Map
        this.attributeTypes = this.attributeTypes.keySet().stream() // Iterate over the keys of the original map 
                .collect(Collectors.toMap( // Collect them in a new map 
                        // The new key is the single one that in qualifiedAttributes such that the original key is suffix of the qualified one
                        // (i.e. filter the qAttrs such that the qAttr ends with the original name)
                        key -> this.qualifiedAttributes.stream().filter(k -> k.endsWith(key)).findAny().orElse(null),
                        // The new value is the same of the original mapping
                        key -> this.attributeTypes.get(key)));
        */

        // Second , get the protection of each attribute type and their idKeys
        nodes = policy.getElementsByTagName("attribute_type");
        for (int i = 0; i < nodes.getLength(); i++) {
            // Get the node and the list of its attributes
            Node node = nodes.item(i);
            NamedNodeMap attributes = node.getAttributes();
            // Extract the reuqired attributes
            String attributeType = attributes.getNamedItem("type").getNodeValue();
            String typeProtection = attributes.getNamedItem("protection").getNodeValue();
            // Add the information to the map
            this.typesProtection.put(attributeType, typeProtection);
            // Get the idKey only if the protection module is "homomorphic"
            if (typeProtection.equals("homomorphic")) {
                String dataID = attributes.getNamedItem("id_key").getNodeValue();
                this.typesDataIDs.put(attributeType, dataID);
            }
        }
        // FIXME - Should the policy specify in which cloud to store the encrypted data?
        // If so, this information should be available in the "attribute_type" tag
        // so the "mapping" showing where to store each attribute should be built here.
        /* Example:
         * <endpoint id=1 protocol="prot" port="12345">
         *   <parameters>
         *      <parameter param="name1" value="val1" />
         *   </parameters>
         * </endpoint>
         * <endpoint id=2 protocol="prot1" port="98765">
         *   <parameters>
         *      <parameter param="name3" value="val12" />
         *   </parameters>
         * </endpoint>
         * ...
         * <attribute_type
         *   type="confidential"
         *   protection="encryption"
         *   id_key="176"
         *   cloud="1">
         */
        // At the moment, the mapping will be done assuming the encrypted attributes go to the first cloud
        //this.qualifiedAttributes.forEach(qualifiedName -> this.attributeClouds.put(qualifiedName, 0));
    }
    
    @Override
    protected void finalize() throws Throwable{
        super.finalize();
        this.keyStore.deleteInstance();
    }

    @Override
    public List<DataOperationCommand> get(String[] attributeNames, Criteria[] criteria) {
        // IMPORTANT REMARK:
        // Since the encryption is not homomorphic, all the data must be retrieved
        // The selection of the rows will be done in the outboud GET, after decrypting the data
        
        Map<String,String> attributesMapping = this.buildAttributesMapping(attributeNames, notCoveredAttribute -> notCoveredAttribute, unprotectedAttrib -> unprotectedAttrib);

        Base64.Encoder encoder = Base64.getEncoder();

        // First, generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(attributesMapping.get(attributeName)));
        
        // Second, determine is there is an HomomrphicCriteria
        // This procedure will consider THE LAST HomomorphicCriteria found
        HomomorphicCriteria homoCrit = null;
        List<Criteria> listCriteria = new ArrayList<>();
        
        if(criteria != null){
            // Find the HomomorphicCriteria
            for(Criteria crit : criteria){
                if(crit instanceof HomomorphicCriteria){
                    // TODO 
                    homoCrit = (HomomorphicCriteria) crit;
                    continue;
                }
                listCriteria.add(crit);
            }
            listCriteria.forEach(criterion -> {
                // Determine if the column is encrypted of not
                String protectedAttribute = attributesMapping.get(criterion.getAttributeName());
                if (!criterion.getAttributeName().equals(protectedAttribute)) {
                    // The protected and unprotected Attribute Names do not match
                    // This implies the criteria operates over an encrypted column
                    // First, modify the operator to use a String comparator
                    criterion.setOperator("s=");
                    // Second, encrypt the treshold
                    String protectedThreshold = "";
                    try {
                        // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                        String matchedProtection = null;
                        for(String protectionRule : this.attributeTypes.keySet()){
                            Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                            if(p.matcher(criterion.getAttributeName()).matches()){
                                matchedProtection = protectionRule;
                            }
                        }

                        // If none matches, ignore this attribute => it is not convered by the Policy
                        if(matchedProtection == null)
                            return;
                        
                        // FIXME - This is not the Attribute Name of the criteria but the token it matches
                        // Obtain the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                        // Get the prpteciton type of this attribute
                        String protection = this.typesProtection
                                .get(this.attributeTypes.get(matchedProtection));
                        // Encrypt only if the protection type is "encryption" or "simple"
                        if (protection.equals("homomorphic")) {
                            // Get the KeyPair
                            KeyPair key = this.keyStore.retrieveKey(dataID);

                            // Create the BigInteger object
                            // In this part we will assume the homomorphic attributes ARE integers
                            // This can be assumed since homomophic operations are guaranteed only on Integer
                            // Parse the value.
                            long contentValue = (long) Double.parseDouble(criterion.getValue());
                            BigInteger bigIntValue = BigInteger.valueOf(contentValue);

                            // Encrypt the value and obtain the bytes representation
                            EncryptedInteger encrypted = Paillier.encrypt(key.getPublic(), bigIntValue);
                            BigInteger encValue = encrypted.getValue();

                            // Encode the bytes using Base64
                            protectedThreshold = encoder.encodeToString(encValue.toByteArray());
                        } else {
                            // Otherwise, just let the valut to compare pass in plain text
                            protectedThreshold = criterion.getValue();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.exit(1);
                    }
                    criterion.setValue(protectedThreshold);
                    // Third, substitute the involved attribute name with its protected one
                    criterion.setAttributeName(attributesMapping.get(criterion.getAttributeName()));
                }
            });
        }
        
        
        // Third, create the Command object
        DataOperationCommand command = null;
        if(homoCrit == null){
            command = new HomomorphicCommand(attributeNames,
                    protectedAttributes.toArray(new String[attributeNames.length]), null, attributesMapping, criteria);
        } else {
            try{
                String dataID;
                // Determine the Public Key of the attribute in the homomorphic operation
                // FIXME - This is not the attribute name but the TOKEN it matches
                dataID = this.typesDataIDs.get(this.attributeTypes.get(homoCrit.getAttributeName()));
                KeyStore ks = KeyStore.getInstance();
                PublicKey pk = ks.retrieveKey(dataID).getPublic();
                ks.deleteInstance();
                // An encrypted zero migh be useful to start computing the sum
                EncryptedInteger encryptedZero = Paillier.encrypt(pk, BigInteger.ZERO);
                // Find the protected name of the involved column
                // FIXME - This is not the attribute name but the TOKEN it matches.
                String protAttribHomoName = attributesMapping.get(homoCrit.getAttributeName());
                // Create the HomomorphicReoteOperationCommand object
                command = new HomomorphicRemoteOperationCommand(attributeNames, protectedAttributes.toArray(new String[attributeNames.length]), null,
                        attributesMapping, listCriteria.toArray(new Criteria[listCriteria.size()]), homoCrit.getOperator(), protAttribHomoName, pk, encryptedZero);
            } catch (IOException e){
                e.printStackTrace();
                System.exit(1);
            }
        }
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
    }

    @Override
    public List<DataOperationResult> get(List<DataOperationCommand> promise, List<String[][]> contents) {
        // Iterate over all the given commands
        List<DataOperationResult> commands = new ArrayList<>();
        int rowCount = 0;
        for (int n = 0; n < promise.size(); n++) {
            DataOperationCommand com = promise.get(n);
            String[][] content = contents.get(n);

            String[] plainAttributeNames = new String[com.getProtectedAttributeNames().length];
            List<String[]> plainContents = new ArrayList<>();
            Map<String, String> mapAttributes = new HashMap<>();

            Base64.Decoder decoder = Base64.getDecoder();

            // Second, decipher the attribute names
            try {
                // First, decipher the attribute Names and map them to the origial ones
                for (int i = 0; i < com.getProtectedAttributeNames().length; i++) {
                    // Get the proteciton type of this attribute
                    String protection = this.typesProtection.get(this.attributeTypes.get(com.getAttributeNames()[i]));

                    // Decrypt only if the protection type is "homomorphic"
                    if (protection.equals("homomorphic")) {
                        // "Decrypting" the attribute names is as simple as removing the "_homoenc" suffix
                        int suffIndex = com.getProtectedAttributeNames()[i].indexOf("_homoenc");
                        
                        plainAttributeNames[i] = com.getProtectedAttributeNames()[i].substring(0, suffIndex);
                    } else {
                        plainAttributeNames[i] = com.getProtectedAttributeNames()[i];
                    }
                    mapAttributes.put(com.getProtectedAttributeNames()[i], plainAttributeNames[i]);
                }

                // Second, decipher the contents
                for (int i = 0; i < content.length; i++) {
                    String[] row = new String[plainAttributeNames.length]; // Reconstructed row
                    for (int j = 0; j < plainAttributeNames.length; j++) {
                        // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                        String matchedProtection = null;
                        for(String protectionRule : this.attributeTypes.keySet()){
                            Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                            if(p.matcher(plainAttributeNames[j]).matches()){
                                matchedProtection = protectionRule;
                            }
                        }

                        // If none matches, ignore this attribute => it is not convered by the Policy
                        if(matchedProtection == null)
                            continue;
                        
                        // We assume the attribute names are in the same order of the content
                        String plainValue;
                        // Get the proteciton type of this attribute
                        String protection = this.typesProtection.get(this.attributeTypes.get(matchedProtection));

                        // Decrypt only if the protection type is "homomorphic"
                        if (protection.equals("homomorphic")) {
                            // Get the dataID
                            String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                            // Get the KeyPair
                            KeyPair key = this.keyStore.retrieveKey(dataID);

                            // Create the BigInteger and EncryptedInteger objects containing the data
                            // Since this is a protected attribute, it is B64-encoded
                            BigInteger encContent = new BigInteger(decoder.decode(content[i][j]));
                            EncryptedInteger data = new EncryptedInteger(encContent, key.getPublic());

                            // Decrypt the value and obtain the bytes representation
                            BigInteger decrypted = Paillier.decrypt(key.getSecret(), data);
                            
                            // Recover the decrypted data. It is assumed the value fits in a long
                            plainValue = decrypted.longValue() + "";
                        } else {
                            // Simply copy the content
                            plainValue = content[i][j];
                        }
                        row[j] = plainValue;
                    }
                    plainContents.add(row);
                    rowCount++;
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }

            // Encapsulate the output
            DataOperationResult command = new HomomorphicResult(plainAttributeNames,
                    plainContents.toArray(new String[rowCount][plainAttributeNames.length]));
            commands.add(command);
        }
        return commands;
    }

    @Override
    public List<DataOperationCommand> post(String[] attributeNames, String[][] contents) {
        String[][] encContents = new String[contents.length][attributeNames.length];

        Base64.Encoder encoder = Base64.getEncoder();
        
        // Create the mapping between the given Attribute Names and the protected ones.
        // This method uses the "buildAttributesMapping" function, letting the not covered and unprotected attributes pass
        // (i.e. not marking them since this mapping WILL NOT be filtered later)
        Map<String, String> attributesMapping = this.buildAttributesMapping(attributeNames, notCoveredAttrib -> notCoveredAttrib, unprotectedAttrib -> unprotectedAttrib);

        try {
            // Second, obfuscate the contents
            for (int i = 0; i < contents.length; i++) {
                for (int j = 0; j < attributeNames.length; j++) {
                    // Get the prpteciton type of this attribute
                    // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                    String matchedProtection = null;
                    for(String protectionRule : this.attributeTypes.keySet()){
                        Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                        if(p.matcher(attributeNames[j]).matches()){
                            matchedProtection = protectionRule;
                        }
                    }

                    // If none matches, ignore this attribute => it is not convered by the Policy
                    if(matchedProtection == null)
                        continue;
                    
                    String protection = typesProtection.get(this.attributeTypes.get(matchedProtection));
                    // Encrypt only if the protection type is "homomorphic"
                    if (protection.equals("homomorphic")) {
                        // Get the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                        // Get the KeyPair
                        KeyPair key = this.keyStore.retrieveKey(dataID);
                        
                        // Create the BigInteger object
                        // In this part we will assume the homomorphic attributes ARE integers
                        // This can be assumed since homomophic operations are guaranteed only on Interger
                        // Parse the value.
                        long contentValue = (long) Double.parseDouble(contents[i][j]);
                        BigInteger bigIntValue = BigInteger.valueOf(contentValue);
                        
                        // Encrypt the value and obtain the bytes representation
                        EncryptedInteger encrypted = Paillier.encrypt(key.getPublic(), bigIntValue);
                        BigInteger encValue = encrypted.getValue();
                        
                        // Encode the bytes using Base64
                        encContents[i][j] = encoder.encodeToString(encValue.toByteArray());
                    } else {
                        // Simply copy the content
                        encContents[i][j] = contents[i][j];
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        // Generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(attributesMapping.get(attributeName)));

        // Encapsulate the output
        DataOperationCommand command = new HomomorphicCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), encContents, attributesMapping,
                null);
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
    }

    @Override
    public List<DataOperationCommand> put(String[] attributeNames, Criteria[] criteria, String[][] contents) {
        // Put operation is not supported in this module
        return null;
    }

    @Override
    public List<DataOperationCommand> delete(String[] attributeNames, Criteria[] criteria) {
        // Delete operation is not supported in this module
        return null;
    }

    @Override
    public List<Map<String, String>> head(String[] attributeNames) {
        // First, resolve the wildcards according to the policy definitions
        String[] resolvedAttributes = AttributeNamesUtilities.resolveOperationAttributeNames(attributeNames, new ArrayList<>(this.attributeTypes.keySet()));
        // Remove duplicates here, since the resolved attributes will be the keys of the mapping
        // Let's leave the HashSet class do the magic :)
        Set<String> filteredAttributes = new HashSet<>(Arrays.asList(resolvedAttributes));
        // Then build the Attributes Mapping AND filter the ones not concerned
        Map<String, String> attribsMapping = filterMapingEntries(this.buildAttributesMapping(filteredAttributes.toArray(new String[filteredAttributes.size()]),
                attrib -> attrib, // Not covered Attributes will NOT be marked for later filtering
                attrib -> HomomorphicModule.TO_BE_FILTERED_FLAG)); // Not protected Attributes will be marked for later filtering
        List<Map<String, String>> aux = new ArrayList<>();
        for (int i = 0; i < this.cloudsNumber; i++) {
            // Insert the Mapping in the first place
            aux.add(i == 0 ? attribsMapping : new HashMap<>());
        }
        return aux;
    }
    
    private Map<String,String> filterMapingEntries(Map<String,String> mapping){
        // This function will analyze the given mapping (built using buildAttributesMapping)
        // and remove the entries that are not comprised in the seciryt policy.
        // Get the Entries set
        Set<Map.Entry<String,String>> entries = mapping.entrySet();
        Set<Map.Entry<String,String>> newEntries = new HashSet<>();
        // Select which entries will remain in the map.
        entries.stream().forEach(entry -> {
            String value = entry.getValue();
            if(!value.equals(HomomorphicModule.TO_BE_FILTERED_FLAG)){
                // if the value WAS NOT marked as "not covered" the entry SHOULD be kept.
                newEntries.add(entry);
            }
        });
        // Reconstruct the final HashMap
        return newEntries.stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
    
    private Map<String,String> buildAttributesMapping(String[] attributes, Function<String, String> notCoveredTransform, Function<String,String> notProtected){
        // NOTE: The "notCoveredTransform" function will say what to do with the attributes non-covered by the security policy.
        // NOTE: The "notProtected" function will say what to do with the attributes covered by the security policy but not using this module
        // FIXME - Create the mapping between the given attribute names and their protected names
        // This mapping must be done considering the list of attributes to protect specified in the security policy
        // Generate the map between qualified Attributes and protected Attributes Names
        Map<String,String> mapping;
        
        mapping = Arrays.asList(attributes).stream() // Get all the qualified Names
                .collect(Collectors.toMap( // Reduce them into a new Map
                        originalQualifAttribName -> originalQualifAttribName, // Use the same qualified Attribute Name as key
                        originalQualifAttribName -> { // Generate the mapped values: the "encrypted" ones
                            String attribEnc = "";
                            try {
                                // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                                String matchedProtection = null;
                                for(String protectionRule : this.attributeTypes.keySet()){
                                    Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                                    if(p.matcher(originalQualifAttribName).matches()){
                                        matchedProtection = protectionRule;
                                    }
                                }
                                
                                // If none matches, ignore this attribute => it is not convered by the Policy
                                // To filter these entries later, we will use a "special" string.
                                if(matchedProtection == null)
                                    return notCoveredTransform.apply(originalQualifAttribName);
                                
                                // Obtain the dataID
                                String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                                // Encrypt the column name only if the policy says so
                                // Get the prpteciton type of this attribute
                                String protection = this.typesProtection.get(this.attributeTypes.get(matchedProtection));
                                // Encrypt only if the protection type is "encryption" or "simple"
                                if (protection.equals("homomorphic")) {
                                    /*
                                    // The name of the attribute CAN be completely encrypted. Use this code to do so
                                    byte[] bytesAttribEnc;

                                    // Initialize the Secret Key and the Init Vector of the Cipher
                                    IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));
                                    SecretKey sk = this.keyStore.retrieveKey(dataID);

                                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                    cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

                                    // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                                    bytesAttribEnc = cipher.doFinal(originalQualifAttribName.getBytes());
                                    attribEnc = Base64.getEncoder().encodeToString(bytesAttribEnc);
                                    */
                                    attribEnc = originalQualifAttribName + "_homoenc";
                                } else {
                                    // Otherwise, just let the attribute name pass in plain text
                                    // In this case, the attribute was identified but it is not protected.
                                    attribEnc = notProtected.apply(originalQualifAttribName);
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                System.exit(1);
                            }
                            return attribEnc;
                        }));
        return mapping;
    }
}
