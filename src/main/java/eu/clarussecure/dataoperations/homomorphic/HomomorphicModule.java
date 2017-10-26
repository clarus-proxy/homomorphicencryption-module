package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.dataoperations.geometry.GeometryBuilder;
import eu.clarussecure.dataoperations.geometry.ProjectedCRS;
import cat.urv.crises.eigenpaillier.paillier.EncryptedInteger;
import cat.urv.crises.eigenpaillier.paillier.KeyPair;
import cat.urv.crises.eigenpaillier.paillier.Paillier;
import cat.urv.crises.eigenpaillier.paillier.PublicKey;
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
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.postgis.PGbox2d;
import org.postgis.Point;

public class HomomorphicModule implements DataOperation{
    
    // This string is a flag to identify attributes that are not covered in the security policy
    // It is used actively by the HEAD function.
    protected static final String TO_BE_FILTERED_FLAG = "NOT_COVERED";
    
    // Data extracted from the security policy
    protected Map<String, String> attributeTypes = new HashMap<>(); // qualifName->type
    protected Map<String, String> dataTypes = new HashMap<>(); // qualifName->data_type
    protected Map<String, String> typesProtection = new HashMap<>(); // type->protectionModule
    protected Map<String, String> typesDataIDs = new HashMap<>(); // type->idKey
    protected KeyStore keyStore = KeyStore.getInstance();

    // Map of the fully-qualified Attribute Names
    protected List<String> qualifiedAttributes = new ArrayList<>();
    
    // From Encryption ISSUE #3
    protected final static String NULL_PROTECTION_FLAG = "NULL_PROTECTION";

    // Mapping to determine where to store each qualified name
    protected int cloudsNumber;
    // protected Map<String, Integer> attributeClouds = new HashMap<>();
    
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
            String dataType = attributes.getNamedItem("data_type").getNodeValue();
            // Add the information to the map
            this.attributeTypes.put(attributeName, attributeType);
            this.dataTypes.put(attributeName, dataType);
            // From Encryption ISSUE #3
            this.typesProtection.put(attributeType, HomomorphicModule.NULL_PROTECTION_FLAG);
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
                    // criterion.setOperator("s=");
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

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = criterion.getValue();

                                if (criterion.getOperator().equals("area")) {
                                    String[] area = value.split(",");
                                    value = String.format("SRID=%s;BOX(%s %s, %s %s)", area[4].trim(), area[0].trim(),
                                            area[1].trim(), area[2].trim(), area[3].trim());
                                }

                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    if (geom instanceof Point) {
                                        // NOTE - To correctly encrypt, just cipher coordinates
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        // Homomorphically encrypt a real value is not mathematically possible.
                                        /*
                                         * point.x = encryptDouble(cipher, point.x, maxX);
                                         * point.y = encryptDouble(cipher, point.y, maxY);
                                         */
                                    } else if (geom instanceof PGbox2d) {
                                        PGbox2d box = (PGbox2d) geom;
                                        int srid = box.getLLB().getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            box.getLLB().x = crs.getAxis("x").getMin();
                                            box.getLLB().y = crs.getAxis("y").getMin();
                                            box.getURT().x = crs.getAxis("x").getMax();
                                            box.getURT().y = crs.getAxis("y").getMax();
                                        } else {
                                            box.getLLB().x = -Double.MAX_VALUE;
                                            box.getLLB().y = -Double.MAX_VALUE;
                                            box.getURT().x = Double.MAX_VALUE;
                                            box.getURT().y = Double.MAX_VALUE;
                                        }
                                        if (criterion.getOperator().equals("area")) {
                                            value = box.getLLB().x + ", " + box.getLLB().y + ", " + box.getURT().x + ", " + box.getURT().y + ", " + srid;
                                        }
                                    }
                                    if (!criterion.getOperator().equals("area")) {
                                        value = builder.encode(geom);
                                    }
                                }
                                protectedThreshold = value;
                            } else {
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
                            }
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
        for (int n = 0; n < promise.size(); n++) {
            DataOperationCommand com = promise.get(n);
            String[][] content = contents.get(n);

            String[] plainAttributeNames = new String[com.getProtectedAttributeNames().length];
            List<String[]> plainContents = new ArrayList<>();
            Map<String, String> mapAttributes = new HashMap<>();

            Base64.Decoder decoder = Base64.getDecoder();

            // Second, decipher the attribute names
            // First, decipher the attribute Names and map them to the origial ones
            for (int i = 0; i < com.getProtectedAttributeNames().length; i++) {

                if (com.getProtectedAttributeNames()[i].endsWith("_homoenc")) {
                    // "Decrypting" the attribute names is as simple as removing the "_homoenc" suffix
                    int suffIndex = com.getProtectedAttributeNames()[i].indexOf("_homoenc");

                    plainAttributeNames[i] = com.getProtectedAttributeNames()[i].substring(0, suffIndex);
                } else {
                    plainAttributeNames[i] = com.getProtectedAttributeNames()[i];
                }
                mapAttributes.put(com.getProtectedAttributeNames()[i], plainAttributeNames[i]);
            }

            // Second, decipher the contents
            IntStream.range(0, content.length).parallel().forEach(i ->{
            //for (int i = 0; i < content.length; i++) {
                String[] row = new String[plainAttributeNames.length]; // Reconstructed row
                IntStream.range(0, plainAttributeNames.length).parallel().forEach(j -> {
                //for (int j = 0; j < plainAttributeNames.length; j++) {
                    try{
                        // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                        String matchedProtection = null;
                        for (String protectionRule : this.attributeTypes.keySet()) {
                            Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                            if (p.matcher(plainAttributeNames[j]).matches()) {
                                matchedProtection = protectionRule;
                            }
                        }

                        // If none matches, ignore this attribute => it is not convered by the Policy
                        if(matchedProtection == null)
                            return;

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

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = content[i][j];
                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    if (geom instanceof Point) {
                                        // NOTE - To correctly encrypt, just cipher coordinates
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid == 0) {
                                            srid = Arrays.stream(com.getCriteria())
                                                    .filter(c -> c.getOperator().equals("area")).findFirst()
                                                    .map(Criteria::getValue).map(v -> v.split(",")).map(tk -> tk[4])
                                                    .map(String::trim).map(Integer::parseInt).orElse(0);
                                        }
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        // Homomorphically encrypt a real value is not mathematically possible.
                                        /*
                                         * point.x = encryptDouble(cipher, point.x, maxX);
                                         * point.y = encryptDouble(cipher, point.y, maxY);
                                         */
                                    } else if (geom instanceof PGbox2d) {
                                        PGbox2d box = (PGbox2d) geom;
                                        int srid = box.getLLB().getSrid();
                                        if (srid == 0) {
                                            srid = Arrays.stream(com.getCriteria())
                                                    .filter(c -> c.getOperator().equals("area")).findFirst()
                                                    .map(Criteria::getValue).map(v -> v.split(",")).map(tk -> tk[4])
                                                    .map(String::trim).map(Integer::parseInt).orElse(0);
                                        }
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            box.getLLB().x = crs.getAxis("x").getMin();
                                            box.getLLB().y = crs.getAxis("y").getMin();
                                            box.getURT().x = crs.getAxis("x").getMax();
                                            box.getURT().y = crs.getAxis("y").getMax();
                                        } else {
                                            box.getLLB().x = -Double.MAX_VALUE;
                                            box.getLLB().y = -Double.MAX_VALUE;
                                            box.getURT().x = Double.MAX_VALUE;
                                            box.getURT().y = Double.MAX_VALUE;
                                        }
                                    }
                                    value = builder.encode(geom);
                                }
                                plainValue = value;
                            } else {
                                // Create the BigInteger and EncryptedInteger objects containing the data
                                // Since this is a protected attribute, it is B64-encoded
                                BigInteger encContent = new BigInteger(decoder.decode(content[i][j]));
                                EncryptedInteger data = new EncryptedInteger(encContent, key.getPublic());

                                // Decrypt the value and obtain the bytes representation
                                BigInteger decrypted = Paillier.decrypt(key.getSecret(), data);

                                // Recover the decrypted data. It is assumed the value fits in a long
                                plainValue = decrypted.longValue() + "";
                                if ("clarus_null".equals(plainValue)) {
                                    plainValue = null;
                                }
                            }
                        } else {
                            // Simply copy the content
                            plainValue = content[i][j];
                        }
                    row[j] = plainValue;
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.exit(1);
                    }
                });
                plainContents.add(row);
            });

            // Encapsulate the output
            DataOperationResult command = new HomomorphicResult(plainAttributeNames,
                    plainContents.toArray(new String[plainContents.size()][plainAttributeNames.length]));
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

            // Second, obfuscate the contents
            IntStream.range(0, contents.length).parallel().forEach(i -> {
            //IntStream.range(0, contents.length).forEach(i -> {
                //for (int j = 0; j < attributeNames.length; j++) {
                IntStream.range(0, attributeNames.length).parallel().forEach(j -> {
                //IntStream.range(0, attributeNames.length).forEach(j -> {
                    try{
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
                            return;

                        String protection = typesProtection.get(this.attributeTypes.get(matchedProtection));
                        // Encrypt only if the protection type is "homomorphic"
                        if (protection.equals("homomorphic")) {
                            // Get the dataID
                            String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                            // Get the KeyPair
                            KeyPair key = this.keyStore.retrieveKey(dataID);

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = contents[i][j];
                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    // NOTE - To correctly encrypt, just cipher coordinates
                                    if (geom instanceof Point) {
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        // Homomorphically encrypt a real value is not mathematically possible.
                                        /*
                                         * point.x = encryptDouble(cipher, point.x, maxX);
                                         * point.y = encryptDouble(cipher, point.y, maxY);
                                         */
                                    }
                                    value = builder.encode(geom);
                                }
                                encContents[i][j] = value;
                            } else {
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
                            }
                        } else {
                            // Simply copy the content
                            encContents[i][j] = contents[i][j];
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.exit(1);
                    }
                });
            });

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
        Map<String, String> attributesMapping = this.buildAttributesMapping(attributeNames,
                notCoveredAttribute -> notCoveredAttribute, unprotectedAttrib -> unprotectedAttrib);

        // First, Generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(attributesMapping.get(attributeName)));

        // Second, process the Criteria to transform the requested
        // AttributeNames to the protected ones
        if (criteria != null) {
            Stream.of(criteria).parallel().forEach(criterion -> {
                // Determine if the column is encrypted of not
                String protectedAttribute = attributesMapping.get(criterion.getAttributeName());
                if (!criterion.getAttributeName().equals(protectedAttribute)) {
                    // The protected and unprotected Attribute Names do not
                    // match
                    // This implies the criteria operates over an encrypted
                    // column
                    // Encrypt the treshold
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

                        // Obtain the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                        // Get the prpteciton type of this attribute
                        String protection = this.typesProtection
                                .get(this.attributeTypes.get(matchedProtection));
                        // Encrypt only if the protection type is "encryption"
                        // or "simple"
                        if (protection.equals("homomorphic")) {
                            byte[] bytesAttribEnc;

                            // Get the KeyPair
                            KeyPair key = this.keyStore.retrieveKey(dataID);

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = criterion.getValue();

                                if (criterion.getOperator().equals("area")) {
                                    String[] area = value.split(",");
                                    value = String.format("SRID=%s;BOX(%s %s, %s %s)", area[4].trim(), area[0].trim(),
                                            area[1].trim(), area[2].trim(), area[3].trim());
                                }

                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    if (geom instanceof Point) {
                                        // NOTE - To correctly encrypt, just cipher coordinates
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        // Homomorphically encrypt a real value is not mathematically possible.
                                        /*
                                         * point.x = encryptDouble(cipher, point.x, maxX);
                                         * point.y = encryptDouble(cipher, point.y, maxY);
                                         */
                                    } else if (geom instanceof PGbox2d) {
                                        PGbox2d box = (PGbox2d) geom;
                                        int srid = box.getLLB().getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            box.getLLB().x = crs.getAxis("x").getMin();
                                            box.getLLB().y = crs.getAxis("y").getMin();
                                            box.getURT().x = crs.getAxis("x").getMax();
                                            box.getURT().y = crs.getAxis("y").getMax();
                                        } else {
                                            box.getLLB().x = -Double.MAX_VALUE;
                                            box.getLLB().y = -Double.MAX_VALUE;
                                            box.getURT().x = Double.MAX_VALUE;
                                            box.getURT().y = Double.MAX_VALUE;
                                        }
                                        if (criterion.getOperator().equals("area")) {
                                            value = box.getLLB().x + ", " + box.getLLB().y + ", " + box.getURT().x + ", " + box.getURT().y + ", " + srid;
                                        }
                                    }
                                    if (!criterion.getOperator().equals("area")) {
                                        value = builder.encode(geom);
                                    }
                                }
                                protectedThreshold = value;
                            } else {
                                // Create the BigInteger object
                                // In this part we will assume the homomorphic attributes ARE integers
                                // This can be assumed since homomophic operations are guaranteed only on Interger
                                // Parse the value.
                                String value = criterion.getValue() != null ? criterion.getValue() : "clarus_null";
                                // WARNING!!! - if criterion value == null, the next line will fail with a NumberFormatException!!!
                                // TODO - Fix the criteria with no values.
                                long contentValue = (long) Double.parseDouble(value);
                                BigInteger bigIntValue = BigInteger.valueOf(contentValue);

                                // NOTE - To correctly encrypt, First cipher, THEN
                                // Base64 encode
                                // Encrypt the value and obtain the bytes representation
                                EncryptedInteger encrypted = Paillier.encrypt(key.getPublic(), bigIntValue);
                                BigInteger encValue = encrypted.getValue();

                                protectedThreshold = Base64.getEncoder().encodeToString(encValue.toByteArray());
                            }
                        } else {
                            // Otherwise, just let the value pass in plain text
                            protectedThreshold = criterion.getValue();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.exit(1);
                    }
                    criterion.setValue(protectedThreshold);
                    // Third, substitute the involved attribute name with its
                    // protected one
                    criterion.setAttributeName(attributesMapping.get(criterion.getAttributeName()));
                }
            });
        }

        // Third, create the Comman object
        DataOperationCommand command = new HomomorphicCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), null, attributesMapping, criteria);
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
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
                attrib -> HomomorphicModule.TO_BE_FILTERED_FLAG, // Not covered Attributes will be marked for later filtering
                attrib -> attrib)); // Not protected Attributes will NOT be marked for later filtering
        List<Map<String, String>> aux = new ArrayList<>();
        for (int i = 0; i < this.cloudsNumber; i++) {
            // Insert the Mapping in the first place
            aux.add(i == 0 ? attribsMapping : new HashMap<>());
        }
        return aux;
    }
    
    

    private double encryptDouble(KeyPair key, double value, double maxValue) {
        long rawBits = Double.doubleToRawLongBits(value);       // e.g. clear: 0xa3412345678abcde
        // separate encryption of the exponent and of the significand to
        // preserve validity regarding the range of valid values
        long sign = rawBits & 0x8000000000000000L;              // e.g. clear: 0x8000000000000000
        long exponent = rawBits & 0x7ff0000000000000L;          // e.g. clear: 0x2340000000000000
        long significand = rawBits & 0x000fffffffffffffL;       // e.g. clear: 0x00012345678abcde
        // encrypt significand using the provided cipher
        significand = significand << 4;                         // e.g. clear: 0x0012345678abcde0
        byte[] bytesContent = toByteArray(significand);
        bytesContent = swapByteArray(bytesContent);             // e.g. clear: 0xe0cdab7856341200
        bytesContent[0] = (byte) ((bytesContent[0] & 0xff) >>> 4);      // e.g. clear: 0x0ecdab7856341200
        significand = toLong(bytesContent);
        significand = significand >>> 8;                        // e.g. clear: 0x000ecdab78563412
        bytesContent = toByteArray(significand);
        byte[] bytesContentEnc = new byte[bytesContent.length];
        bytesContentEnc[0] = bytesContent[0];                   // e.g. encrypted: 0x0000000000000000
        bytesContentEnc[1] = bytesContent[1];                   // e.g. encrypted: 0x000e000000000000
        //Original line:
        //cipher.doFinal(bytesContent, 2, bytesContent.length - 2, bytesContentEnc, 2);
        // Prepare the bytes for the encryption
        byte[] toEncrypt = Arrays.copyOfRange(bytesContent, 2, bytesContent.length - 2);
        BigInteger plainInteger = new BigInteger(toEncrypt);
        // Encrypt the bytes
        EncryptedInteger encInteger = Paillier.encrypt(key.getPublic(), plainInteger);
        byte[] encBytes = encInteger.getValue().toByteArray();
        // Copy back the encrypted bytes
        significand = toLong(bytesContentEnc);                  // e.g. encrypted: 0x000e(cdab78563412)
        // encrypt the exponent using XOR cipher
        short expo = (short) (exponent >>> 52);                 // e.g. clear: 0x0234
        long rawBitsMax = Double.doubleToRawLongBits(maxValue); // e.g. clear: 0xc1731940863d70a4
        long exponentMax = rawBitsMax & 0x7ff0000000000000L;    // e.g. clear: 0xc170000000000000
        short expoMax = (short) (exponentMax >>> 52);           // e.g. clear: 0x0c17
        int highestLeadingBit = 32 - Integer.numberOfLeadingZeros(expoMax) - 1; // e.g. 10
        short lowestBitsMask = (short) ((1 << highestLeadingBit) - 1);  // e.g. 0x03ff
        short highestBitsMask = (short) ~lowestBitsMask;        // e.g. 0xfc00
        short xorMask = (short) (expoMax & lowestBitsMask);     // e.g. 0x0017
        expo = (short) ((expo & highestBitsMask)                // e.g. encrypted: 0x02(23)
                | ((expo & lowestBitsMask) ^ xorMask));
        exponent = (long) expo << 52;                           // e.g. encrypted: 0x2(23)0000000000000
        rawBits = sign | exponent | significand;                // e.g. encrypted: 0xa(23)e(cdab78563412)
        value = Double.longBitsToDouble(rawBits);
        return value;
    }

    private double decryptDouble(KeyPair key, double value, double maxValue){
        long rawBits = Double.doubleToRawLongBits(value);       // e.g. encrypted: 0xa(23)e(cdab78563412)
        // separate decryption of the exponent and of the significand to
        // preserve validity regarding the range of valid values
        long sign = rawBits & 0x8000000000000000L;              // e.g. encrypted: 0x8000000000000000
        long exponent = rawBits & 0x7ff0000000000000L;          // e.g. encrypted: 0x2(23)0000000000000
        long significand = rawBits & 0x000fffffffffffffL;       // e.g. encrypted: 0x000e(cdab78563412)
        // decrypt the significand using the provided cipher
        byte[] bytesContent = toByteArray(significand);
        byte[] bytesDecContent = new byte[bytesContent.length];
        bytesDecContent[0] = bytesContent[0];                   // e.g. clear: 0x0000000000000000
        bytesDecContent[1] = bytesContent[1];                   // e.g. clear: 0x000e000000000000
        //cipher.doFinal(bytesContent, 2, bytesContent.length - 2, bytesDecContent, 2);
        significand = toLong(bytesDecContent);                  // e.g. clear: 0x000ecdab78563412
        significand = significand << 8;                         // e.g. clear: 0x0ecdab7856341200
        bytesDecContent = toByteArray(significand);
        bytesDecContent[0] = (byte) (bytesDecContent[0] << 4);  // e.g. clear: 0xe0cdab7856341200
        bytesDecContent = swapByteArray(bytesDecContent);       // e.g. clear: 0x0012345678abcde0
        significand = toLong(bytesDecContent);
        significand = significand >>> 4;                        // e.g. clear: 0x00012345678abcde
        // decrypt the exponent using XOR cipher
        short expo = (short) (exponent >>> 52);                 // e.g. encrypted: 0x02(23)
        long rawBitsMax = Double.doubleToRawLongBits(maxValue); // e.g. clear: 0xc1731940863d70a4
        long exponentMax = rawBitsMax & 0x7ff0000000000000L;    // e.g. clear: 0xc170000000000000
        short expoMax = (short) (exponentMax >>> 52);           // e.g. clear: 0x0c17
        int highestLeadingBit = 32 - Integer.numberOfLeadingZeros(expoMax) - 1; // e.g. 10
        short lowestBitsMask = (short) ((1 << highestLeadingBit) - 1);  // e.g. 0x03ff
        short highestBitsMask = (short) ~lowestBitsMask;        // e.g. 0xfc00
        short xorMask = (short) (expoMax & lowestBitsMask);     // e.g. 0x0017
        expo = (short) ((expo & highestBitsMask)                // e.g. encrypted: 0x0234
                | ((expo & lowestBitsMask) ^ xorMask));
        exponent = (long) expo << 52;                           // e.g. clear: 0x2340000000000000
        rawBits = sign | exponent | significand;                // e.g. clear: 0xa3412345678abcde
        value = Double.longBitsToDouble(rawBits);
        return value;
    }

    private byte[] swapByteArray(byte[] value) {
        for (int i = 0; i < value.length / 2; i++) {
            byte b = value[i];
            value[i] = value[value.length - i - 1];
            value[value.length - i - 1] = b;
        }
        return value;
    }

    private byte[] toByteArray(long value) {
        return new byte[] { (byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value };
    }

    private long toLong(byte[] value) {
        return ((long) value[0] & 0xff) << 56 | ((long) value[1] & 0xff) << 48 | ((long) value[2] & 0xff) << 40
                | ((long) value[3] & 0xff) << 32 | ((long) value[4] & 0xff) << 24 | ((long) value[5] & 0xff) << 16
                | ((long) value[6] & 0xff) << 8 | (long) value[7] & 0xff;
    }
    
    private Map<String,String> filterMapingEntries(Map<String,String> mapping) {
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

    private Map<String,String> buildAttributesMapping(String[] attributes, Function<String, String> notCoveredTransform, Function<String,String> notProtected) {
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
                                for (String protectionRule : this.attributeTypes.keySet()) {
                                    Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                                    if (p.matcher(originalQualifAttribName).matches()) {
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
