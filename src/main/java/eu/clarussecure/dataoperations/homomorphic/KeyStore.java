package eu.clarussecure.dataoperations.homomorphic;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import static com.mongodb.client.model.Filters.eq;
import com.mongodb.client.model.UpdateOptions;
import cat.urv.crises.eigenpaillier.paillier.KeyPair;
import cat.urv.crises.eigenpaillier.paillier.Paillier;
import cat.urv.crises.eigenpaillier.paillier.PublicKey;
import cat.urv.crises.eigenpaillier.paillier.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bson.Document;

public class KeyStore {
    private static KeyStore instance = null;
    private final MongoDatabase db;
    private final MongoClient mongoClient;
    private final MongoCollection<Document> keystoreCollection;
    private int instancesNumber;

    private String confFile = "/etc/clarus/clarus-keystore.conf";
    private String mongoDBHostname = "localhost"; // Default server
    private int mongoDBPort = 27017; // Default port
    private String clarusDBName = "CLARUS"; // Default DB name

    private KeyStore() {
        // Initiate the basic connections to the database
        // Correctly configure the log level
        Logger mongoLogger = Logger.getLogger("org.mongodb.driver");
        mongoLogger.setLevel(Level.SEVERE);
        // Open the configuraiton file to extract the information from it.
        this.processConfigurationFile();
        // Create a new client connecting to "localhost" on port 
        this.mongoClient = new MongoClient(this.mongoDBHostname, this.mongoDBPort);

        // Get the database (will be created if not present)
        this.db = mongoClient.getDatabase(this.clarusDBName);
        this.keystoreCollection = this.db.getCollection("keystore");
    }

    public static synchronized KeyStore getInstance() {
        if (KeyStore.instance == null) {
            KeyStore.instance = new KeyStore();
        }
        KeyStore.instance.logInstance();
        return KeyStore.instance;
    }

    public synchronized void deleteInstance() {
        this.instancesNumber--;

        if (this.instancesNumber <= 0) {
            this.mongoClient.close();
            KeyStore.instance = null;
        }
    }

    private void logInstance() {
        this.instancesNumber++;
    }

    public KeyPair retrieveKey(String dataID) throws IOException {
        SecretKey sk = null;
        PublicKey pk = null;
        KeyPair keyPair = null;
        String stringPubKeyN, stringPubKeyG, stringPrivKeyL, stringPrivKeyM;
        byte[] bytesPubKeyN = null, bytesPubKeyG = null, bytesPrivKeyL = null, bytesPrivKeyM = null;
        BigInteger pkN = null, pkG = null, skL = null, skM = null;

        // Check if there is an entry for this data ID
        if (this.keystoreCollection.count(eq("dataID", dataID)) <= 0) {
            // There is not a Key-IV pair, generate one
            this.generateSecurityParameters(dataID);
        }

        // At this point, a Key-IV pair EXISTS in the DB for this dataID
        // Retrieve the key
        MongoCursor<Document> keys = this.keystoreCollection.find(eq("dataID", dataID)).iterator();
        Base64.Decoder decoder = Base64.getDecoder();
        if (keys.hasNext()) {
            // A key was found, retrieve it
            Document doc = keys.next();
            stringPubKeyN = doc.getString("homo-pub-key-n");
            stringPubKeyG = doc.getString("homo-pub-key-g");
            stringPrivKeyL = doc.getString("homo-priv-key-lambda");
            stringPrivKeyM = doc.getString("homo-priv-key-mu");

            // Decode the Strings
            bytesPubKeyN = decoder.decode(stringPubKeyN);
            bytesPubKeyG = decoder.decode(stringPubKeyG);
            bytesPrivKeyL = decoder.decode(stringPrivKeyL);
            bytesPrivKeyM = decoder.decode(stringPrivKeyM);

            // Create the BigInteger objects
            pkN = new BigInteger(bytesPubKeyN);
            pkG = new BigInteger(bytesPubKeyG);
            skL = new BigInteger(bytesPrivKeyL);
            skM = new BigInteger(bytesPrivKeyM);

            // Create the Key Objects
            sk = new SecretKey(skL, skM);
            pk = new PublicKey(pkN);
            keyPair = new KeyPair(pk, sk);
        }
        return keyPair;
    }

    protected boolean generateSecurityParameters(String dataID) {
        KeyPair keys;
        String stringPubKeyN, stringPubKeyG, stringPrivKeyL, stringPrivKeyM;
        byte[] bytesPubKeyN = null, bytesPubKeyG = null, bytesPrivKeyL = null, bytesPrivKeyM = null;

        // Extract the length of the key from the configs
        int keyLength = this.getKeyLength();

        // Generate the Keys using the KeyGenerator of the Paillier library
        keys = Paillier.Keygen(keyLength);

        BigInteger pkN = keys.getPublic().getN();
        BigInteger pkG = keys.getPublic().getG();
        BigInteger skL = keys.getSecret().getLambda();
        BigInteger skM = keys.getSecret().getMu();

        // Extract the bytes of each integer
        bytesPubKeyN = pkN.toByteArray();

        bytesPubKeyG = pkG.toByteArray();

        bytesPrivKeyL = skL.toByteArray();

        bytesPrivKeyM = skM.toByteArray();

        // Encode the bytes using Base64 encoder
        Base64.Encoder encoder = Base64.getEncoder();

        stringPubKeyN = encoder.encodeToString(bytesPubKeyN);
        stringPubKeyG = encoder.encodeToString(bytesPubKeyG);
        stringPrivKeyL = encoder.encodeToString(bytesPrivKeyL);
        stringPrivKeyM = encoder.encodeToString(bytesPrivKeyM);

        // Prepare the document into the dabase
        Document doc = new Document("dataID", dataID);
        doc.append("homo-pub-key-n", stringPubKeyN);
        doc.append("homo-pub-key-g", stringPubKeyG);
        doc.append("homo-priv-key-lambda", stringPrivKeyL);
        doc.append("homo-priv-key-mu", stringPrivKeyM);

        // Store the encoded key into the database
        boolean ack = this.keystoreCollection.replaceOne(eq("dataID", dataID), doc, new UpdateOptions().upsert(true))
                .wasAcknowledged();
        return ack;
    }

    private int getKeyLength() {
        // This method should retrieve the key length (in bits) from the DB
        MongoCursor<Document> cursor = this.keystoreCollection.find(eq("conf", "homomorphic-keylength")).iterator();

        int keyLength = 2048; // Default value is 2048 bits
        while (cursor.hasNext()) {
            keyLength = cursor.next().getDouble("keylength").intValue();
        }
        return keyLength;
    }

    private void processConfigurationFile() throws RuntimeException {
        // Open the file in read-only mode. This will avoid any permission problem
        try {
            // Read all the lines and join them in a single string
            List<String> lines = Files.readAllLines(Paths.get(this.confFile));
            String content = lines.stream().reduce("", (a, b) -> a + b);

            // Use the bson document parser to extract the info
            Document doc = Document.parse(content);
            this.mongoDBHostname = doc.getString("CLARUS_keystore_db_hostname");
            this.mongoDBPort = doc.getInteger("CLARUS_keystore_db_port");
            this.clarusDBName = doc.getString("CLARUS_keystore_db_name");
        } catch (IOException e) {
            throw new RuntimeException("CLARUS configuration file could not be processed", e);
        }
    }
}
