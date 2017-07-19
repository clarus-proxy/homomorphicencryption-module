package eu.clarussecure.dataoperations.homomorphic;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import static com.mongodb.client.model.Filters.eq;
import com.mongodb.client.model.UpdateOptions;
import eu.clarussecure.encryption.paillier.KeyPair;
import eu.clarussecure.encryption.paillier.Paillier;
import eu.clarussecure.encryption.paillier.PublicKey;
import eu.clarussecure.encryption.paillier.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bson.Document;

public class KeyStore {
    private static KeyStore instance = null;
    private final MongoDatabase db;
    private final MongoClient mongoClient;
    private final MongoCollection<Document> keystoreCollection;
    private int instancesNumber;

    private KeyStore() {
        // Initiate the basic connections to the database
        // Correctly configure the log level
        Logger mongoLogger = Logger.getLogger("org.mongodb.driver");
        mongoLogger.setLevel(Level.SEVERE);
        // Create a new client connecting to "localhost" on port 
        this.mongoClient = new MongoClient("localhost", 27017);

        // Get the database (will be created if not present)
        this.db = mongoClient.getDatabase("CLARUS");
        this.keystoreCollection = this.db.getCollection("keystore");

        this.instancesNumber++;
    }

    public static KeyStore getInstance() {
        if (KeyStore.instance == null) {
            KeyStore.instance = new KeyStore();
        }
        return KeyStore.instance;
    }

    public void deleteInstance() {
        this.instancesNumber--;

        if (this.instancesNumber <= 0) {
            this.mongoClient.close();
            KeyStore.instance = null;
        }
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
            ObjectInputStream inputStream;
            try {
                inputStream = new ObjectInputStream(new ByteArrayInputStream(bytesPubKeyN));
                pkN = (BigInteger) inputStream.readObject();
                inputStream = new ObjectInputStream(new ByteArrayInputStream(bytesPubKeyG));
                pkG = (BigInteger) inputStream.readObject();
                inputStream = new ObjectInputStream(new ByteArrayInputStream(bytesPrivKeyL));
                skL = (BigInteger) inputStream.readObject();
                inputStream = new ObjectInputStream(new ByteArrayInputStream(bytesPrivKeyM));
                skM = (BigInteger) inputStream.readObject();
            } catch (IOException | ClassNotFoundException e) {
                System.err.println("There was an error decoding the homomorphic keys");
                e.printStackTrace();
                System.exit(1);
            }

            // Create the Key Objects
            sk = new SecretKey(skL, skM);
            pk = new PublicKey(pkN, pkG);
            keyPair = new KeyPair(pk, sk);
        }
        return keyPair;
    }

    protected boolean generateSecurityParameters(String dataID) {
        KeyPair keys;
        String stringPubKeyN, stringPubKeyG, stringPrivKeyL, stringPrivKeyM;
        byte[] bytesPubKeyN = null, bytesPubKeyG = null, bytesPrivKeyL = null, bytesPrivKeyM = null;

        // TODO - Extract the length of the key from the configs
        int keyLength = 1024;

        // Generate the Keys using the KeyGenerator of the Paillier library
        keys = Paillier.Keygen(keyLength);

        BigInteger pkN = keys.getPublic().getN();
        BigInteger pkG = keys.getPublic().getG();
        BigInteger skL = keys.getSecret().getLambda();
        BigInteger skM = keys.getSecret().getMu();

        ByteArrayOutputStream baos;
        ObjectOutputStream outputStream;
        try {
            // Extract the bytes of each integer
            baos = new ByteArrayOutputStream();
            outputStream = new ObjectOutputStream(baos);
            outputStream.writeObject(pkN);
            bytesPubKeyN = baos.toByteArray();

            baos = new ByteArrayOutputStream();
            outputStream = new ObjectOutputStream(baos);
            outputStream.writeObject(pkG);
            bytesPubKeyG = baos.toByteArray();

            baos = new ByteArrayOutputStream();
            outputStream = new ObjectOutputStream(baos);
            outputStream.writeObject(skL);
            bytesPrivKeyL = baos.toByteArray();

            baos = new ByteArrayOutputStream();
            outputStream = new ObjectOutputStream(baos);
            outputStream.writeObject(skM);
            bytesPrivKeyM = baos.toByteArray();
        } catch (IOException e) {
            System.err.println("");
            System.exit(1);
        }

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
}
