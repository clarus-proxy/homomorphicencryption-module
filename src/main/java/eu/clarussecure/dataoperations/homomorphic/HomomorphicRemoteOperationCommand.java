package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.Criteria;
import cat.urv.crises.eigenpaillier.paillier.EncryptedInteger;
import cat.urv.crises.eigenpaillier.paillier.PublicKey;
import java.util.Map;

public class HomomorphicRemoteOperationCommand extends HomomorphicCommand {
    // TODO - This class will represent the request for a remote
    // operation on data encrypted with homomorphic schema

    // FIXME - Maybe define the operations in a ENUM depeding on the encryption schema?
    protected String operation;
    protected String involvedColumn; // It is assumed this is a protected Attribute name
    protected PublicKey pk; // The homomorphic computation REQUIRES the public key.
    protected EncryptedInteger encryptedZero; // This constant might be useful for the cloud to start computing

    public HomomorphicRemoteOperationCommand(String[] attributeNames, String[] protectedAttributeNames,
            String[][] protectedContents, Map<String, String> mapping, Criteria[] criteria, String operation,
            String involvedRow, PublicKey pk, EncryptedInteger encryptedZero) {
        super(attributeNames, protectedAttributeNames, protectedContents, mapping, criteria);
        this.operation = operation;
        this.involvedColumn = involvedRow;
        this.pk = pk;
        this.encryptedZero = encryptedZero;
    }

    public String getOperation() {
        return this.operation;
    }

    public String getInvolvedColumn() {
        return this.involvedColumn;
    }

    public PublicKey getPublicKey() {
        return this.pk;
    }

    public EncryptedInteger getEncryptedZero() {
        return this.encryptedZero;
    }
}
