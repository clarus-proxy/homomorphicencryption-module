package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.Criteria;
import java.util.Map;

public class HomomorphicRemoteOperationCommand extends HomomorphicCommand {
    // TODO - This class will represent the request for a remote
    // operation on data encrypted with homomorphic schema

    // FIXME - Maybe define the operations in a ENUM depeding on the encryption schema?
    protected String operation;
    protected String involvedColumn; // It is assumed this is a protected Attribute name

    public HomomorphicRemoteOperationCommand(String[] attributeNames, String[] protectedAttributeNames,
            String[][] protectedContents, Map<String, String> mapping, Criteria[] criteria, String operation,
            String involvedRow) {
        super(attributeNames, protectedAttributeNames, protectedContents, mapping, criteria);
        this.operation = operation;
        this.involvedColumn = involvedRow;
    }

    public String getOperation() {
        return this.operation;
    }

    public String getInvelvedColumn() {
        return this.involvedColumn;
    }
}
