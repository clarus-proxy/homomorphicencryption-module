package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperationCommand;
import java.util.Map;

public class HomomorphicCommand extends DataOperationCommand {

    public HomomorphicCommand(String[] attributeNames, String[] protectedAttributeNames, String[][] protectedContents,
            Map<String, String> mapping, Criteria[] criteria) {
        this.protectedAttributeNames = protectedAttributeNames;
        this.attributeNames = attributeNames;
        this.extraBinaryContent = null;
        this.extraProtectedAttributeNames = null;
        this.protectedContents = protectedContents;
        this.mapping = mapping;
        this.criteria = criteria;
    }
}
