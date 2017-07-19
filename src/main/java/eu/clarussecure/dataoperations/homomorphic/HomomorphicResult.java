package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.DataOperationResult;

public class HomomorphicResult extends DataOperationResult {
    private String[][] decryptedContent;
    private String[] decryptedAttributeNames;

    public HomomorphicResult(String[] attributeNames, String[][] content) {
        this.decryptedAttributeNames = attributeNames;
        this.decryptedContent = content;
    }

    public String[][] getDecryptedContent() {
        return this.decryptedContent;
    }

    public String[] getDecryptedAttributeNames() {
        return this.decryptedAttributeNames;
    }
}
