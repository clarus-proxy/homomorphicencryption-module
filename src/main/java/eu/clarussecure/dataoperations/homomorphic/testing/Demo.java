package eu.clarussecure.dataoperations.homomorphic.testing;

import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.dataoperations.homomorphic.HomomorphicCriteria;
import eu.clarussecure.dataoperations.homomorphic.HomomorphicModule;
import eu.clarussecure.dataoperations.homomorphic.HomomorphicRemoteOperationCommand;
import eu.clarussecure.dataoperations.homomorphic.HomomorphicResult;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Demo {
    public final static String POLICY_FILENAME = "sec-pol-examples/homo-pol.xml";
    public final static String DATA_FILENAME = "sec-pol-examples/meuse2.txt";
    public final static int HOMOCOLUMN = 2;

    public static void main(String[] args) throws IOException, SAXException, ParserConfigurationException {
        // Read the data from the file
        String[] attributes = readColumnNames(DATA_FILENAME);
        String[] qualifiedAttribs = AttributeNamesUtilities.fullyQualified(Arrays.asList(attributes))
                .toArray(new String[attributes.length]);
        String[][] data = readData(DATA_FILENAME);

        // Initialize the "cloud" to execute the commands
        HomomorphicCloud cloud = null;
        HomomorphicCloud untouchedCloud = new HomomorphicCloud(attributes);
        untouchedCloud.addRows(data);

        // Print the untouched cloud
        System.out.println("*****************ORIGINAL*******************");
        System.out.print(untouchedCloud.simplePrintCloudContents());
        System.out.println("********************************************");

        // Parse the XML security policy
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document policy = db.parse(new File(POLICY_FILENAME));

        // Instantiate the Clarus Encryption Module
        DataOperation encryption = new HomomorphicModule(policy);
        //DataOperation encryption = new EncryptionModule(null);

        // First "POST" to the cloud
        List<DataOperationCommand> commandsPost = encryption.post(qualifiedAttribs, data);
        // Create a cloud object with the protected Attribute Names
        cloud = new HomomorphicCloud(commandsPost.get(0).getProtectedAttributeNames());

        // Query the cloud
        for (DataOperationCommand command : commandsPost) {
            cloud.addRows(command.getProtectedContents());
        }

        // Show the content of the cloud
        System.out.println("****************ENCRYPTED*******************");
        System.out.print(cloud.simplePrintCloudContents());
        System.out.println("********************************************");

        // Insert a new row into the cloud
        // The "0" in third column (copper value) will be interpreted as "48"... its ASCII value
        String[][] append = { { "500", "1.800000000000000", "0", "97.000000000000000", "251.000000000000000",
                "9.073000000000000", "0.228123000000000", "9.000000000000000", "1", "1", "0", "Ag",
                "300.000000000000000", "0101000020E61000000000000040190641000000009C531441" } };

        List<DataOperationCommand> commandsPost2 = encryption.post(attributes, append);

        // Query the cloud
        for (DataOperationCommand command : commandsPost2) {
            cloud.addRow(command.getProtectedContents()[0]);
        }

        // Show the content of the cloud
        System.out.println("***************ENCRYPTED-2******************");
        System.out.print(cloud.simplePrintCloudContents());
        System.out.println("********************************************");

        List<DataOperationCommand> commandsGet = null;
        List<String[][]> results = null;
        List<DataOperationResult> r = null;
        HomomorphicResult response = null;
        HomomorphicCloud aux = null;

        // Retrieve the data from the cloud
        // CASE 1: no criteria = all the data
        commandsGet = encryption.get(qualifiedAttribs, null);

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (HomomorphicResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new HomomorphicCloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("*****************DECRYPTED******************");
        System.out.print(aux.decodeAndPrintCloudContents());
        System.out.println("********************************************");

        // CASE 2: select some columns
        String[] someColumns = { "meuseDB/meuse/gid", "meuseDB/meuse/copper", "meuseDB/meuse/lead" };
        String[] qualifiedSomeColumns = AttributeNamesUtilities.fullyQualified(Arrays.asList(someColumns))
                .toArray(new String[someColumns.length]);
        commandsGet = encryption.get(qualifiedSomeColumns, null);

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (HomomorphicResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new HomomorphicCloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-2*****************");
        System.out.print(aux.decodeAndPrintCloudContents());
        System.out.println("********************************************");

        // CASE 3: Find a single record with a Criterion (using entry ID)
        Criteria crit = new Criteria("meuseDB/meuse/gid", "=", "5");
        commandsGet = encryption.get(qualifiedAttribs, new Criteria[] { crit });

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (HomomorphicResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new HomomorphicCloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-3*****************");
        System.out.print(aux.decodeAndPrintCloudContents());
        System.out.println("********************************************");

        // CASE 4: Find records with multiple criteria in different columns
        // NOTE - At the moment, using multiple criteria has an "and" semantics
        crit = new Criteria("meuseDB/meuse/gid", ">=", "20"); // gid is not encrypted.
        //Criteria crit2 = new Criteria("meuseDB/meuse/lead", ">=", "500"); lead is encrypted... THIS IS NOT SUPPORTED
        Criteria crit2 = new Criteria("meuseDB/meuse/elev", ">=", "8.0");
        commandsGet = encryption.get(qualifiedAttribs, new Criteria[] { crit, crit2 });

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (HomomorphicResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new HomomorphicCloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-4*****************");
        System.out.print(aux.decodeAndPrintCloudContents());
        System.out.println("********************************************");

        // CASE 5: Simple homomorphic Operation
        // NOTE - At the moment, using multiple criteria has an "and" semantics
        //crit = new Criteria("meuseDB/meuse/gid", ">=", "20"); // gid is not encrypted.
        HomomorphicCriteria crit3 = HomomorphicCriteria.getInstance("+", "meuseDB/meuse/copper");
        commandsGet = encryption.get(qualifiedAttribs, new Criteria[] { crit3 });

        // Query the cloud
        results = new ArrayList<>();
        HomomorphicRemoteOperationCommand homoCom = null;
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            if (command instanceof HomomorphicRemoteOperationCommand) {
                String[][] partialResult = cloud.performHomomorphicComputation(command.getProtectedAttributeNames(),
                        command.getCriteria(), (HomomorphicRemoteOperationCommand) command);
                homoCom = (HomomorphicRemoteOperationCommand) command;
                results.add(partialResult);
            }
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (HomomorphicResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new HomomorphicCloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-6*****************");
        System.out.print(aux.decodeAndPrintCloudContents());
        System.out.println("********************************************");

        // CASE 6: Homomorphic Operation and selection of rows
        // NOTE - At the moment, using multiple criteria has an "and" semantics
        crit = new Criteria("meuseDB/meuse/gid", ">=", "100"); // gid is not encrypted.
        crit3 = HomomorphicCriteria.getInstance("+", "meuseDB/meuse/copper");
        commandsGet = encryption.get(qualifiedAttribs, new Criteria[] { crit, crit3 });

        // Query the cloud
        results = new ArrayList<>();
        homoCom = null;
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            if (command instanceof HomomorphicRemoteOperationCommand) {
                String[][] partialResult = cloud.performHomomorphicComputation(command.getProtectedAttributeNames(),
                        command.getCriteria(), (HomomorphicRemoteOperationCommand) command);
                homoCom = (HomomorphicRemoteOperationCommand) command;
                results.add(partialResult);
            }
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (HomomorphicResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new HomomorphicCloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-6*****************");
        System.out.print(aux.decodeAndPrintCloudContents());
        System.out.println("********************************************");

    }

    private static String[] readColumnNames(String filename) throws IOException {
        String line;
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            line = br.readLine();
        }

        return line.split(",");
    }

    private static String[][] readData(String filename) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));

        br.readLine(); // discard first line: column names

        String line;
        Set<String[]> data = new HashSet<>();
        int records = 0, columns = 1;

        while ((line = br.readLine()) != null) {
            data.add(line.split(","));
            records++;
            columns = line.split(",").length;
        }

        return data.toArray(new String[columns][records]);
    }
}
