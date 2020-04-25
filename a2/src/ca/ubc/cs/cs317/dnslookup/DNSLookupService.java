package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.net.DatagramPacket;
import java.io.ByteArrayInputStream;

import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static final int MAX_QUERY_LENGTH = 512;
    private static final int QUERY_HEADER_LENGTH = 12;
    private static final int QTYPE_LENGTH = 2;
    private static final int QCLASS_LENGTH = 2;
    private static final int RR_TYPE_LENGTH = 2;
    private static final int RR_CLASS_LENGTH = 2;
    private static final int RR_TTL_LENGTH = 4;
    private static final int RR_RDATA_LENGTH = 2;
    private static final int Q_STUFF = 5;
    private static final int MAX_RESPONSE = 1024;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();
    private static int offset = 0; //global offset for decoding

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    private static int findQueryLength(String hostName) {
        int ret = QUERY_HEADER_LENGTH;
        String[] domainNames = hostName.split("\\.");
        ret += domainNames.length;
        for (String names : domainNames) {
            ret += names.length();
        }
        ret += Q_STUFF; // the QCLASS, QTYPE, QNAME
        return ret;
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        Set<ResourceRecord> allResults = cache.getCachedResults(node);
        if (allResults.isEmpty()) {
            allResults = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
            if (allResults.isEmpty()) {
                retrieveResultsFromServer(node, rootServer);
                allResults = cache.getCachedResults(node);
                if (allResults.isEmpty())
                    allResults = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
                else return allResults;
                if (allResults.isEmpty()) return Collections.emptySet();
            }
            Object[] arr = allResults.toArray();
            ResourceRecord cname = (ResourceRecord) arr[new Random().nextInt(arr.length)];
            return getResults(
                    new DNSNode(cname.getTextResult(), node.getType()),
                    indirectionLevel + 1);
        }
        return allResults;
    }

    private static void decodeResponse(DNSNode node, byte[] resp) throws Exception {
        // 1. decode the header

        byte[] header = Arrays.copyOfRange(resp, 0, QUERY_HEADER_LENGTH);
        int ID = Integer.parseInt(String.format("%02X%02X", header[0], header[1]), 16);
        int QDCount = Integer.parseInt(String.format("%02X%02X", header[4], header[5]), 16);
        int ANCount = Integer.parseInt(String.format("%02X%02X", header[6], header[7]), 16);
        int NSCount = Integer.parseInt(String.format("%02X%02X", header[8], header[9]), 16);
        int ARCount = Integer.parseInt(String.format("%02X%02X", header[10], header[11]), 16);
        boolean AA = false;
        // decode flags in the second and third byte of the header
        ByteArrayInputStream flags = new ByteArrayInputStream(Arrays.copyOfRange(resp, 2, 4));
        int flagByte = flags.read();
        if ((flagByte >> 7) == 1) { // we have a response
            if ((flagByte & 0x04) == 0x04) {
                AA = true;
            }
            if (verboseTracing) {
                System.out.printf("Response ID: %d Authoritative = %s\n", ID, AA);
            }
            int rCode = flags.read();
            switch (rCode & 0x0F) {
                case 0x00: // no errors
                    if (AA && ANCount == 0){
                        throw new Exception("Authoritative response present, but nothing in 'Answer' section");
                    }
                    break;
                case 0x01:
                    throw new Exception("Format error");
                case 0x02:
                    throw new Exception("Server failure, problem with NS");
                case 0x03:
                    throw new Exception("Name error, domain name referenced in the query does not exist");
                case 0x04:
                    throw new Exception("Not Implemented - The name server does not support the requested kind of query");
                case 0x05:
                    throw new Exception("Refused - The name server refuses to perform the specified operation for " +
                            "policy reasons.");
                default:
                    throw new Exception("RCODE is not in the range [0, 5]");
            }
        } else return; // don't have a response

        // 2. read FQDN
        StringBuilder qName = new StringBuilder();
        ByteArrayInputStream ans = new ByteArrayInputStream(Arrays.copyOfRange(resp, header.length, resp.length));
        int oneByte = ans.read();
        while (oneByte != 0x00) {
            if ((oneByte >> 6) == 0) { // high-order two bits are 0
                int numChar = oneByte; // the number of char in the 'label'
                while (numChar != 0) {
                    qName.append((char) ans.read());
                    numChar--;
                }
                oneByte = ans.read();
                if (oneByte != 0x00) {
                    qName.append(".");
                }
            }
        }

        // 3. read the query stuff
        byte[] qTypeByte = new byte[QTYPE_LENGTH];
        ans.read(qTypeByte, 0, QTYPE_LENGTH);

        byte[] qClassByte = new byte[QCLASS_LENGTH];
        ans.read(qClassByte, 0, QCLASS_LENGTH);

        // rest of bytes in ans should pertain to RRs

        // the 2 comes from the 0x00 which terminates qName, and an additional byte for the 'label' char length
        offset = QUERY_HEADER_LENGTH + QCLASS_LENGTH + QTYPE_LENGTH + qName.toString().length() + 2;

        ResourceRecord record;

        ArrayList<ResourceRecord> answers = new ArrayList<>();
        if (verboseTracing)
            System.out.println("  Answers (" + ANCount + ")");
        for (int i = 0; i < ANCount; i++) {
            record = decodeRR(resp, AA);
            answers.add(record);
            verbosePrintResourceRecord(record, 0);
        }

        ArrayList<ResourceRecord> nameServers = new ArrayList<>();
        if (verboseTracing)
            System.out.println("  Nameservers (" + NSCount + ")");
        for (int i = 0; i < NSCount; i++) {
            record = decodeRR(resp, true);
            nameServers.add(record);
            verbosePrintResourceRecord(record, 0);
        }

        ArrayList<ResourceRecord> additionals = new ArrayList<>();
        if (verboseTracing)
            System.out.println("  Additional Information (" + ARCount + ")");
        for (int i = 0; i < ARCount; i++) {
            record = decodeRR(resp, true);
            additionals.add(record);
            verbosePrintResourceRecord(record, 0);
        }

        if (!AA && !nameServers.isEmpty()) {
            if (additionals.isEmpty()) {
                additionals.addAll(getResults(new DNSNode(nameServers.get(0).getTextResult(), RecordType.A), 0));
            }
            for (ResourceRecord ad : additionals) {
                if (ad.getType().getCode() == 1) {
                    for (ResourceRecord ns : nameServers) {
                        if (ad.getHostName().equals(ns.getTextResult())) {
                            retrieveResultsFromServer(node, ad.getInetResult());
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    // returns the compressed msg string, and the number of bytes the string occupies
    private static String[] compressedMsg(int offset, byte[] resp) {
        int numBytesCount = 0;
        ByteArrayInputStream msg = new ByteArrayInputStream(Arrays.copyOfRange(resp, offset, resp.length));
        int oneByte = msg.read();
        StringBuilder str = new StringBuilder();
        while (oneByte != 0x00) { // not at the end of the name
            if ((oneByte >> 6) == 3) { // high-order two bits are 1's --> ptr
                int firstOctet = oneByte & 0x3F; // get the last six bits, part of the offset
                numBytesCount++;
                int ptrOffset = Integer.parseInt(String.format("%02X%02X", firstOctet, msg.read()), 16);
                return new String[]{str.append(compressedMsg(ptrOffset, resp)[0]).toString(), String.valueOf(++numBytesCount)};
            } else {
                int numChar = oneByte; // the  number of char in the 'label'
                numBytesCount++;
                while (numChar != 0) {
                    str.append((char) msg.read());
                    numBytesCount++;
                    numChar--;
                }
            }
            oneByte = msg.read();
            if (oneByte != 0x00) {
                str.append(".");
            }
        }
        numBytesCount++;
        return new String[]{str.toString(), String.valueOf(numBytesCount)};
    }

    private static ResourceRecord decodeRR(byte[] resp, boolean shouldCache) {
        // RR NAME
        ByteArrayInputStream rr = new ByteArrayInputStream(Arrays.copyOfRange(resp, offset, resp.length));
        String[] compressedName = compressedMsg(offset, resp);
        String name = compressedName[0];
        StringBuilder info = new StringBuilder();
        int numBytesFromName = Integer.parseInt(compressedName[1]);
        rr.skip(numBytesFromName);
        offset += numBytesFromName;

        // RR TYPE
        byte[] rrType = new byte[RR_TYPE_LENGTH];
        rr.read(rrType, 0, RR_TYPE_LENGTH);
        offset += RR_TYPE_LENGTH;
        RecordType type = RecordType.getByCode(hexByteToInt(rrType));

        // RR CLASS
        byte[] rrClass = new byte[RR_CLASS_LENGTH];
        rr.read(rrClass, 0, RR_CLASS_LENGTH);
        offset += RR_CLASS_LENGTH;

        // RR TTL
        byte[] rrTTL = new byte[RR_TTL_LENGTH];
        rr.read(rrTTL, 0, RR_TTL_LENGTH);
        offset += RR_TTL_LENGTH;
        StringBuilder ttlStr = new StringBuilder();
        for (byte b : rrTTL) {
            ttlStr.append(String.format("%02X", b));
        }
        long ttl = Long.parseLong(ttlStr.toString(), 16);

        // RR RDATA (length)
        StringBuilder rDataLengthString = new StringBuilder();
        byte[] rrRData = new byte[RR_RDATA_LENGTH];
        rr.read(rrRData, 0, RR_RDATA_LENGTH);
        offset += RR_RDATA_LENGTH;
        int rrRDataLen = hexByteToInt(rrRData);
        ResourceRecord record;
        InetAddress ip = null;
        try {
            if (type == RecordType.getByCode(1) || type == RecordType.getByCode(28)) {
                byte[] ipArr = new byte[rrRDataLen];
                rr.read(ipArr, 0, rrRDataLen);
                ip = InetAddress.getByAddress(ipArr);
            } else {
                info.append(compressedMsg(offset, resp)[0]);
                rr.skip(rrRDataLen);
            }
        } catch (UnknownHostException uhe) {
            uhe.printStackTrace();
            return null;
        }
        offset += rrRDataLen;
        if (type == RecordType.getByCode(1) || type == RecordType.getByCode(28)) {
            record = new ResourceRecord(name, type, ttl, ip);
        } else {
            record = new ResourceRecord(name, type, ttl, info.toString());
        }
        if (shouldCache) cache.addResult(record);
        return record;
    }

    /**
     * Given byte array, convert to hex representation
     *
     * @param arr The byte array that contains the hex digits
     * @return integer representing the hexadecimal representation in decimal
     */
    private static int hexByteToInt(byte[] arr) {
        StringBuilder str = new StringBuilder();
        for (byte b : arr) {
            str.append(String.format("%02X", b));
        }
        return Integer.parseInt(str.toString(), 16);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        int queryId = random.nextInt(65536);

        String dnsName = node.getHostName();
        RecordType dnsType = node.getType();
        String[] domainNames = dnsName.split("\\.");
        int queryLength = Integer.min(MAX_QUERY_LENGTH, findQueryLength(dnsName)); // can prob simplify to just findQueryLength()
        ByteBuffer query = ByteBuffer.allocate(queryLength); // placeholder, change length later
        query.putShort((short) queryId); // id
        query.putShort((short) 0x0000); // query parameters
        query.putShort((short) 0x0001); // number of questions
        query.putShort((short) 0x0000); // number of answers
        query.putShort((short) 0x0000); // number of authority records
        query.putShort((short) 0x0000); // number of additional records
        // QNAME
        for (String names : domainNames) {
            query.put((byte) names.length());
            for (int i = 0; i < names.length(); i++) {
                char c = names.charAt(i);
                query.put((byte) c);
            }
        }
        query.put((byte) 0x00); // zero byte to end QNAME
        switch (dnsType){
            case A:
                query.putShort((short) 0x0001);
                break;
            case NS:
                query.putShort((short) 0x0002);
                break;
            case CNAME:
                query.putShort((short) 0x0005);
                break;
            case SOA:
                query.putShort((short) 0x0006);
                break;
            case MX:
                query.putShort((short) 0x000F);
                break;
            case AAAA:
                query.putShort((short) 0x001C);
                break;
            default: // OTHER
                query.putShort((short) 0x0000);
                break;
        }
        query.putShort((short) 0x0001); // QCLASS
        // send packet with query and geta response back
        DatagramPacket sentPacket = new DatagramPacket(query.array(), queryLength, server, DEFAULT_DNS_PORT);
        byte[] incomingData = new byte[MAX_RESPONSE];
        DatagramPacket receivedPacket = new DatagramPacket(incomingData, MAX_RESPONSE);
        int tries = 0;
        while(tries < 3) {
            try {
                socket.send(sentPacket);
                if (verboseTracing) {
                    System.out.printf("\n\nQuery ID     %d %s  %s --> %s\n",
                            queryId, node.getHostName(),
                            node.getType(),
                            server.toString().substring(1));
                }
                socket.receive(receivedPacket);
                tries++;
                incomingData = receivedPacket.getData();

                // check if queryID == transactionID from the receivedPacket
                byte[] transactionID = Arrays.copyOfRange(incomingData, 0, 2);
                if (hexByteToInt(transactionID) == queryId) {
                    decodeResponse(node, incomingData);
                    break;
                }
            } catch (SocketTimeoutException ste) {
                tries++;

            } catch (Exception e) {
                // System.err.println("ERROR " + e);
                return;
            }
        }
    }


    private static void verbosePrintResourceRecord (ResourceRecord record,int rtype){
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults (DNSNode node, Set < ResourceRecord > results){
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
