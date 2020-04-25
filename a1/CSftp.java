import java.lang.System;
import java.io.*;
import java.nio.file.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.net.InetSocketAddress;

//
// This is an implementation of a simplified version of a command
// line ftp client. The program always takes two arguments
//


public class CSftp {
    static final int MAX_LEN = 255;
    static final int ARG_CNT = 2;
    static final int DEFAULT_PORT_NUMBER = 21;
    static final List<String> validCommands1 = Arrays.asList("features", "dir", "quit");
    static final List<String> validCommands2 = Arrays.asList("pw", "user", "get", "cd");
    private static Socket dataSocket = null;
    private static BufferedReader dataReader = null;
    private static Socket commandSocket = null;
    private static BufferedReader commandReader = null;
    private static PrintWriter commandWriter = null;

    private static int checkValidity(String[] cmdArr) {
        String cmd = cmdArr[0];
        if (validCommands1.contains(cmd) || validCommands2.contains(cmd)) {
            if (validCommands1.contains(cmd) && cmdArr.length == 1) return 0;
            if (validCommands2.contains(cmd) && cmdArr.length == 2) return 0;
            return 1;
        }
        return 2;
    }

    private static void createDataConnection(String IP, int port) {
        try {
            dataSocket = new Socket();
            dataSocket.connect(new InetSocketAddress(IP, port), 10000);
            dataReader = new BufferedReader(new InputStreamReader(dataSocket.getInputStream()));
        } catch (Exception e) {
            System.err.println("0x3A2 Data transfer connection to " + IP + " on port " + port + " failed to open.");
        }
    }

    private static void closeDataConnection() {
        try {
            dataReader.close();
            dataSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean setPassiveMode() {
        try {
            sendMessage("PASV");
            String passiveIPResponse = printResponse(commandReader);
            int start = passiveIPResponse.indexOf('(');
            int finish = passiveIPResponse.indexOf(')');
            String[] splittedIPPort;
            String IPAddress = "";
            int port = 0;
            if (start != -1 && finish != -1) {
                splittedIPPort = passiveIPResponse.substring(start + 1, finish).split(",");

                for (int i = 0; i < splittedIPPort.length; i++) {
                    if (i < 3) {
                        IPAddress += splittedIPPort[i] + ".";
                    } else if (i == 3) {
                        IPAddress += splittedIPPort[i];
                    } else if (i == 4) {
                        port += 256 * Integer.parseInt(splittedIPPort[i]);
                    } else if (i == 5) {
                        port += Integer.parseInt(splittedIPPort[i]);
                    }
                }
                createDataConnection(IPAddress, port);
                return true;
            }
            return false;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static void sendMessage(String msg) {
        System.out.println("--> " + msg);
        commandWriter.println(msg);
    }

    private static String printResponse(BufferedReader in) throws IOException {
        String line;
        if (in == dataReader) {
            try {
                while ((line = in.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                System.err.println("0x3A7 Data transfer connection I/O error, closing data connection.");
                closeDataConnection();
            }
            return null;
        } else {

            do {
                line = in.readLine();
                System.out.println("<-- " + line);
            } while (!(line.matches("\\d\\d\\d\\s.*")));

            return line;
        }
    }

    public static void main(String[] args) {
        byte cmdString[] = new byte[MAX_LEN];

        // Get command line arguments and connected to FTP
        // If the arguments are invalid or there aren't enough of them
        // then exit.

        if (args.length != ARG_CNT && args.length != ARG_CNT - 1) {
            System.out.print("Usage: cmd ServerAddress ServerPort\n");
            return;
        }

        String host = args[0];
        int portNumber = DEFAULT_PORT_NUMBER;
        try {
            if (args.length == ARG_CNT) {
                // what if the second argument is not an int? should we throw an exception
                portNumber = Integer.parseInt(args[1]);
            }
        } catch (NumberFormatException nfe) {
            System.out.println("Cannot have a non-integer value as a port number.");
            return;
        }

        if (portNumber < 0) {
            System.out.println("Cannot have a negative number as a port number.");
            return;
        }
        try {
            commandSocket = new Socket();
            commandSocket.connect(new InetSocketAddress(host, portNumber), 20000);
            commandReader = new BufferedReader(new InputStreamReader(commandSocket.getInputStream()));
            commandWriter = new PrintWriter(commandSocket.getOutputStream(), true);
            if (!commandSocket.isConnected()) {
                System.err.println("0xFFFC Control connection to " + host + " on port " + portNumber + " failed to open\n");
                return;
            } else {
                printResponse(commandReader);
            }
        } catch (Exception e) {
            System.err.println("0xFFFC Control connection to " + host + " on port " + portNumber + " failed to open\n");
            return;
        }

        for (int len; ; ) {
            System.out.print("csftp> ");
            try {
                len = System.in.read(cmdString);
            } catch (IOException e) {
                System.out.println("0xFFFE Input error while reading commands, terminating.");
                return;
            }
            int tmpLen = 0;
            StringBuilder str = new StringBuilder();

            while (tmpLen < len) {
                str.append((char) cmdString[tmpLen]);
                tmpLen++;
            }

            String trimmedCmd = str.toString().trim();
            String[] cmdArr = trimmedCmd.split("\\s+");
            int valid = checkValidity(cmdArr);
            if (valid == 1) {
                System.err.println("0x002 Incorrect number of arguments.");
                continue;
            } else if (valid == 2) {
                if (trimmedCmd.length() != 0) {
                    if (cmdArr[0].charAt(0) != "#".charAt(0)) {
                        System.err.println("0x001 Invalid command.");
                        continue;
                    }
                }
            }

            try {
                switch (cmdArr[0]) {
                    case "user":
                        sendMessage("USER " + cmdArr[1]);
                        printResponse(commandReader);
                        break;

                    case "pw":
                        sendMessage("PASS " + cmdArr[1]);
                        printResponse(commandReader);
                        break;

                    case "quit":
                        sendMessage("QUIT");
                        printResponse(commandReader);
                        commandReader.close();
                        commandWriter.close();
                        commandSocket.close();
                        if (dataReader != null) dataReader.close();
                        if (dataSocket != null) dataSocket.close();
                        return;

                    case "get":

                        if (setPassiveMode()) {
                            sendMessage("TYPE I");
                            printResponse(commandReader);
                            sendMessage("RETR " + cmdArr[1]);
                            String fromServerString = printResponse(commandReader);

                            Path path = Paths.get(System.getProperty("user.dir") + "/" + cmdArr[1]);
                            try {
                                if (fromServerString.contains("150")) {
                                    Files.copy(dataSocket.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
                                    printResponse(commandReader);
                                }
                            } catch (Exception exception) {
                                printResponse(commandReader);
                                System.err.println("0x38E Access to local file " + cmdArr[1] + " denied.");
                                closeDataConnection();
                            }
                        }
                        break;

                    case "features":
                        sendMessage("FEAT");
                        printResponse(commandReader);
                        break;

                    case "cd":
                        sendMessage("CWD " + cmdArr[1]);
                        printResponse(commandReader);
                        break;

                    case "dir":

                        if (setPassiveMode()) {
                            sendMessage("LIST");
                            printResponse(commandReader);
                            printResponse(dataReader);
                            closeDataConnection();
                            printResponse(commandReader);
                        }
                        break;

                    default:
                        break;
                }

            } catch (IOException exception) {
                System.err.println("0xFFFD Input error while reading commands, terminating.");
                return;
            } catch (Exception e) {
                System.err.println("0xFFFF Processing error." + e.getLocalizedMessage());
                return;
            }
        }
    }
}