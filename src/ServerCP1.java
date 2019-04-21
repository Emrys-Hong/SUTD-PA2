package src;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerCP1 {
    static ServerSocket welcomeSocket = null;
    static Socket connectionSocket = null;
    static DataOutputStream toClient = null;
    static DataInputStream fromClient = null;
    static FileOutputStream fileOutputStream = null;
    static BufferedOutputStream bufferedFileOutputStream = null;
    static BufferedReader inputReader = null;
    static PrintWriter out = null;

    /**************** CHANGE THESE VARIABLES ****************/
    static int PORTNUMBER = 4321;
    static String SERVERCRT = "/Users/emrys/Github/school/PA2-SUTD/keys/signedCert.crt";
    static String OUTPUT_FOLDER = "/Users/emrys/Github/school/PA2-SUTD/recv/";

    public static void main(String[] args) {

        try {
            welcomeSocket = new ServerSocket(PORTNUMBER);

            // Prints IP
            System.out.println("Server IP: " + welcomeSocket.getInetAddress().getLocalHost().getHostAddress());

            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            inputReader = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

            out = new PrintWriter(connectionSocket.getOutputStream(), true);

            while (true){
                System.out.println("STEP0: ---------- request authentication ---------------");
                String request = getMessageFromClient(1);
                if (request.equals("1")){
                    System.out.println("----------------- STEP0 COMPLETE --------------------------");
                    break;
                }
                else
                    System.out.println("Request failed...");
            }

            // Set up protocol
            ServerProtocol serverProtocol = new ServerProtocol(SERVERCRT);

            // Get nonce from client
            System.out.println("STEP1: ---------- Getting nonce from client ---------------");
            fromClient.readFully(serverProtocol.getNonce());
            System.out.println("----------------- STEP1 COMPLETE --------------------------");

            // Encrypt nonce
            System.out.println("Encrypting nonce...");
            serverProtocol.encryptNonce();

            // Send nonce to client
            System.out.println("STEP2: --------- Sending encrypted nonce to client --------");
            toClient.write(serverProtocol.getEncryptedNonce());
            toClient.flush();
            System.out.println("---------------  STEP2 COMPLETE ---------------------------");

            // Receive certificate request from client
            while (true){
                System.out.println("STEP3: -------- receive client request for certificate -----------");
                String request = inputReader.readLine();
                System.out.println(request);
                if (request.equals("Request certificate...")){
                    System.out.println("---------------  STEP3 COMPLETE ---------------------------");

                    // Send certificate to client
                    System.out.println("STEP4: --------- Sending certificate to client -----------------");
                    toClient.write(serverProtocol.getCertificate());
                    toClient.flush();
                    System.out.println("---------------  STEP4 COMPLETE ---------------------------");
                    break;
                }
                else
                    System.out.println("Request failed...");
            }

            // Waiting for client to finish verification
            System.out.println("Client: " + inputReader.readLine());

            // Starts file transfer
            System.out.println("AP completes. Receiving file...");

            // Get file size from client
            int fileSize = fromClient.readInt();
            System.out.println(fileSize);
            int size = 0;

            int count = 0;
            while (size < fileSize) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filepath = new byte[numBytes];
                    fromClient.read(filepath);
                    String FILENPATH = new String(filepath, 0, numBytes);
                    fileOutputStream = new FileOutputStream(OUTPUT_FOLDER + "CP_2" + getFileNameFromFilePath(FILENPATH));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    count++;
                    int numBytes = fromClient.readInt();
                    int decryptedNumBytes = fromClient.readInt();
                    size+=decryptedNumBytes;

                    byte [] block = new byte[numBytes];
                    fromClient.read(block);

                    // Decrypt each 128 bytes
                    byte[] decryptedBlock = serverProtocol.decryptFile(block);

                    if (numBytes > 0){
                        bufferedFileOutputStream.write(decryptedBlock, 0, decryptedNumBytes);
                        bufferedFileOutputStream.flush();
                    }
                }
            }

            // Indicate end of transfer to client
            System.out.println("Transfer finished");
            out.println("Ending transfer...");

            // Close connection
            System.out.println("Closing connection...");
            bufferedFileOutputStream.close();
            fileOutputStream.close();

            fromClient.close();
            toClient.close();
            connectionSocket.close();

        } catch (Exception e) {e.printStackTrace();}

    }

    static private String getMessageFromClient(int length) throws IOException{
        byte[] temp = new byte[length];
        fromClient.readFully(temp);
        String message = new String(temp);
        return message;
    }

    static private String getFileNameFromFilePath(String filepath) {
        String[] FILENAMES = filepath.split("/");
        String FILENAME = FILENAMES[FILENAMES.length-1];
        return FILENAME;
    }
}
