package src;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;

public class ServerCP2 {

    static ServerSocket welcomeSocket;
    static Socket connectionSocket;
    static DataOutputStream toClient;
    static DataInputStream fromClient;
    static FileOutputStream fileOutputStream;
    static BufferedReader inputReader;
    static PrintWriter out;


    /**************** CHANGE THESE VARIABLES ****************/
    static int PORTNUMBER = 4321;
    static String SERVERCRT = "/Users/emrys/Github/school/PA2-SUTD/keys/signedCert.crt";
    static String OUTPUT_FOLDER = "/Users/emrys/Github/school/PA2-SUTD/recv/";

    public static void main(String[] args) throws IOException {

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
            System.out.println("----------- CONGRATULATIONS YOU ARE VERIFIED ---------------");


            System.out.println("-------------- SESSION KEY SHARING ------------------");
            // Hold some variables here.
            byte[] encryptedSessionKey;
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            // wait for client to send over the signal to accept the encrypted key
            while (!connectionSocket.isClosed()) {

                int command = fromClient.readInt();
                BufferedInputStream inputStream = new BufferedInputStream(connectionSocket.getInputStream());

                if (command == 0) {
                    // Get the encrypted session key and decrypt using private key
                    int encryptedSessionKeySize = fromClient.readInt();
                    encryptedSessionKey = new byte[encryptedSessionKeySize];
                    fromClient.readFully(encryptedSessionKey);

                    System.out.println("Received encrypted session key of size: " + encryptedSessionKey.length);
                    System.out.println("---------------- print session key ------------------------");
                    System.out.println(Base64.getEncoder().encodeToString(encryptedSessionKey));
                    System.out.println("---------------- print session key end --------------------");
                    byte[] sessionKeyBytes = serverProtocol.decryptFile(encryptedSessionKey);
                    SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
                    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);
                    System.out.println("------------ SESSION KEY SHARING COMPLETE ----------------");
                }
                else if (command == 1) {
                    // set the filename
                    System.out.println("----------- receive filename -------------");
                    int nameLength = fromClient.readInt();
                    byte[] nameBytes = new byte[nameLength];
                    fromClient.readFully(nameBytes);
                    String filepath = new String(nameBytes);
                    fileOutputStream = new FileOutputStream(OUTPUT_FOLDER + "CP_2_" + getFileNameFromFilePath(filepath));
                    System.out.println("------------- filename received ---------------");

                } else if (command == 2) {
                    // Starts file transfer
                    System.out.println("Attempting to receive file...");
                    System.out.println("Getting file size...");
                    int encryptedFileSize = fromClient.readInt();
                    byte[] encryptedFileBytes = new byte[encryptedFileSize];
                    fromClient.readFully(encryptedFileBytes, 0, encryptedFileSize);
                    System.out.println("transfered length:" + encryptedFileBytes.length);
                    System.out.println("------------- file transfer complete ----------------");

                    System.out.println("---------------Decrypting file with session key ----------");
                    byte[] result = sessionCipher.doFinal(encryptedFileBytes);

                    fileOutputStream.write(result);
                    fileOutputStream.close();

                    // Indicate end of transfer to client
                    out.println("Ending transfer...");


                    // Close connection
                    System.out.println("----------- Closing connection --------------");
                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                }
            }
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