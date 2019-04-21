package src;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

public class ClientCP2 {
    public static void main(String[] args) {


        Socket clientSocket = null;
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
        FileInputStream fileInputStream = null;
        PrintWriter out = null;
        BufferedReader in = null;
        long timeStarted = 0;


        /*****************CHANGE THESE VARIABLES****************/
        String filename = "../input/smallest/rr.txt";
        String serverIP = "localhost";
        int serverPort = 4321;
        String CACERT = "CA.crt";

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverIP, serverPort);

            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // Set up protocol
            ClientProtocol clientProtocol = new ClientProtocol(CACERT);

            out.println("Requesting authentication...");
            System.out.println("Requesting authentication...");

            // Generate nonce
            System.out.println("Generating nonce...");
            clientProtocol.generateNonce();

            // Send nonce to sever
            System.out.println("Sending nonce to server...");
            toServer.write(clientProtocol.getNonce());

            // Retrieve encrypted nonce from server
            fromServer.read(clientProtocol.getEncryptedNonce());
            System.out.println("Retrieved encrypted nonce from server...");

            // Send certificate request to server
            System.out.println("Requesting certificate from server...");
            out.println("Request certificate...");


            clientProtocol.getCertificate(fromServer);
            System.out.println("Validating certificate...");
            clientProtocol.verifyCert();
            System.out.println("Certificate validated");
            System.out.println("Verifying server...");
            // Get public key
            clientProtocol.getPublicKey();

            // Decrypt encrypted nonce
            byte[] decryptedNonce = clientProtocol.decryptNonce(clientProtocol.getEncryptedNonce());

            if (clientProtocol.validateNonce(decryptedNonce)){
                System.out.println("Server verified");
                out.println("Server verified");
            } else{
                System.out.println("Server verification failed");
                System.out.println("Closing all connections...");
                toServer.close();
                fromServer.close();
                clientSocket.close();
            }

            System.out.println("Starting CP-2 session...");

            // init the cipher
            SecretKey sessionKey = KeyGenerator.getInstance("AES").generateKey();
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);

            // encrypt the session key
            byte[] encryptedSessionKey = clientProtocol.encryptFile(sessionKey.getEncoded());
            System.out.println(Base64.getEncoder().encodeToString(encryptedSessionKey));

            BufferedOutputStream outputStream = new BufferedOutputStream(toServer);

            // begin clocking the file transfer
            timeStarted = System.nanoTime();

            // notify server that the session key is coming
            toServer.writeInt(0);
            toServer.writeInt(encryptedSessionKey.length);
            toServer.flush();

            outputStream.write(encryptedSessionKey, 0, encryptedSessionKey.length);
            outputStream.flush();

            System.out.println("Sent encrypted session key");

            // Open the file
            File file = new File(filename);
            fileInputStream = new FileInputStream(file);

            // set up buffer and read the file into it
            byte[] fileByteArray = new byte[(int)file.length()];
            fileInputStream.read(fileByteArray, 0, fileByteArray.length);
            fileInputStream.close();

            // send the file name as encrypted byte array
            toServer.writeInt(1);
            toServer.writeInt(filename.getBytes().length);
            toServer.flush();

            outputStream.write(filename.getBytes());
            outputStream.flush();

            // encrypt the file with the session key
            //byte[] encryptedFile = clientProtocol.encryptFile(sessionCipher, fileByteArray);
            byte[] encryptedFile = sessionCipher.doFinal(fileByteArray);
            System.out.println(Base64.getEncoder().encodeToString(encryptedFile));

            // tell the server the encrypted file is coming and send it
            toServer.writeInt(2);
            System.out.println("Writing length: " + encryptedFile.length);
            toServer.writeInt(encryptedFile.length);
            toServer.flush();

            //outputStream = new BufferedOutputStream(toServer);
            toServer.write(encryptedFile, 0, encryptedFile.length);
            toServer.flush();

            // Receives end signal from server
            while (true) {
                String end = in.readLine();
                if (end.equals("Ending transfer...")){
                    System.out.println("Server: " + end);
                    break;
                }
                else
                    System.out.println("End request failed...");
            }

            System.out.println("Closing connection...");
            fileInputStream.close();

        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }
}