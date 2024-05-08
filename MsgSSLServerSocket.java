import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class MsgSSLServerSocket {

	private static PrivateKey serverPrivateKey;
	//private static PublicKey serverPublicKey;

	private static Connection createConnection() {
		
		Connection conn = null;
		Statement statement = null;

		try {
			conn = DriverManager.getConnection("jdbc:sqlite:st1-database.db");
			statement = conn.createStatement();
			statement.setQueryTimeout(30);  

			statement.executeUpdate("drop table if exists users");
			statement.executeUpdate("create table users (numCliente string unique, clavePublica string unique)");
			System.out.println("Tabla users creada exitosamente.");

			statement.executeUpdate("drop table if exists orders");
			statement.executeUpdate("create table orders (numCliente number, numCamas number, numMesas number, numSillas number, numSillones number)");
			System.out.println("Tabla orders creada exitosamente.");

			generateKeysForServer();

		} catch (SQLException e) {
			e.printStackTrace();
		}
		return conn;
	}

	private static void insertUser(Connection conn, String numCliente, String clavePublica) {

		PreparedStatement preparedStatement = null;

		try {		
			String insertSQL = "INSERT INTO users (numCliente, clavePublica) VALUES (?, ?)";
			preparedStatement = conn.prepareStatement(insertSQL);
			preparedStatement.setString(1, numCliente);
			preparedStatement.setString(2, clavePublica);
			preparedStatement.executeUpdate();
		
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	private static void insertTransaction(Connection conn, String numCliente, Integer numCamas, Integer numMesas, Integer numSillas, Integer numSillones) {

		PreparedStatement preparedStatement = null;

		try {		
			String insertSQL = "INSERT INTO transactions (numCliente, numCamas, numMesas, numSillas, numSillones) VALUES (?, ?, ?, ?, ?)";
			preparedStatement = conn.prepareStatement(insertSQL);
			preparedStatement.setString(1, numCliente);
			preparedStatement.setInt(2, numCamas);
			preparedStatement.setInt(3, numMesas);
			preparedStatement.setInt(4, numSillas);
			preparedStatement.setInt(5, numSillones);
			preparedStatement.executeUpdate();
		
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	private static void populateDatabase(Connection conn) {

		try {
			for (int i = 1; i <= 10; i++) {

				String publicKeyStr = null;
				KeyPairGenerator keyPairGenerator;

				try {
					keyPairGenerator = KeyPairGenerator.getInstance("RSA");
					keyPairGenerator.initialize(2048);
					KeyPair keyPair = keyPairGenerator.generateKeyPair();
					PublicKey publicKey = keyPair.getPublic();
					publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());

				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				}

				insertUser(conn, "user" + i, publicKeyStr);
			}
			Statement statement = conn.createStatement();
			ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM users");
			System.out.println("Tabla de usuarios poblada exitosamente con " + rs.getInt(1) + " usuarios.");
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	private static void generateKeysForServer() {
		
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
	
			//PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
	
			MsgSSLServerSocket.serverPrivateKey = privateKey;
			//MsgSSLServerSocket.serverPublicKey = publicKey;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private static boolean verifyUserExists(Connection conn, String numCliente, String clavePublica) {
		try {
			Statement statement = conn.createStatement();
			ResultSet rs = statement.executeQuery("SELECT * FROM users WHERE numCliente = '" + numCliente + "' AND clavePublica = '" + clavePublica + "'");
			return rs.next(); // true if there is a row, false if not
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		}
	}

	// Integrity msg check
	private static boolean verifyHMAC(String message, String receivedHMAC) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			byte[] secretKeyBytes = serverPrivateKey.getEncoded();
			SecretKeySpec secretKey = new SecretKeySpec(secretKeyBytes, "HmacSHA256");
			mac.init(secretKey);

			byte[] calculatedHMAC = mac.doFinal(message.getBytes());
			String calculatedHMACBase64 = Base64.getEncoder().encodeToString(calculatedHMAC);
			return calculatedHMACBase64.equals(receivedHMAC);

		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static Boolean verifySignature(Connection conn, String msg, String numCliente, String firma) {

		try {
			Statement statement = conn.createStatement();
			String publicKeyStr = statement.executeQuery("SELECT clavePublica FROM users WHERE numCliente = '" + numCliente.trim()).getString(0);
			byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey;
			
			try {
				publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
				Signature sg = Signature.getInstance("SHA256withRSA");
				sg.initVerify(publicKey);
				sg.update(msg.getBytes());
				return sg.verify(firma.getBytes());
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
				return false;
			} catch (SignatureException e) {
				e.printStackTrace();
				return false;
			}
	
		} catch (SQLException | NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
			return false;
		}
	}

	public static void main(String[] args) {
        
		try {
			Connection conn = createConnection();
            populateDatabase(conn);

            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(3343);
			ExecutorService executorService = Executors.newCachedThreadPool();

            while (true) {
                System.err.println("Waiting for connection...");
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                executorService.execute(new ClientHandler(socket, conn));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler implements Runnable {
        
		private final SSLSocket socket;
        private final Connection conn;

        public ClientHandler(SSLSocket socket, Connection conn) {
            this.socket = socket;
            this.conn = conn;
        }

		@Override
        public void run() {
            try (BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()))) {

                String msg = input.readLine();
                String[] parts = msg.split(",");

                String numCliente = parts[0].trim();
				String clavePublica = parts[1].trim();

				Integer numCamas = Integer.parseInt(parts[2].trim());
				Integer numMesas = Integer.parseInt(parts[3].trim());
				Integer numSillas = Integer.parseInt(parts[4].trim());
				Integer numSillones = Integer.parseInt(parts[5].trim());

				String macRecibida = parts[6].trim();
				String firma = parts[7].trim();

                if (verifyUserExists(conn, numCliente, clavePublica) && verifyHMAC(msg, macRecibida)) {
                    if (!verifySignature(conn, msg, numCliente, firma)) {
                        insertTransaction(conn, numCliente, numCamas, numMesas, numSillas, numSillones);
                        output.println("Transaccion exitosa. El mensaje ha sido almacenado en el servidor");
                    } else {
                        output.println("Transaccion repetida. El mensaje NO ha sido almacenado en el servidor");
                    }
                } else if (!verifyUserExists(conn, numCliente, clavePublica)) {
                    output.println("Usuario no reconocido/autenticado. El mensaje NO ha sido almacenado en el servidor");
                } else if (!verifyHMAC(msg, macRecibida)) {
                    output.println("Mensaje no integro. El mensaje NO ha sido almacenado en el servidor");
                }

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
	}
}