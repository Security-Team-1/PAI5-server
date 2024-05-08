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

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class MsgSSLServerSocket {

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

	private static Boolean verifySignature(Connection conn, String msg, String numCliente, String firma) {

		try {
			Statement statement = conn.createStatement();
			String publicKeyStr = statement.executeQuery("SELECT clavePublica FROM users WHERE numCliente = '" + numCliente.trim()).getString(0);
			
			if (publicKeyStr == null) { // User does not exist
				return false;
			
			} else {

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
	
			while (true) {
				System.err.println("Waiting for connection...");
				SSLSocket socket = (SSLSocket) serverSocket.accept();
	
				try (BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					 PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()))) {
	
					String msg = input.readLine();
					String[] parts = msg.split(",");
	
					String numCliente = parts[0].trim();
					Integer numCamas = Integer.parseInt(parts[1].trim());
					Integer numMesas = Integer.parseInt(parts[2].trim());
					Integer numSillas = Integer.parseInt(parts[3].trim());
					Integer numSillones = Integer.parseInt(parts[4].trim());
					String firma = parts[5].trim();
	
					if (verifySignature(conn, msg, numCliente, firma)) {
						insertTransaction(conn, numCliente, numCamas, numMesas, numSillas, numSillones);
						output.println("Transaccion exitosa. El mensaje ha sido almacenado en el servidor");
					} else {
						output.println("Transaccion repetida. El mensaje NO ha sido almacenado en el servidor");
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
	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}