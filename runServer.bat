@echo off

javac MsgSSLServerSocket.java

java "-Djavax.net.ssl.keyStore=C:\SSLStore\keystore.jks" "-Djavax.net.ssl.keyStorePassword=pai5st1" -classpath ".;sqlite-jdbc-3.45.2.0.jar;slf4j-api-1.7.36.jar" MsgSSLServerSocket
