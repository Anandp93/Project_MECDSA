package com.anand.crypto.ds.mecdsa.server;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import javax.json.Json;
import javax.json.JsonObject;
public class ServerThread extends Thread {
	private Server server;
	private BufferedReader bufferedReader;
	private PrintWriter printWriter; 
	public ServerThread(Socket socket, Server server) throws IOException {
		this.server = server;
		this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.printWriter = new PrintWriter(socket.getOutputStream(), true);
	}
	public void run() {
		JsonObject jsonObject = null;
		try {
			while(true) {
				jsonObject = Json.createReader(bufferedReader).readObject();  
				System.out.println("\n[system]: "+jsonObject.toString());
				server.forwardMessage(jsonObject.toString(), this);
				if (jsonObject.containsKey("a")) 
					System.out.println("[Eve]: have domain params (curve & generator point) for "+jsonObject.getString("name"));
				else if (jsonObject.containsKey("x")) {
					System.out.println("[Eve]: to sign messages as being "+jsonObject.getString("name")+" need to solve ECDLP ");
					System.out.println("       and compute his/her private key d or ephemeral key");
				}
			} 
		} catch (Exception e) { server.getServerThreads().remove(this);}
	}
	void forwardMessage(String message) { printWriter.println(message); }
}
