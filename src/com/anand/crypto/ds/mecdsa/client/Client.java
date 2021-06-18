package com.anand.crypto.ds.mecdsa.client;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.IntStream;
import javax.json.Json;
public class Client {
	public static boolean ASCII_FLAG = false;
	public static int BASE = 10; // enter 10 for decimal and 16 for hexadecimal message and curve value
	private PrintWriter printWriter; 
	private String name = null;
	private String otherPartyName = null;
	private EllipticCurve ellipticCurve = null;
	private EllipticCurve otherPartyEllipticCurve = null;
	private Point pointA = null;
	private Point otherPartyPointA = null;
	private Point otherPartyPointB = null; 
	private BigInteger privateKey = null;
	private boolean readyFlag = false;
	private String prompt = null;
	public static void main(String[] args) throws UnknownHostException, IOException {
		if (ASCII_FLAG) System.out.println("running in ASCII & base "+ BASE + " modes");
		else System.out.println("running in base "+ BASE + " mode");
		Client client = new Client();
		Socket socket = new Socket("localhost", 4444);
		new ClientThread(socket, client).start();
		client.printWriter = new PrintWriter(socket.getOutputStream(), true);
		client.handleInput(BASE);
	}
	public void handleInput(int base) {
		BufferedReader bR = new BufferedReader(new InputStreamReader(System.in));
		try {
			StringWriter sW = new StringWriter();
			initDomainParams(sW, bR, base);
			calcPublicKey(sW, bR, base);
		} catch (IOException e) { System.out.println(e.getMessage()); }
		while (true) {
			if (!readyFlag) {
				prompt = new String("[system]: ready to send & receive messages, or e:xit");
				System.out.println(prompt);
				readyFlag = true;
			}
			try { pickupHashSignAndSendMessage(bR, base);} 
			catch(Exception e) {System.out.println("[system]: invalid entry.");}
		}
	}
	private void pickupHashSignAndSendMessage(BufferedReader bR, int base) throws IOException, NoSuchAlgorithmException {
		String message = null;
		StringBuffer xStringBuffer = null;
		if (!ASCII_FLAG) {
			message = bR.readLine();
			if (message.equals("e")) System.exit(0);
			xStringBuffer = handleMessageHashing(message, base);
		} else {
			while (true) {
				try {
					message = bR.readLine();
					if (message.equals("e")) System.exit(0);
					new BigInteger(message, base);
					break;
				} catch (Exception e) { System.out.println("invalid entry.");}
			}
		}
		BigInteger ephemeralKey = pickupEphemeralKey(bR, base);
		BigInteger r = calculateR(ephemeralKey);
		StringBuffer sStringBuffer = null;
		if (ASCII_FLAG) sStringBuffer = calculateS(message.trim(), bR, ephemeralKey, r, base);
		else sStringBuffer = calculateS(xStringBuffer.toString().trim(), bR, ephemeralKey, r, base);
		sendSignedMessage(message, r, sStringBuffer, base);
	}
	private BigInteger calculateR(BigInteger ephemeralKey) {
		Point pointR = this.ellipticCurve.fastMultiply(ephemeralKey, this.pointA);
		System.out.println("["+name+"]: R = "+ pointR);
		return pointR.getX();
	}
	private StringBuffer calculateS(String message, BufferedReader bR, 
			               BigInteger ephemeralKey, BigInteger r, int base) throws IOException {
		String tokens = message.trim();
		BigInteger s = null; 
		StringBuffer sStringBuffer = new StringBuffer();
		BigInteger signingKey = pickupSigningKey(bR, base);
		s = (new BigInteger(tokens).add(signingKey.multiply(r)))
						.multiply(ephemeralKey.modInverse(this.getEllipticCurve().getN())).mod(this.getEllipticCurve().getN());
		sStringBuffer.append(s+" ");
		String xHash = "SHA(x)";
		if (Client.ASCII_FLAG) xHash = "h(x)";
		System.out.println("["+name+"]: s <congruent> (("+xHash+"+d*r)*(ephemeralKey^(-1))) mod n = "+s);
		return sStringBuffer;
	}
	private BigInteger pickupSigningKey(BufferedReader bR, int base) {
		BigInteger signingKey = null;
		while (true) {
			try {
				System.out.println("[system]: enter key d to sign message where 0<d<n");
				signingKey = new BigInteger(bR.readLine(), base);
				if (signingKey.compareTo(EllipticCurve.ZERO) > 0 && ellipticCurve.getN().compareTo(signingKey) > 0) break;
				else System.out.println("[system]: usage ==> 0 < d < n");
			} catch (Exception e) { System.out.println("[system]: invalid entry.");}
		}
		return signingKey;
	}
	private void sendSignedMessage(String x, BigInteger r, StringBuffer sStringBuffer, int base) {
		StringWriter sW = new StringWriter();
		Json.createWriter(sW).writeObject(Json.createObjectBuilder()
								              .add("name", name)
								              .add("x", x)
								              .add("r", r.toString())
								              .add("s", sStringBuffer.toString()).build());
		System.out.println("["+name+"]: send "+ sW.toString());
		printWriter.println(sW);
	}
	private StringBuffer handleMessageHashing(String message, int base) throws NoSuchAlgorithmException {
		StringBuffer xStringBuffer = new StringBuffer();
		if (!Client.ASCII_FLAG) {
			String xString = Client.hashMessage(message, "SHA-256");
			System.out.println("["+name+"]: SHA(x) = "+xString);
			IntStream.range(0, xString.length()).forEach( index -> 
				xStringBuffer.append((xString.charAt(index)) + ""));
		} else {
			String[] xStringTokens = message.split(" ");
			IntStream.range(0, xStringTokens.length).forEach(index -> {
				new Integer(xStringTokens[index]);
				xStringBuffer.append(xStringTokens[index] + " ");
			});
		}
		return xStringBuffer;
	}
	private BigInteger pickupEphemeralKey(BufferedReader bR, int base) {
		BigInteger ephemeralKey = null;
		while (true) {
			try {
				System.out.println("[system]: choose ephemeralKey such that 0<ephemeralKey<n ");
				ephemeralKey = new BigInteger(bR.readLine(), base);
				if (ephemeralKey.compareTo(EllipticCurve.ZERO) > 0 && ellipticCurve.getN().compareTo(ephemeralKey) > 0) break;
				else System.out.println("[system]: usage ==> 0 < ephemeralKey < n");
			} catch (Exception e) { System.out.println("[system]: invalid entry.");}
		}
		return ephemeralKey;
	}
	static String hashMessage(String message, String algorithm) throws NoSuchAlgorithmException {
		StringBuffer stringBuffer = new StringBuffer();
		MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
		messageDigest.update(message.getBytes());
		byte byteData[] = messageDigest.digest();
		IntStream.range(0, byteData.length).forEach(i -> 
				stringBuffer.append(Integer.toString((byteData[i] & 0xff) +0x100).substring(1)));
		return stringBuffer.toString();
	}
	private void initDomainParams(StringWriter sW, BufferedReader bR, int base) throws IOException {
		prompt = new String("[system]: enter name");
		System.out.println(prompt);
		String[] values = bR.readLine().split(" ");
		name = values[0];
		if (this.getEllipticCurve() == null) {
			ellipticCurve = handleEllipticCurveInput(bR, base);
			while (true) {
				try {
					prompt = new String("[system]: enter Generator Point A's x & y coordinates, or e:xit");
					System.out.println(prompt);
					String[] input = bR.readLine().split(" ");
					if (input[0].equalsIgnoreCase("e")) System.exit(0);
					Point pointA = new Point(new BigInteger(input[0], base), new BigInteger(input[1], base));
					if (ellipticCurve.isPointOnCurve(pointA)) {
						this.pointA = pointA;
						break;
					} else System.out.println("[system]: point A not on curve");
				} catch(Exception e) {System.out.println("[system]: invalid entry.");}
			}
		}
	}
	private void calcPublicKey(StringWriter sW, BufferedReader bR, int base) throws IOException {
		while (true) {
			try {
				prompt = new String("[system]: pick secret # d from set {2, ..., "+
			                       ellipticCurve.getN().subtract(EllipticCurve.ONE).toString(BASE)+"}");
				System.out.println(prompt);
				privateKey = new BigInteger(bR.readLine(), base);
				if (privateKey.compareTo(EllipticCurve.ZERO) > 0 && ellipticCurve.getN().compareTo(privateKey) > 0) break;
				else System.out.println("[system]: usage ==> 0 < d < n");
			} catch(Exception e) {System.out.println("[system]: invalid entry.");}
		}
		Point pointB = ellipticCurve.fastMultiply(privateKey, pointA);
		System.out.print("["+name+"]: calculate & send public key B = ");
		System.out.print("dA = ");
		System.out.print(privateKey.toString(base) +""+ pointA.toString(base) + " = ");
		System.out.println(pointB.toString(base));
		Json.createWriter(sW).writeObject(Json.createObjectBuilder() 
					         .add("name", name)
							 .add("a", ellipticCurve.getA().toString())
							 .add("b", ellipticCurve.getB().toString())
							 .add("p", ellipticCurve.getP().toString())
							 .add("n", ellipticCurve.getN().toString())
							 .add("h", ellipticCurve.getH().toString())
							 .add("GeneratorX", pointA.getX().toString())
							 .add("GeneratorY", pointA.getY().toString())
							 .add("PublicKeyX", pointB.getX().toString())
					         .add("PublicKeyY", pointB.getY().toString())
					         .build());
		printWriter.println(sW);
	}
	EllipticCurve handleEllipticCurveInput(BufferedReader bufferedReader, int base) {
		EllipticCurve returnValue = null;
		boolean flag = true;
		while (flag) {
			try { 
				boolean inputFlag = true;
				while (inputFlag) {
					prompt = new String("[system]: enter a, b, p, n, h (E: y^2 <congruent> x^3 + ax + b mod p), or e:xit");
					System.out.println(prompt);
					String[] input = bufferedReader.readLine().split(" ");
					if (input[0].equalsIgnoreCase("e")) System.exit(0);
					BigInteger a = new BigInteger(input[0], base); 
					BigInteger b = new BigInteger(input[1], base); 
					BigInteger p = new BigInteger(input[2], base); 
					BigInteger n = new BigInteger(input[3], base); 
					BigInteger h = new BigInteger(input[4], base);
					if (EllipticCurve.isNonsingular(a, b)) {
						if (p.compareTo(EllipticCurve.THREE)> 0) {
							returnValue = new EllipticCurve(a, b, p, n, h);
							inputFlag = false;
						} else System.out.println("[system]: usage ==> p > 3");
					} else System.out.println("[system]: invalid entry (singular elliptic curve)");
				}
				flag = false;
			} catch (Exception e) {
				System.out.println("invalid entry (usage: a b p where E: y^2 <congruent> x^3 + ax + b mod p)");
			}
		}
		return returnValue;
	}
	public String getPrompt() { return prompt; }
	public String getName() { return name; }
	public BigInteger getPrivateKey() { return privateKey;} 
	public Point getGeneratorPoint() { return pointA; }
	public Point getOtherPartyPublicKeyPoint() { return otherPartyPointB; }
	public EllipticCurve getEllipticCurve() { return ellipticCurve; }
	public EllipticCurve getOtherPartyEllipticCurve() { return otherPartyEllipticCurve; }
	public String getOtherPartyName() { return otherPartyName; }
	public Point getOtherPartyGeneratorPoint() { return otherPartyPointA; }
	public void setOtherPartyName(String otherPartyName) { this.otherPartyName = otherPartyName; }
	public void setOtherPartyEllipticCurve(EllipticCurve otherPartyEllipticCurve) {this.otherPartyEllipticCurve = otherPartyEllipticCurve; }
	public void setOtherPartyPublicKeyPoint(Point otherPartyPublicKeyPoint) { this.otherPartyPointB = otherPartyPublicKeyPoint; }
	public void setOtherPartyGeneratorPoint(Point otherPartyGeneratorPoint) { this.otherPartyPointA = otherPartyGeneratorPoint; }
}
