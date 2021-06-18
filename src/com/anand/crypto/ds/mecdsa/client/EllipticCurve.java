package com.anand.crypto.ds.mecdsa.client;
import java.math.BigInteger;
public class EllipticCurve {
	static final BigInteger ZERO = BigInteger.ZERO;
	static final BigInteger ONE = BigInteger.ONE;
	static final BigInteger TWO = new BigInteger("2");
	static final BigInteger THREE = new BigInteger("3");
	static final BigInteger FOUR = new BigInteger("4");
	static final BigInteger TWENTY_SEVEN = new BigInteger("27");
	private BigInteger a, b, p, n, h, orderE;
	public EllipticCurve(BigInteger a, BigInteger b, BigInteger p, BigInteger n, BigInteger h) {
		this.a = a; this.b = b; this.p = p; this.h = h;
		this.n = n; this.orderE = h.multiply(n);
	}
	public Point fastMultiply(BigInteger d, Point pointG) {
		Point pointT = new Point(pointG.getX(), pointG.getY());
		String dInBinary = d.toString(2);
		for (int i = 1; i < dInBinary.length(); i++) {
			int bit = Integer.parseInt(dInBinary.substring(i, i + 1));
			pointT = duoble(pointT);
			if (bit == 1) pointT = add(pointG,pointT);
		}
		return pointT;
	}
	public Point add(Point pointG, Point pointQ) {
		Point returnPoint = null;
		if (pointG.equals(pointQ)) returnPoint = duoble(pointG);
		else if(pointG.equals(Point.POINT_AT_INFINITY)) returnPoint = pointQ;
		else if(pointQ.equals(Point.POINT_AT_INFINITY)) returnPoint = pointG;
		else if(isInverse(pointG, pointQ)) returnPoint = Point.POINT_AT_INFINITY;
		else {
			BigInteger s = pointQ.getY().subtract(pointG.getY()).mod(p).multiply((pointQ.getX().subtract(pointG.getX())).modInverse(p));
			BigInteger pointRx = s.multiply(s).subtract(pointG.getX()).subtract(pointQ.getX()).mod(p);
			BigInteger pointRy = (s.multiply(pointG.getX().subtract(pointRx))).subtract(pointG.getY()).mod(p);
			returnPoint = new Point(pointRx, pointRy);
		}
		return returnPoint;
	}
	private Point duoble(Point pointG) {
		Point returnPoint = null;
		if(pointG.equals(Point.POINT_AT_INFINITY)) returnPoint = pointG;
		else {
			BigInteger s = (THREE.multiply(pointG.getX().modPow(TWO,p)).add(a)).mod(p).multiply(TWO.multiply(pointG.getY()).modInverse(p));
			BigInteger pointRx = s.multiply(s).subtract(pointG.getX()).subtract(pointG.getX()).mod(p);
			BigInteger pointRy = (s.multiply(pointG.getX().subtract(pointRx))).subtract(pointG.getY()).mod(p);
			returnPoint = new Point(pointRx, pointRy);
		}
		return returnPoint;
	}
	private boolean isInverse(Point pointG, Point pointT){
		return (p.compareTo(pointT.getY().add(pointG.getY()))== 0 && pointG.getX().compareTo(pointT.getX()) == 0);
	}
	public boolean isPointOnCurve(Point pointG){
		return pointG.getY().multiply(pointG.getY()).mod(p).equals(
			  (pointG.getX().multiply(pointG.getX()).multiply(pointG.getX())).add((a.multiply(pointG.getX())).add(b)).mod(p));
	}
	static public boolean isNonsingular(BigInteger a, BigInteger b) {
		return !(FOUR.multiply(a.multiply(a).multiply(a)).add((TWENTY_SEVEN.multiply(b.multiply(b))))).equals(ZERO);
	}
	public BigInteger getA() { return a; }
	public BigInteger getB() { return b; }
	public BigInteger getP() { return p; }
	public BigInteger getN() { return n; }
	public BigInteger getH() { return h; }
	public BigInteger getOrderE() { return orderE; }
	public String toString() {return "E: y^2 <congruent> x^3 + "+a+"x + "+b + " mod "+p;}
}
