package com.anand.crypto.ds.mecdsa.client;
import java.math.BigInteger;
public class Point {
	static BigInteger INFINITY = new BigInteger("999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999");
	static Point POINT_AT_INFINITY = new Point(EllipticCurve.ZERO, INFINITY);
	private BigInteger x;
	private BigInteger y;
	public Point(BigInteger x, BigInteger y) { this.x = x; this.y = y; }
	public BigInteger getX() { return x; }
	public BigInteger getY() { return y; }
	public boolean equals(Object object) {
		Point point = (Point)object;
		boolean flag = false;
		if (this.getY().equals(point.getY()) && this.getY().equals(INFINITY)) flag = true;
		else if (this.getX().equals(point.getX()) && this.getY().equals(point.getY()) ) flag = true;
		return flag;
	}
	public String toString() {
		String returnValue = "(" + x +", "+y+")"; 
		if (y.equals(INFINITY)) returnValue = " O           ";
		return returnValue;
	}
	public String toString(int base) {
		String returnValue = "";
		returnValue = "(" + x.toString(base) +", "+y.toString(base)+")"; 
		if (y.equals(INFINITY)) returnValue = " O           ";
		return returnValue;
	}
}
