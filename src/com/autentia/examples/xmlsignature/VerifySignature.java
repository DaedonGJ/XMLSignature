package com.autentia.examples.xmlsignature;

import java.io.File;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class VerifySignature {

	public static void main(String[] args) throws Exception {
		org.apache.xml.security.Init.init();
		String signatureFileName = "signature.xml";
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

		File f = new File(signatureFileName);
		DocumentBuilder db = dbf.newDocumentBuilder();

		Document doc = db.parse(new java.io.FileInputStream(f));
		Element sigElement = (Element) doc.getElementsByTagName("Signature").item(0);
		XMLSignature signature = new XMLSignature(sigElement, f.toURL().toString());

		KeyInfo keyInfo = signature.getKeyInfo();
		if (keyInfo != null) {
			X509Certificate cert = keyInfo.getX509Certificate();
			if (cert != null) {
				// Validamos la firma usando un certificado X509
				if (signature.checkSignatureValue(cert)) {
					System.out.println("Válido según el certificado");
				} else {
					System.out.println("Inválido según el certificado");
				}
			} else {
				// No encontramos un Certificado intentamos validar por la cláve pública
				PublicKey pk = keyInfo.getPublicKey();
				if (pk != null) {
					// Validamos usando la clave pública
					if (signature.checkSignatureValue(pk)) {
						System.out.println("Válido según la clave pública");
					} else {
						System.out.println("Inválido según la clave pública");
					}
				} else {
					System.out.println("No podemos validar, tampoco hay clave pública");
				}
			}
		} else {
			System.out.println("No ha sido posible encontrar el KeyInfo");
		}
	}

}
