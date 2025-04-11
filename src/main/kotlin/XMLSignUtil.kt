import java.io.FileInputStream
import java.security.Key
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.xml.crypto.dsig.*
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.keyinfo.KeyInfo
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory
import javax.xml.crypto.dsig.keyinfo.X509Data
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec
import javax.xml.crypto.dsig.spec.TransformParameterSpec
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import org.w3c.dom.NodeList
import org.xml.sax.InputSource
import java.io.StringReader
import java.io.StringWriter
import javax.xml.transform.OutputKeys

fun resign(soapXmlBodyInput: String, pfxPath: String = "${System.getProperty("user.home")}/Documents/cert.pfx", pfxPassword: String = "privatekey") : String {


    //val pfxPath = "${System.getProperty("user.home")}/Documents/cert.pfx"
    //val pfxPassword: String = "privatekey"

    // Load the PFX keystore
    val keyStore: KeyStore = KeyStore.getInstance("PKCS12")
    val pfxInputStream: FileInputStream = FileInputStream(pfxPath)
    keyStore.load(pfxInputStream, pfxPassword.toCharArray())

    val aliasEnum: java.util.Enumeration<String> = keyStore.aliases()
    val alias: String = aliasEnum.toList().first()

    val key: Key = keyStore.getKey(alias, pfxPassword.toCharArray())
    val privateKey: PrivateKey = key as PrivateKey
    val certificate: X509Certificate = keyStore.getCertificate(alias) as X509Certificate

    // Parse the SOAP request XML
    val documentBuilderFactory: DocumentBuilderFactory = DocumentBuilderFactory.newInstance()
    documentBuilderFactory.isNamespaceAware = true

    val documentBuilder: DocumentBuilder = documentBuilderFactory.newDocumentBuilder()
    val soapDocument: Document = documentBuilder.parse(InputSource(StringReader(soapXmlBodyInput.trimMargin())))

    // Prepare XMLSignatureFactory
    val signatureFactory: XMLSignatureFactory = XMLSignatureFactory.getInstance("DOM")

    val canonicalizationMethod: CanonicalizationMethod = signatureFactory.newCanonicalizationMethod(
        CanonicalizationMethod.EXCLUSIVE,
        null as C14NMethodParameterSpec?
    )
    val signatureMethod: SignatureMethod = signatureFactory.newSignatureMethod(
        SignatureMethod.RSA_SHA256,
        null
    )
    val digestMethod: DigestMethod = signatureFactory.newDigestMethod(
        DigestMethod.SHA256,
        null
    )

    val transformList: List<Transform> = listOf(
        //signatureFactory.newTransform(Transform.ENVELOPED, null as TransformParameterSpec?),
        signatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, null as TransformParameterSpec?)
    )

    val reference: Reference = signatureFactory.newReference(
        "#Body",
        digestMethod,
        transformList,
        null,
        null
    )

    val signedInfo: SignedInfo = signatureFactory.newSignedInfo(
        canonicalizationMethod,
        signatureMethod,
        listOf(reference)
    )

    val keyInfoFactory: KeyInfoFactory = signatureFactory.keyInfoFactory
    val x509Content: List<Any> = listOf(certificate.subjectX500Principal.name, certificate)
    val x509Data: X509Data = keyInfoFactory.newX509Data(x509Content)
    val keyInfo: KeyInfo = keyInfoFactory.newKeyInfo(listOf(x509Data))

    // Find the Signature element
    val signatureNodeList: NodeList = soapDocument.getElementsByTagNameNS(
        "http://www.w3.org/2000/09/xmldsig#",
        "Signature"
        //"http://schemas.xmlsoap.org/soap/security/2000-12",
        //"Signature"

    )

    val signatureNode: Node = signatureNodeList.item(0)
    val signatureParentNode: Node = signatureNode.parentNode

    // Ensure Body has ID attribute
    val bodyNodeList: NodeList = soapDocument.getElementsByTagName("s:Body")
    val bodyElement: Element = bodyNodeList.item(0) as Element
    bodyElement.setAttribute("Id", "Body")

    val domSignContext: DOMSignContext = DOMSignContext(privateKey, signatureParentNode, signatureNode)
    domSignContext.setIdAttributeNS(bodyElement, null, "Id")

    //val xmlSignature: XMLSignature = signatureFactory.newXMLSignature(signedInfo, keyInfo)
    val xmlSignature: XMLSignature = signatureFactory.newXMLSignature(signedInfo, null)
    xmlSignature.sign(domSignContext)

    val transformerFactory: TransformerFactory = TransformerFactory.newInstance()
    val transformer: Transformer = transformerFactory.newTransformer()
    //transformer.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes")
    //transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
    //val outputFile: File = File("path/to/updated-soap.xml")
    val outputFile = StringWriter()
    transformer.transform(DOMSource(soapDocument), StreamResult(outputFile))

    //println(outputFile.toString())
    return outputFile.toString()
    //println("XML Signature regenerated and saved to ${outputFile.absolutePath}")
}

fun prettyPrintXmlString(xml: String): String {
    val documentBuilder = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) // Security
    }.newDocumentBuilder()

    val document = documentBuilder.parse(InputSource(StringReader(xml)))

    val transformer = TransformerFactory.newInstance().newTransformer().apply {
        setOutputProperty(OutputKeys.INDENT, "yes")
        setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
        setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no")
    }

    val writer = StringWriter()
    transformer.transform(DOMSource(document), StreamResult(writer))
    return writer.toString()
}