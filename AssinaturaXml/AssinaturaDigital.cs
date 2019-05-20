using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Security.Cryptography.Xml;

namespace AssinaturaXml
{
    public class AssinaturaDigital
    {
        public enum AlgorithmType
        {
            Sha1,
            Sha256
        }

        public string arqXMLAssinar { get; set; }
        public string certificado { get; set; }
        public string certificadoSenha { get; set; }

        public AssinaturaDigital(string arqXMLAssinar, string certificado, string certificadoSenha)
        {
            this.arqXMLAssinar = arqXMLAssinar;
            this.certificado = certificado;
            this.certificadoSenha = certificadoSenha;
        }

        public void Assinar()
        {
            XmlDocument conteudoXML = new XmlDocument();
            string tagAssinatura = "Rps";
            string tagAtributoId = "InfRps";
            X509Certificate2 x509Cert = null;
            AlgorithmType algorithmType = AlgorithmType.Sha1;
            bool bComURI = true;

            conteudoXML.PreserveWhitespace = true;
            
            //ATRIBUI O CERTIFICADO DIGITAL
            if (string.IsNullOrEmpty(certificado))
            {
                throw new Exception("Nome do arquivo referente ao certificado digital não foi informado nas configurações do UniNFe.");
            }
            else if (!string.IsNullOrEmpty(certificado) && !File.Exists(certificado))
            {
                throw new Exception(string.Format("Certificado digital \"{0}\" não encontrado.", certificado));
            }

            using (FileStream fs = new FileStream(certificado, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                x509Cert = new X509Certificate2(buffer, certificadoSenha);
            }
            

            if (string.IsNullOrEmpty(conteudoXML.InnerText))
            {
                conteudoXML = new XmlDocument();

                try
                {
                    conteudoXML.Load(arqXMLAssinar);
                }
                catch
                {
                    conteudoXML.LoadXml(File.ReadAllText(arqXMLAssinar, System.Text.Encoding.UTF8));
                }
            }

            Assina(conteudoXML, tagAssinatura, tagAtributoId, x509Cert, algorithmType, bComURI);

            try
            {
                // Atualizar a string do XML já assinada
                string StringXMLAssinado = conteudoXML.OuterXml;

                // Gravar o XML Assinado no HD
                StreamWriter SW_2 = File.CreateText(arqXMLAssinar);
                SW_2.Write(StringXMLAssinado);
                SW_2.Close();
            }
            catch
            {
                throw;
            }
        }

        private void Assina(XmlDocument conteudoXML,
            string tagAssinatura,
            string tagAtributoId,
            X509Certificate2 x509Cert,
            AlgorithmType algorithmType,
            bool comURI)
        {
            try
            {
                //if (x509Cert == null)
                //    throw new ExceptionCertificadoDigital(ErroPadrao.CertificadoNaoEncontrado);

                if (conteudoXML.GetElementsByTagName(tagAssinatura).Count == 0)
                {
                    throw new Exception("A tag de assinatura " + tagAssinatura.Trim() + " não existe no XML. (Código do Erro: 5)");
                }
                else if (conteudoXML.GetElementsByTagName(tagAtributoId).Count == 0)
                {
                    throw new Exception("A tag de assinatura " + tagAtributoId.Trim() + " não existe no XML. (Código do Erro: 4)");
                }
                // Existe mais de uma tag a ser assinada
                else
                {
                    XmlNodeList lists = conteudoXML.GetElementsByTagName(tagAssinatura);
                    XmlNode listRPS = null;

                    foreach (XmlNode nodes in lists)
                    {
                        foreach (XmlNode childNodes in nodes.ChildNodes)
                        {
                            if (!childNodes.Name.Equals(tagAtributoId))
                                continue;

                            // Create a reference to be signed
                            Reference reference = new Reference();
                            reference.Uri = "";

                            // pega o uri que deve ser assinada
                            XmlElement childElemen = (XmlElement)childNodes;

                            if (comURI)
                            {
                                if (childElemen.GetAttributeNode("Id") != null)
                                {
                                    reference.Uri = "#" + childElemen.GetAttributeNode("Id").Value;
                                }
                                else if (childElemen.GetAttributeNode("id") != null)
                                {
                                    reference.Uri = "#" + childElemen.GetAttributeNode("id").Value;
                                }
                            }

                            // Create a SignedXml object.
                            SignedXml signedXml = new SignedXml(conteudoXML);

#if _fw46
                            //A3
                            if (!String.IsNullOrEmpty(Empresas.Configuracoes[empresa].CertificadoPIN) &&
                                clsX509Certificate2Extension.IsA3(x509Cert) &&
                                !Empresas.Configuracoes[empresa].CertificadoPINCarregado)
                            {
                                x509Cert.SetPinPrivateKey(Empresas.Configuracoes[empresa].CertificadoPIN);
                                Empresas.Configuracoes[empresa].CertificadoPINCarregado = true;
                            }

                            if (algorithmType.Equals(AlgorithmType.Sha256))
                            {
                                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                                signedXml.SigningKey = x509Cert.GetRSAPrivateKey();
                            }
#endif

                            if (algorithmType.Equals(AlgorithmType.Sha1))
                            {
                                signedXml.SigningKey = x509Cert.PrivateKey;
                            }

                            // Add an enveloped transformation to the reference.
                            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                            reference.AddTransform(new XmlDsigC14NTransform());

                            // Add the reference to the SignedXml object.
                            signedXml.AddReference(reference);

#if _fw46
                            if (algorithmType.Equals(AlgorithmType.Sha256))
                            {
                                reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
                            }
#endif

                            // Create a new KeyInfo object
                            KeyInfo keyInfo = new KeyInfo();

                            // Load the certificate into a KeyInfoX509Data object
                            // and add it to the KeyInfo object.
                            keyInfo.AddClause(new KeyInfoX509Data(x509Cert));

                            // Add the KeyInfo object to the SignedXml object.
                            signedXml.KeyInfo = keyInfo;
                            signedXml.ComputeSignature();

                            // Get the XML representation of the signature and save
                            // it to an XmlElement object.
                            XmlElement xmlDigitalSignature = signedXml.GetXml();
                            
                            // Gravar o elemento no documento XML
                            nodes.AppendChild(conteudoXML.ImportNode(xmlDigitalSignature, true));

                        }
                    }
                }
            }            
            catch
            {
                throw;
            }
        }


    }
}
