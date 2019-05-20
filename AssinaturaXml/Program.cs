using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AssinaturaXml
{
    class Program
    {
        static void Main(string[] args)
        {
            string certificadoFile = @"D:\DOCUMENTOS\CERTIFICADOS\51\12345678 DPL.pfx";
            string certificadoSenha = "12345678";
            string arquivoXML = @"C:\nfse\33-env-loterps.xml";

            var assinar = new AssinaturaDigital(arquivoXML, certificadoFile, certificadoSenha);

            assinar.Assinar();

            Console.WriteLine("XML Assinado!");

            Console.ReadKey();
        
                                          
        }

    }
}
