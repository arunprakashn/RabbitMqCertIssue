using Microsoft.Extensions.Configuration;
using RabbitMQ.Client;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace RabbitMqCertCheck
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                // Load configuration from appsettings.json
                var configuration = new ConfigurationBuilder()
                    //.SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json")
                    .Build();

                // Get RabbitMQ configuration values from appsettings.json
                var rabbitMqConfig = configuration.GetSection("RabbitMQConfig");
                string rabbitMqHostname = rabbitMqConfig["Hostname"];
                int rabbitMqPort = int.Parse(rabbitMqConfig["Port"]);
                string rabbitMqUsername = rabbitMqConfig["Username"];
                string rabbitMqPassword = rabbitMqConfig["Password"];
                string certificatePath = rabbitMqConfig["CertificatePath"];
                string certificatePassphrase = rabbitMqConfig["CertificatePassphrase"];
                string virtualHost = rabbitMqConfig["VirtualHost"];
                string thumbprint = rabbitMqConfig["ThumbPrint"];

                
                Console.WriteLine($"{configuration.GetDebugView()}");

                // Create the RabbitMQ connection factory
                var factory = new ConnectionFactory
                {

                    Port = rabbitMqPort,
                    UserName = null,
                    Password = null,

                    Ssl = new SslOption
                    {
                        //Certs = new X509CertificateCollection { GetCertificate(thumbprint) },
                        Enabled = true,
                        ServerName = rabbitMqHostname,
                        CertPath = certificatePath,
                        CertPassphrase = certificatePassphrase,
                        //AcceptablePolicyErrors = SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNotAvailable,
                        Version = SslProtocols.Tls12 // Adjust the SSL protocol version if needed

                    }
                };


                factory.HostName = rabbitMqHostname;

                factory.VirtualHost = virtualHost;
                //RequestedChannelMax = 5000,

                factory.AuthMechanisms = new IAuthMechanismFactory[] { new ExternalMechanismFactory() };

                // Create the RabbitMQ connection
                using (var connection = factory.CreateConnection())
                {
                    Console.WriteLine("CreateConnection statement crossed");
                    // Create channel and perform RabbitMQ operations
                    using (var channel = connection.CreateModel())
                    {
                        Console.WriteLine("Inside Create Model");
                        // Your RabbitMQ operations go here
                        // For example, you can publish or consume messages
                        // Refer to RabbitMQ .NET SDK documentation for more details
                        // https://www.rabbitmq.com/dotnet-api-guide.html
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message + "   " + ex.StackTrace + ex.InnerException);
            }
        }

        public static X509Certificate2 GetCertificate(string thumbprint)
        {
            // strip any non-hexadecimal values and make uppercase
            thumbprint = Regex.Replace(thumbprint, @"[^\da-fA-F]", string.Empty).ToUpper();
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                store.Open(OpenFlags.ReadOnly);

                var certCollection = store.Certificates;
                var signingCert = certCollection.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (signingCert.Count == 0)
                {
                    throw new FileNotFoundException(string.Format("Cert with thumbprint: '{0}' not found in local machine cert store.", thumbprint));
                }
                else
                {
                    Console.WriteLine("Cert:" + signingCert[0].Issuer + "\n " + "\n \n \n");
                }

                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}