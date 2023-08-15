using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace TlsSslStreamRabbitMq
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            try
            {
                string serverAddress = "lab12app2.mel.labts.net"; // Change to your server's IP address or hostname
                int serverPort = 5671; // Change to your server's port
                string certificatePath = @"C:\\OHS\\certs\\\newlabtswildcard.p12"; // Change to the path of your certificate file
                string certificatePassword = "changeit"; // Change to your certificate password
                Console.WriteLine($"{serverAddress} \n {serverPort} \n {certificatePath} \n");
                TcpClient client = new TcpClient();
                await client.ConnectAsync(serverAddress, serverPort);

                X509Certificate2 clientCertificate = new X509Certificate2(certificatePath, certificatePassword);
                X509Chain chain = new X509Chain();
                chain.Build(clientCertificate);

                foreach (X509ChainElement element in chain.ChainElements)
                {
                    Console.WriteLine($"Element Info Thumbprint: {element.Certificate.Thumbprint} \n Friendly Name: {element.Certificate.FriendlyName} \n Issuer: {element.Certificate.Issuer} \n Subject {element.Certificate.SubjectName.Name} \n Expiration {element.Certificate.GetExpirationDateString()} ");
                    Console.WriteLine("\n \n ");
                }
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    Console.WriteLine("Chain status: " + status.Status);
                    Console.WriteLine("Chain status information: " + status.StatusInformation + "\n \n \n");
                }

                using SslStream sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate, null);

                //(sender, certificate, chain, errors) => true))
                {
                    try
                    {
                        await sslStream.AuthenticateAsClientAsync(serverAddress, new X509CertificateCollection() { clientCertificate }, SslProtocols.Tls12, false);

                        // Now you can use the sslStream to read and write data securely
                        // For example, you can use StreamReader and StreamWriter to work with text data

                        using (StreamWriter writer = new StreamWriter(sslStream))
                        {
                            await writer.WriteLineAsync("Hello, Server!");
                            await writer.FlushAsync();
                        }

                        using (StreamReader reader = new StreamReader(sslStream))
                        {
                            string response = await reader.ReadLineAsync();
                            Console.WriteLine("Server response: " + response);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Exception Message {ex.Message} \n Inner Exception {ex.InnerException} \n Stack Trace {ex.StackTrace}  ");
                    }
                }

                client.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception Message {ex.Message} \n Inner Exception {ex.InnerException}  ");
            }


        }

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                // No errors, certificate is valid
                Console.WriteLine("Certificate is Valid " + sslPolicyErrors);
                return true;
            }

            Console.WriteLine("Certificate validation error: " + sslPolicyErrors);

            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                Console.WriteLine("Chain status: " + status.Status);
                Console.WriteLine("Chain status information: " + status.StatusInformation);
            }

            // You can customize the validation logic here based on your requirements
            // Returning true means the certificate is considered valid despite errors
            // Returning false means the certificate is considered invalid
            return true;
        }
    }
}
