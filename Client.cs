using System;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using Opc.Ua.Client;
using System.IO;

class Program
{
    
    private async Task<object> ReadVariableAsync(Session session, NodeId nodeId, CancellationToken cancellationToken = default)
    {
        // Read the value using the 'ReadAsync' method
        ReadValueId readValueId = new ReadValueId { NodeId = nodeId, AttributeId = Attributes.Value };

        // Use await directly on the ReadAsync method and pass the CancellationToken
        ReadResponse readResponse = await session.ReadAsync(
            null,
            0,
            TimestampsToReturn.Both,
            new[] { readValueId },
            cancellationToken
        );

        // Check if the read was successful
        if (readResponse != null && readResponse.Results != null && readResponse.Results.Count > 0 && StatusCode.IsGood(readResponse.Results[0].StatusCode))
        {
            Console.WriteLine($"Value of MyVariable: {readResponse.Results[0].Value}");
            return readResponse.Results[0].Value;
        }
        else
        {
            Console.WriteLine("Failed to read the variable value.");
            return false;
        }

    }

    private async Task<bool> WriteVariableAsync(Session session, NodeId nodeId, object value, CancellationToken cancellationToken = default)
    {
        try
        {
            // Create a WriteValue object with the NodeId, AttributeId, and the value to be written
            WriteValue writeValue = new WriteValue
            {
                NodeId = nodeId,
                AttributeId = Attributes.Value,
                Value = new DataValue(new Variant(value)),
            };

            // Create an array of WriteValue objects
            WriteValueCollection writeValues = new WriteValueCollection
            {
                writeValue
            };

            // Use the WriteAsync method to write the value to the server
            WriteResponse writeResponse = await session.WriteAsync(
                null,
                writeValues,
                cancellationToken
            );

            // Check if the write was successful
            if (writeResponse != null && writeResponse.Results != null && writeResponse.Results.Count > 0
                && StatusCode.IsGood(writeResponse.Results[0]))
            {
                Console.WriteLine("Write operation successful.");
                return true;
            }
            else
            {
                Console.WriteLine($"Failed to write to the variable.");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during write operation: {ex.Message}");
            return false;
        }
    }


    static async Task Main()
    {

        // Define the endpoint URL of the OPC UA server
        string endpointUrl = "opc.tcp://10.149.251.100:4840";  

        // Define the credentials (username and password) for authentication
        string username = "Client1";
        string password = "545319";
        UserIdentity userIdentity = new UserIdentity(username, password);

        // Load the certificate from a file
        //X509Certificate2 certificate = new X509Certificate2(@"C:\CM FELCA\OpcCmfelca.der");
        string pfxFilePath = @"C:\CM FELCA\OpcCmfelca.pfx";
        string pfxPassword = "Jacopo2022!"; 

        X509Certificate2 certificate = new X509Certificate2(pfxFilePath, pfxPassword);


        // Create the OPC UA application configuration
        ApplicationConfiguration config = new ApplicationConfiguration
        {
            // Configure other settings as needed
            // ...
            ClientConfiguration = new ClientConfiguration
            {
                DefaultSessionTimeout = 60000,
            },

            // Set the user identity for authentication
            SecurityConfiguration = new SecurityConfiguration
            {
                ApplicationCertificate = new CertificateIdentifier 
                {   
                    //StoreType = "Directory", 
                    //StorePath = @"C:\Users\jacopo.pauletto\AppData\Roaming\unifiedautomation\uaexpert\PKI\trusted\certs", 
                    //SubjectName = "OPCUAServer@EA-06F413"
                    Certificate = certificate,
                },
                AutoAcceptUntrustedCertificates = true,
                RejectSHA1SignedCertificates = true, // Reject SHA-1 signed certificates
            },

        };




        // Create an OPC UA session with the server

        using (var session = await Session.Create(config, new ConfiguredEndpoint(null, new EndpointDescription(endpointUrl)), true, "", 60000, userIdentity, null))
        {
            // Now you can interact with the server using the 'session' object

            Program program = new Program();

            
            //Read a variable
            NodeId nodeId = NodeId.Parse("ns=4;s=168.33.100 .Application.Rx_from_Client.Order");

            var cancellationTokenSource = new CancellationTokenSource();
            var cancellationToken = cancellationTokenSource.Token;

            object value = await program.ReadVariableAsync(session, nodeId, cancellationToken);
