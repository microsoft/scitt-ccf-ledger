namespace dotnetctscli;

using System.Formats.Cbor;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure;
using Azure.Core.Pipeline;
using Azure.Security.CodeTransparency;
using Azure.Security.CodeTransparency.Receipt;

/// <summary>
/// The main entry point of this script which will be executed in the python test.
/// </summary>
class Program
{
    private const string OperationSubmit = "submit";
    private const string OperationVerify = "verify";
    private const string EndpointArgument = "--endpoint";
    private const string CaCertificateArgument = "--ca-certificate";


    static void Main(string[] args)
    {
        ParsedArguments parsedArguments = ParseArguments(args);

        string operationArgumentValue = parsedArguments.Operation;
        if (operationArgumentValue != OperationSubmit && operationArgumentValue != OperationVerify)
        {
            Console.WriteLine($"First argument must be the operation name, one of [{OperationSubmit}, {OperationVerify}], got {{{ operationArgumentValue }}}");
            throw new ArgumentException("Invalid operation name");
        }

        Uri? endpoint = parsedArguments.Endpoint;
        string? caCertificatePath = parsedArguments.CaCertificatePath;

        if (endpoint is not null)
        {
            Console.WriteLine($"Using endpoint {{{endpoint}}}");
        }
        if (caCertificatePath is not null)
        {
            Console.WriteLine($"Using CA certificate {{{caCertificatePath}}}");
        }

        Console.WriteLine("Reading the input file...");
        using FileStream fileStream = File.OpenRead(parsedArguments.InputPath);
        BinaryData content = BinaryData.FromStream(fileStream);

        if (operationArgumentValue == OperationSubmit)
        {
            Uri submitEndpoint = endpoint ?? throw new ArgumentException(
                $"Command line argument {EndpointArgument} must be set when {OperationSubmit} is called");
            CodeTransparencyClientOptions options = new();
            // For non-prod endpoints, we expect the identity service to be running in the same environment and can be reached via the same endpoint.
            Uri? resolvedIdentityEndpoint = ResolveDefaultIdentityEndpoint(submitEndpoint);
            if (resolvedIdentityEndpoint is not null)
            {
                options.IdentityClientEndpoint = resolvedIdentityEndpoint.ToString();
            }
            if (caCertificatePath is not null)
            {
                options.Transport = CreateHttpClientTransport(caCertificatePath);
            }
            CodeTransparencyClient client = new CodeTransparencyClient(submitEndpoint, options);

            Console.WriteLine("Sending the signature...");
            Operation<BinaryData> operationResult = client.CreateEntry(WaitUntil.Completed, content);
            string entryId = CborUtils.GetStringValueFromCborMapByKey(operationResult.Value.ToArray(), "EntryId");

            Console.WriteLine($"Waiting for the transparent statement...");
            Response<BinaryData> transparentStatement = client.GetEntryStatement(entryId);
            if (transparentStatement.GetRawResponse().Status != 200)
            {
                Console.WriteLine($"Get transparent statement did not succeed {transparentStatement.GetRawResponse().Status}");
                throw new Exception($"Get transparent statement did not succeed {transparentStatement.GetRawResponse().Status}");
            }

            BinaryData signatureWithReceipt = transparentStatement.Value;
            Console.WriteLine($"Writing the receipt bytes {{{signatureWithReceipt.ToMemory().Length}}} to {{{parsedArguments.OutputPath}}}");
            File.WriteAllBytes(parsedArguments.OutputPath!, signatureWithReceipt.ToArray());
        }
        else if (operationArgumentValue == OperationVerify)
        {
            Console.WriteLine("Verifying...");
            byte[] transparentStatementBytes = content.ToArray();
            var verificationOptions = new CodeTransparencyVerificationOptions
            {
                AuthorizedDomains = new string[] {
                    "127.0.0.1:8000",
                    "localhost:8000",
                    endpoint?.Host ?? throw new ArgumentException($"Command line argument {EndpointArgument} must be set when verify is called") },

                AuthorizedReceiptBehavior = AuthorizedReceiptBehavior.VerifyAllMatching,
                UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
            };
            CodeTransparencyClientOptions clientOptions = new();
            if (caCertificatePath is not null)
            {
                clientOptions.Transport = CreateHttpClientTransport(caCertificatePath);
            }
            CodeTransparencyClient.VerifyTransparentStatement(transparentStatementBytes, verificationOptions, clientOptions);
            Console.WriteLine("Verification succeeded: The statement was registered in the immutable ledger.");
        }

        Console.WriteLine("Done");
    }

    private static ParsedArguments ParseArguments(string[] args)
    {
        List<string> positionals = new();
        Uri? endpoint = null;
        string? caCertificatePath = null;

        for (int index = 0; index < args.Length; index++)
        {
            string argument = args[index];

            if (argument == EndpointArgument)
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {EndpointArgument}");
                }

                endpoint = ParseAbsoluteUri(args[++index], EndpointArgument);
                continue;
            }

            if (argument == CaCertificateArgument)
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {CaCertificateArgument}");
                }

                caCertificatePath = args[++index];
                continue;
            }

            if (argument.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unknown command line argument {{{argument}}}");
            }

            positionals.Add(argument);
        }

        string operation = positionals.Count < 1 ? "nothing" : positionals[0];
        if (positionals.Count < 2)
        {
            Console.WriteLine("Second argument must be a path to the input file");
            throw new ArgumentException("Missing input file path");
        }

        string inputPath = positionals[1];
        string? outputPath = null;

        if (operation == OperationSubmit)
        {
            if (positionals.Count < 3)
            {
                Console.WriteLine("Third argument must be a path to the output file");
                throw new ArgumentException("Missing output file path");
            }

            outputPath = positionals[2];

            if (positionals.Count > 3)
            {
                throw new ArgumentException("Too many positional arguments for submit");
            }
        }
        else if (operation == OperationVerify && positionals.Count > 2)
        {
            throw new ArgumentException("Too many positional arguments for verify");
        }

        return new ParsedArguments(operation, inputPath, outputPath, endpoint, caCertificatePath);
    }

    private static HttpClientTransport CreateHttpClientTransport(string caCertificatePath)
    {
        X509Certificate2 trustedCertificate = LoadCertificate(caCertificatePath);
        HttpClientHandler handler = new()
        {
            ServerCertificateCustomValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                ValidateServerCertificate(certificate, trustedCertificate, sslPolicyErrors),
        };

        return new HttpClientTransport(new HttpClient(handler));
    }

    private static X509Certificate2 LoadCertificate(string certificatePath)
    {
        byte[] rawBytes = File.ReadAllBytes(certificatePath);
        string certificateText = Encoding.ASCII.GetString(rawBytes);

        return certificateText.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal)
            ? X509Certificate2.CreateFromPem(certificateText)
            : new X509Certificate2(rawBytes);
    }

    private static bool ValidateServerCertificate(
        X509Certificate2? certificate,
        X509Certificate2 trustedCertificate,
        SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is null)
        {
            return false;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        if (certificate.RawDataMemory.Span.SequenceEqual(trustedCertificate.RawDataMemory.Span))
        {
            return true;
        }

        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustedCertificate);
        chain.ChainPolicy.ExtraStore.Add(trustedCertificate);

        return chain.Build(certificate);
    }

    private static Uri ParseAbsoluteUri(string value, string argumentName)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? endpoint))
        {
            throw new ArgumentException($"Command line argument {argumentName} must be an absolute URI, got {{{value}}}");
        }

        return endpoint;
    }

    private static Uri? ResolveDefaultIdentityEndpoint(Uri endpoint)
    {
        // If transparent statement was issued in prod then rely on default pod endpoint
        if (endpoint.Host.EndsWith(".confidential-ledger.azure.com", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return endpoint;
    }

    private sealed class ParsedArguments(
        string operation,
        string inputPath,
        string? outputPath,
        Uri? endpoint,
        string? caCertificatePath)
    {
        public string Operation { get; } = operation;
        public string InputPath { get; } = inputPath;
        public string? OutputPath { get; } = outputPath;
        public Uri? Endpoint { get; } = endpoint;
        public string? CaCertificatePath { get; } = caCertificatePath;
    }
}
