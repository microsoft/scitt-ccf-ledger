namespace dotnetctscli;

using System.Collections.Concurrent;
using System.Formats.Cbor;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.CodeTransparency;

/// <summary>
/// The main entry point of this script which will be executed in the python test.
/// </summary>
class Program
{
    private const string OperationSubmit = "submit";
    private const string OperationVerify = "verify";
    private const string EndpointArgument = "--endpoint";
    private const string CaCertificateArgument = "--ca-certificate";
    private const string AsyncArgument = "--async";
    private const string SkipTransparentStatementArgument = "--skip-transparent-statement";
    private const string OperationLoad = "load";
    private const string ConcurrencyArgument = "--concurrency";
    private const string StatsFileArgument = "--stats-file";
    private const int DefaultLoadConcurrency = 10;


    static async Task Main(string[] args)
    {
        ParsedArguments parsedArguments = ParseArguments(args);

        string operationArgumentValue = parsedArguments.Operation;
        if (operationArgumentValue != OperationSubmit && operationArgumentValue != OperationVerify && operationArgumentValue != OperationLoad)
        {
            Console.WriteLine($"First argument must be the operation name, one of [{OperationSubmit}, {OperationVerify}, {OperationLoad}], got {{{ operationArgumentValue }}}");
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

        if (operationArgumentValue == OperationLoad)
        {
            await RunLoad(parsedArguments, endpoint, caCertificatePath);
            Console.WriteLine("Done");
            return;
        }

        Console.WriteLine("Reading the input file...");
        using FileStream fileStream = File.OpenRead(parsedArguments.InputPath);
        BinaryData content = BinaryData.FromStream(fileStream);

        if (operationArgumentValue == OperationSubmit)
        {
            Uri submitEndpoint = endpoint ?? throw new ArgumentException(
                $"Command line argument {EndpointArgument} must be set when {OperationSubmit} is called");
            CodeTransparencyClient client = CreateClient(submitEndpoint, caCertificatePath);

            Console.WriteLine(parsedArguments.UseAsync ? "Sending the signature (async)..." : "Sending the signature...");
            // CreateEntry (with waitForCommit) registers the statement and returns the
            // registration receipt. The entry id (registration transaction id) is
            // extracted directly from the receipt, which works whether the entry was
            // committed inline or via a 303 redirect (the Location header is not
            // preserved across the redirect).
            Response<BinaryData> receiptResponse = parsedArguments.UseAsync
                ? await client.CreateEntryAsync(content, true, default)
                : client.CreateEntry(content, true, default);
            BinaryData receipt = receiptResponse.Value;
            string entryId = CcfReceipt.GetRegistrationTransactionId(receipt.ToArray());

            if (parsedArguments.SkipTransparentStatement)
            {
                Console.WriteLine($"Skipping the transparent statement download for entry {{{entryId}}}");
            }
            else
            {
                Console.WriteLine($"Waiting for the transparent statement for entry {{{entryId}}}...");
                Response<BinaryData> transparentStatement = parsedArguments.UseAsync
                    ? await client.GetEntryStatementAsync(entryId)
                    : client.GetEntryStatement(entryId);
                if (transparentStatement.GetRawResponse().Status != 200)
                {
                    Console.WriteLine($"Get transparent statement did not succeed {transparentStatement.GetRawResponse().Status}");
                    throw new Exception($"Get transparent statement did not succeed {transparentStatement.GetRawResponse().Status}");
                }

                BinaryData signatureWithReceipt = transparentStatement.Value;
                Console.WriteLine($"Writing the receipt bytes {{{signatureWithReceipt.ToMemory().Length}}} to {{{parsedArguments.OutputPath}}}");
                File.WriteAllBytes(parsedArguments.OutputPath!, signatureWithReceipt.ToArray());
            }
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
        bool useAsync = false;
        bool skipTransparentStatement = false;
        int concurrency = DefaultLoadConcurrency;
        string? statsFile = null;

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

            if (argument == AsyncArgument)
            {
                useAsync = true;
                continue;
            }

            if (argument == SkipTransparentStatementArgument)
            {
                skipTransparentStatement = true;
                continue;
            }

            if (argument == ConcurrencyArgument)
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {ConcurrencyArgument}");
                }

                if (!int.TryParse(args[++index], out concurrency) || concurrency < 1)
                {
                    throw new ArgumentException($"{ConcurrencyArgument} must be a positive integer");
                }
                continue;
            }

            if (argument == StatsFileArgument)
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {StatsFileArgument}");
                }

                statsFile = args[++index];
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
            if (skipTransparentStatement)
            {
                // The output file only holds the downloaded transparent statement,
                // so it is neither required nor used when the download is skipped.
                if (positionals.Count > 2)
                {
                    throw new ArgumentException("Too many positional arguments for submit");
                }
            }
            else
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
        }
        else if (operation == OperationVerify && positionals.Count > 2)
        {
            throw new ArgumentException("Too many positional arguments for verify");
        }
        else if (operation == OperationLoad && positionals.Count > 2)
        {
            throw new ArgumentException("Too many positional arguments for load");
        }

        return new ParsedArguments(operation, inputPath, outputPath, endpoint, caCertificatePath, useAsync, skipTransparentStatement, concurrency, statsFile);
    }

    private static CodeTransparencyClient CreateClient(Uri endpoint, string? caCertificatePath)
    {
        // Cap the exponential backoff and reduce the number of retries so that
        // submissions fail fast rather than retrying for a long time under load.
        DelayStrategy aggressiveDelayStrategy = DelayStrategy.CreateExponentialDelayStrategy(
            TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(60));
        CodeTransparencyClientOptions options = new()
        {
            RetryPolicy = new RetryPolicy(maxRetries: 10, delayStrategy: aggressiveDelayStrategy),
        };
        // For non-prod endpoints, we expect the identity service to be running in
        // the same environment and can be reached via the same endpoint.
        Uri? resolvedIdentityEndpoint = ResolveDefaultIdentityEndpoint(endpoint);
        if (resolvedIdentityEndpoint is not null)
        {
            options.IdentityClientEndpoint = resolvedIdentityEndpoint.ToString();
        }
        if (caCertificatePath is not null)
        {
            options.Transport = CreateHttpClientTransport(caCertificatePath);
        }
        return new CodeTransparencyClient(endpoint, options);
    }

    /// <summary>
    /// Submits every *.cose statement found in the input directory concurrently
    /// using a single shared client. Reusing one client keeps the TLS
    /// connection, HTTP pipeline and JIT-compiled code warm across submissions,
    /// so the measured throughput reflects the service rather than per-process
    /// or per-connection startup overhead.
    /// </summary>
    private static async Task RunLoad(
        ParsedArguments parsedArguments, Uri? endpoint, string? caCertificatePath)
    {
        Uri loadEndpoint = endpoint ?? throw new ArgumentException(
            $"Command line argument {EndpointArgument} must be set when {OperationLoad} is called");

        string inputDirectory = parsedArguments.InputPath;
        if (!Directory.Exists(inputDirectory))
        {
            throw new ArgumentException(
                $"Load input path must be a directory, got {{{inputDirectory}}}");
        }

        string[] inputFiles = Directory.GetFiles(inputDirectory, "*.cose");
        if (inputFiles.Length == 0)
        {
            throw new ArgumentException(
                $"No .cose files found in {{{inputDirectory}}}");
        }

        int concurrency = parsedArguments.Concurrency;
        bool useAsync = parsedArguments.UseAsync;
        Console.WriteLine(
            $"Load test: submitting {inputFiles.Length} statements with concurrency " +
            $"{concurrency} ({(useAsync ? "async" : "sync")})...");

        CodeTransparencyClient client = CreateClient(loadEndpoint, caCertificatePath);

        using SemaphoreSlim gate = new(concurrency);
        int failures = 0;
        // Per-request latencies (ms) and per-second completion counts, collected
        // concurrently so the run can emit a stats summary similar to the locust
        // load test's JSON output.
        var latenciesMs = new ConcurrentBag<double>();
        var completionsPerSecond = new ConcurrentDictionary<long, int>();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        IEnumerable<Task> tasks = inputFiles.Select(async inputFile =>
        {
            await gate.WaitAsync();
            long startedMs = stopwatch.ElapsedMilliseconds;
            try
            {
                BinaryData body = BinaryData.FromBytes(
                    await File.ReadAllBytesAsync(inputFile));
                // Registration-only load: wait for commit but skip the
                // transparent statement download.
                if (useAsync)
                {
                    await client.CreateEntryAsync(body, true, default);
                }
                else
                {
                    // The synchronous SDK call blocks its thread until commit;
                    // offload to the thread pool so submissions still run
                    // concurrently (this trades an async continuation for a
                    // blocked pool thread per in-flight request).
                    await Task.Run(() => client.CreateEntry(body, true, default));
                }

                long finishedMs = stopwatch.ElapsedMilliseconds;
                latenciesMs.Add(finishedMs - startedMs);
                completionsPerSecond.AddOrUpdate(finishedMs / 1000, 1, (_, count) => count + 1);
            }
            catch (Exception e)
            {
                Interlocked.Increment(ref failures);
                Console.WriteLine($"Submission failed for {{{inputFile}}}: {e.Message}");
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);
        stopwatch.Stop();

        double seconds = stopwatch.Elapsed.TotalSeconds;
        double throughput = seconds > 0 ? inputFiles.Length / seconds : 0;
        Console.WriteLine(
            $"Load test complete: {inputFiles.Length} submissions, {failures} failures, " +
            $"total {seconds:F2}s, throughput {throughput:F2} req/s");

        if (parsedArguments.StatsFile is string statsFile)
        {
            WriteLoadStats(
                statsFile, inputFiles.Length, failures, seconds, throughput,
                concurrency, useAsync, latenciesMs, completionsPerSecond);
            Console.WriteLine($"Load stats written to {{{statsFile}}}");
        }

        if (failures > 0)
        {
            throw new Exception($"{failures} submission(s) failed during load test");
        }
    }

    /// <summary>
    /// Writes a JSON summary of a load run (aggregate metrics, latency
    /// percentiles and per-second completion counts) that downstream tooling can
    /// turn into charts, mirroring the locust load test's stats output.
    /// </summary>
    private static void WriteLoadStats(
        string path,
        int submissions,
        int failures,
        double totalSeconds,
        double throughput,
        int concurrency,
        bool useAsync,
        IReadOnlyCollection<double> latenciesMs,
        IDictionary<long, int> completionsPerSecond)
    {
        double[] sorted = latenciesMs.OrderBy(value => value).ToArray();

        double Percentile(double percentile)
        {
            if (sorted.Length == 0)
            {
                return 0;
            }
            int rank = (int)Math.Ceiling(percentile / 100.0 * sorted.Length) - 1;
            return sorted[Math.Clamp(rank, 0, sorted.Length - 1)];
        }

        var stats = new
        {
            submissions,
            failures,
            total_seconds = Math.Round(totalSeconds, 3),
            throughput_rps = Math.Round(throughput, 2),
            concurrency,
            mode = useAsync ? "async" : "sync",
            latency_ms = new
            {
                min = sorted.Length > 0 ? Math.Round(sorted[0], 2) : 0,
                mean = sorted.Length > 0 ? Math.Round(sorted.Average(), 2) : 0,
                p50 = Math.Round(Percentile(50), 2),
                p90 = Math.Round(Percentile(90), 2),
                p99 = Math.Round(Percentile(99), 2),
                max = sorted.Length > 0 ? Math.Round(sorted[^1], 2) : 0,
            },
            requests_per_sec = completionsPerSecond
                .OrderBy(pair => pair.Key)
                .ToDictionary(pair => pair.Key.ToString(), pair => pair.Value),
        };

        string json = JsonSerializer.Serialize(
            stats, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
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
        string? caCertificatePath,
        bool useAsync,
        bool skipTransparentStatement,
        int concurrency,
        string? statsFile)
    {
        public string Operation { get; } = operation;
        public string InputPath { get; } = inputPath;
        public string? OutputPath { get; } = outputPath;
        public Uri? Endpoint { get; } = endpoint;
        public string? CaCertificatePath { get; } = caCertificatePath;
        public bool UseAsync { get; } = useAsync;
        public bool SkipTransparentStatement { get; } = skipTransparentStatement;
        public int Concurrency { get; } = concurrency;
        public string? StatsFile { get; } = statsFile;
    }
}
