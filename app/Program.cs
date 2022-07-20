using System;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Prometheus;
using Serilog;

class Program
{
    public class MetricInfo
    {
        public string? Type { get; set; }
        public string? Label { get; set; }
    }
    public static IConfigurationRoot? configuration;
    private static readonly Counter ssl = Metrics.CreateCounter("f5_bigip_ssl_conn_total", "Total Number of SSL Connections",
        new CounterConfiguration
        {
            LabelNames = new[] { "type" }
        });
    private static readonly Gauge mem = Metrics.CreateGauge("f5_bigip_memory_bytes", "Memory in bytes",
        new GaugeConfiguration
        {
            LabelNames = new[] { "type" }
        });
    private static readonly Gauge cpu = Metrics.CreateGauge("f5_bigip_cpu_percent", "CPU in percent",
        new GaugeConfiguration
        {
            LabelNames = new[] { "state" }
        });

    static async Task Main()
    {
		Log.Logger = new LoggerConfiguration()
			 .WriteTo.Console(Serilog.Events.LogEventLevel.Debug)
			 .MinimumLevel.Debug()
			 .Enrich.FromLogContext()
			 .CreateLogger();
        Log.Information("Starting F5 SNMP metrics collection configuration...");

		ServiceCollection serviceCollection = new ServiceCollection();
		ConfigureServices(serviceCollection);

        List<Variable> oidList = new List<Variable>();
        Dictionary<string, MetricInfo> _metricInfo = new Dictionary<string, MetricInfo>();
        string host = configuration.GetSection("AppConfig")["F5bigipHost"];
        string community = configuration.GetSection("AppConfig")["SnmpCommunityString"];
        int snmpPort = Int32.Parse(configuration.GetSection("AppConfig")["SnmpPort"]);
        int webPort = Int32.Parse(configuration.GetSection("AppConfig")["WebServerPort"]);
        string[] metricsType = {"SSLMetrics", "CPUMetrics", "MemoryMetrics"};
        VersionCode version = VersionCode.V2;
        int timeout = 1000;

        foreach(string type in metricsType)
        {
            var sslMetricsSection = configuration.GetSection(type);
            if (sslMetricsSection != null)
            {
                foreach (IConfigurationSection _section in sslMetricsSection.GetChildren())
                {
                    MetricInfo mInfo = new MetricInfo();
                    mInfo.Type = type;
                    mInfo.Label = _section.GetValue<string>("Label");
                    _metricInfo.Add(_section.GetValue<string>("OID"), mInfo);
                    Variable oid = new Variable(new ObjectIdentifier(_section.GetValue<string>("OID")));
                    oidList.Add(oid);
                }
            }
            else
            {
                Log.Error("Missing some or all configuration sections in appsettings.json");
                System.Environment.Exit(-1);
            }
        }

        IPAddress ip;
        bool parsedIP = IPAddress.TryParse(host, out ip);
        if (!parsedIP)
        {
            var addresses = Dns.GetHostAddressesAsync(host);
            addresses.Wait();
            foreach (IPAddress address in addresses.Result.Where(address => address.AddressFamily == AddressFamily.InterNetwork))
            {
                ip = address;
                break;
            }
            if (ip == null)
            {
                Log.Error("Invalid host or wrong IP address found: " + host);
                return;
            }
        }
        IPEndPoint receiver = new IPEndPoint(ip, snmpPort);

        Log.Information("Starting metrics server on port {0}", webPort);
        Metrics.SuppressDefaultMetrics();
        var server = new MetricServer(port: webPort);
        server.Start();

        Metrics.DefaultRegistry.AddBeforeCollectCallback(async (cancel) =>
        {
            Log.Information("--> GET /metrics query");
            try
            {
                int count = 0;
                foreach (Variable variable in Messenger.Get(version, receiver, new OctetString(community), oidList, timeout))
                {
                    count++;
                    string label = _metricInfo["." + variable.Id.ToString()].Label;
                    switch (_metricInfo["." + variable.Id.ToString()].Type)
                    {
                        case "SSLMetrics":
                            ssl.WithLabels(label).IncTo(Convert.ToDouble(variable.Data.ToString()));
                            break;
                        case "CPUMetrics":
                            cpu.WithLabels(label).Set(Convert.ToDouble(variable.Data.ToString()));
                            break;
                        case "MemoryMetrics":
                            mem.WithLabels(label).Set(Convert.ToDouble(variable.Data.ToString()));
                            break;
                        default:
                            Log.Warning("Attempt to match ISnmpData.OID ==> MetricInfo.Type failed!  Possible corruption in Dictionary.");
                            break;
                    }
                }
                Log.Information("--> SNMP results returned = {0}", count);
            }
            catch (Exception e)
            {
                Log.Error("Exception ==> {0}", e);
            }
        });

        while (true)
        {
            await Task.Delay(500);
        }
    }

    private static void ConfigureServices(IServiceCollection serviceCollection)
	{
		// Add logging
		serviceCollection.AddSingleton(LoggerFactory.Create(builder =>
		{
			builder.AddSerilog(dispose: true);
		}));

		serviceCollection.AddLogging();

		// Build configuration
		configuration = new ConfigurationBuilder()
			.SetBasePath(Directory.GetParent(AppContext.BaseDirectory).FullName)
			.AddJsonFile("appsettings.json", false)
			.Build();

		// Add access to generic IConfigurationRoot
		serviceCollection.AddSingleton<IConfigurationRoot>(configuration);
	}
}
