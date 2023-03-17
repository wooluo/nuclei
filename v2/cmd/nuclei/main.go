package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/nuclei/v2/internal/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types/scanstrategy"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/monitor"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	cfgFile    string
	memProfile string // optional profile file path
	options    = &types.Options{}
)

func main() {
	if err := runner.ConfigureOptions(); err != nil {
		gologger.Fatal().Msgf("无法初始化选项: %s\n", err)
	}
	flagSet := readConfig()
	configPath, _ := flagSet.GetConfigFilePath()

	if options.ListDslSignatures {
		gologger.Info().Msgf("The available custom DSL functions are:")
		fmt.Println(dsl.GetPrintableDslFunctionSignatures(options.NoColor))
		return
	}

	// Profiling related code
	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			gologger.Fatal().Msgf("profile: could not create memory profile %q: %v", memProfile, err)
		}
		old := runtime.MemProfileRate
		runtime.MemProfileRate = 4096
		gologger.Print().Msgf("profile: memory profiling enabled (rate %d), %s", runtime.MemProfileRate, memProfile)

		defer func() {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			f.Close()
			runtime.MemProfileRate = old
			gologger.Print().Msgf("profile: memory profiling disabled, %s", memProfile)
		}()
	}

	runner.ParseOptions(options)
	options.ConfigPath = configPath

	if options.HangMonitor {
		cancel := monitor.NewStackMonitor(10 * time.Second)
		defer cancel()
	}

	nucleiRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		return
	}

	// Setup graceful exits
	resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			nucleiRunner.Close()
			if options.ShouldSaveResume() {
				gologger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
				err := nucleiRunner.SaveResumeConfig(resumeFileName)
				if err != nil {
					gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
				}
			}
			os.Exit(1)
		}
	}()

	if err := nucleiRunner.RunEnumeration(); err != nil {
		if options.Validate {
			gologger.Fatal().Msgf("Could not validate templates: %s\n", err)
		} else {
			gologger.Fatal().Msgf("Could not run nuclei: %s\n", err)
		}
	}
	nucleiRunner.Close()
	// on successful execution remove the resume file in case it exists
	if fileutil.FileExists(resumeFileName) {
		os.Remove(resumeFileName)
	}
}

func readConfig() *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`
    ▄█     █▄   ▄██████▄   ▄██████▄   ▄█       ███    █▄   ▄██████▄
  ███     ███ ███    ███ ███    ███ ███       ███    ███ ███    ███
 ███     ███ ███    ███ ███    ███ ███       ███    ███ ███    ███
███ ▄█▄ ███ ███    ███ ███    ███ ███▌    ▄ ███    ███ ███    ███
 ▀███▀███▀   ▀██████▀   ▀██████▀  █████▄▄██ ████████▀   ▀██████▀
	 
	WOOLUO是基于Nuclei模板的快速漏洞扫描工具, 具备大规模扫描的可扩展性和易用性。`)
	/* TODO Important: The defined default values, especially for slice/array types are NOT DEFAULT VALUES, but rather implicit values to which the user input is appended.
	This can be very confusing and should be addressed
	*/

	flagSet.CreateGroup("input", "Target",
		flagSet.StringSliceVarP(&options.Targets, "target", "u", nil, "要扫描的目标URL或者IP地址", goflags.StringSliceOptions),
		flagSet.StringVarP(&options.TargetsFilePath, "list", "l", "", "包含要扫描的目标URL/主机列表的文件路径（每行一个）"),
		flagSet.StringVar(&options.Resume, "resume", "", "使用Resume恢复扫描 resume.cfg (clustering将被禁用)"),
		flagSet.BoolVarP(&options.ScanAllIPs, "scan-all-ips", "sa", false, "扫描与dns记录相关的所有IP"),
		flagSet.StringSliceVarP(&options.IPVersion, "ip-version", "iv", nil, "要扫描主机名的IP版本（v4,v6）-（默认值v4）", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("templates", "Templates",
		flagSet.BoolVarP(&options.NewTemplates, "new-templates", "nt", false, "仅运行最新Nucleus templates版本中添加的新模板"),
		flagSet.StringSliceVarP(&options.NewTemplatesWithVersion, "new-templates-version", "ntv", nil, "运行在特定版本中添加的新模板", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.AutomaticScan, "automatic-scan", "as", false, "使用wappalyzer技术检测到标签映射的自动web扫描"),
		flagSet.StringSliceVarP(&options.Templates, "templates", "t", nil, "要运行的模板或模板目录列表（逗号分隔，文件）", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.TemplateURLs, "template-url", "tu", nil, "要运行的模板URL列表（逗号分隔，文件）", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Workflows, "workflows", "w", nil, "要运行的工作流或工作流目录列表（逗号分隔，文件）", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.WorkflowURLs, "workflow-url", "wu", nil, "要运行的工作流URL列表（逗号分隔，文件）", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&options.Validate, "validate", false, "验证传递给Nucleus的模板"),
		flagSet.BoolVarP(&options.NoStrictSyntax, "no-strict-syntax", "nss", false, "禁用模板上的严格语法检查"),
		flagSet.BoolVarP(&options.TemplateDisplay, "template-display", "td", false, "显示模板内容"),
		flagSet.BoolVar(&options.TemplateList, "tl", false, "列出所有可用模板"),
		flagSet.StringSliceVarConfigOnly(&options.RemoteTemplateDomainList, "remote-template-domain", []string{"api.nuclei.sh"}, "允许从中加载远程模板的域列表"),
	)

	flagSet.CreateGroup("filters", "Filtering",
		flagSet.StringSliceVarP(&options.Authors, "author", "a", nil, "基于作者运行的模板（逗号分隔，文件）", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVar(&options.Tags, "tags", nil, "基于标记运行的模板（逗号分隔，文件）", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeTags, "exclude-tags", "etags", nil, "基于标记排除的模板（逗号分隔，文件)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.IncludeTags, "include-tags", "itags", nil, "即使默认或配置排除标签，也要执行标签", goflags.FileNormalizedStringSliceOptions), // TODO show default deny list
		flagSet.StringSliceVarP(&options.IncludeIds, "template-id", "id", nil, "基于模板ID(逗号分隔，文件)运行的模板", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeIds, "exclude-id", "eid", nil, "基于模板ID排除的模板(逗号分隔，文件)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.IncludeTemplates, "include-templates", "it", nil, "要执行的模板，即使默认或配置排除了这些模板", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludedTemplates, "exclude-templates", "et", nil, "要排除的模板或模板目录（逗号分隔，文件）", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeMatchers, "exclude-matchers", "em", nil, "要在结果中排除的模板匹配器", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.VarP(&options.Severities, "severity", "s", fmt.Sprintf("基于严重性运行的模板。可能的值: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&options.ExcludeSeverities, "exclude-severity", "es", fmt.Sprintf("要根据严重性排除的模板。可能的值: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&options.Protocols, "type", "pt", fmt.Sprintf("基于协议类型运行的模板。可能的值: %s", templateTypes.GetSupportedProtocolTypes())),
		flagSet.VarP(&options.ExcludeProtocols, "exclude-type", "ept", fmt.Sprintf("要根据协议类型排除的模板。可能的值: %s", templateTypes.GetSupportedProtocolTypes())),
		flagSet.StringSliceVarP(&options.IncludeConditions, "template-condition", "tc", nil, "基于表达式条件运行的模板", goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "输出文件以写入发现的问题/漏洞"),
		flagSet.BoolVarP(&options.StoreResponse, "store-resp", "sresp", false, "将通过Nucleus传递的所有请求/响应存储到输出目录"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-resp-dir", "srd", runner.DefaultDumpTrafficOutputFolder, "将通过Nucleus传递的所有请求/响应存储到自定义目录"),
		flagSet.BoolVar(&options.Silent, "silent", false, "仅显示结果"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "禁用输出内容着色(ANSI转义码)"),
		flagSet.BoolVar(&options.JSON, "json", false, "以JSONL(ines)格式输出"),
		flagSet.BoolVarP(&options.JSONRequests, "include-rr", "irr", false, "在JSONL输出中包括请求/响应对（仅用于结果）"),
		flagSet.BoolVarP(&options.NoMeta, "no-meta", "nm", false, "禁用在cli输出中打印结果"),
		flagSet.BoolVarP(&options.Timestamp, "timestamp", "ts", false, "启用在cli输出中打印时间戳"),
		flagSet.StringVarP(&options.ReportingDB, "report-db", "rdb", "", "本地Nuclei报告数据库(始终使用此数据库保存报告数据)"),
		flagSet.BoolVarP(&options.MatcherStatus, "matcher-status", "ms", false, "显示可选的匹配失败状态"),
		flagSet.StringVarP(&options.MarkdownExportDirectory, "markdown-export", "me", "", "以markdown格式导出结果的目录"),
		flagSet.StringVarP(&options.SarifExport, "sarif-export", "se", "", "要以SARIF格式导出结果的文件"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "配置文件的路径"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "为http模板启用以下重定向"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "在同一主机上执行重定向"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "mr", 10, "http模板要遵循的最大重定向数"),
		flagSet.BoolVarP(&options.DisableRedirects, "disable-redirects", "dr", false, "禁用http模板的重定向"),
		flagSet.StringVarP(&options.ReportingConfig, "report-config", "rc", "", "Nucleis报告模块配置文件"), // TODO merge into the config file or rename to issue-tracking
		flagSet.StringSliceVarP(&options.CustomHeaders, "header", "H", nil, "自定义标头/cookie以包含在标头中的所有http请求中:值格式 (cli, file)", goflags.FileStringSliceOptions),
		flagSet.RuntimeMapVarP(&options.Vars, "var", "V", nil, "自定义变量var值的格式: key=value"),
		flagSet.StringVarP(&options.ResolversFile, "resolvers", "r", "", "包含核解析程序列表的文件"),
		flagSet.BoolVarP(&options.SystemResolvers, "system-resolvers", "sr", false, "使用系统DNS解析作为错误回退"),
		flagSet.BoolVarP(&options.DisableClustering, "disable-clustering", "dc", false, "禁用请求群集"),
		flagSet.BoolVar(&options.OfflineHTTP, "passive", false, "启用被动HTTP响应处理模式"),
		flagSet.BoolVarP(&options.ForceAttemptHTTP2, "force-http2", "fh2", false, "对请求强制http2连接"),
		flagSet.BoolVarP(&options.EnvironmentVariables, "env-vars", "ev", false, "允许在模板中使用环境变量"),
		flagSet.StringVarP(&options.ClientCertFile, "client-cert", "cc", "", "用于对扫描的主机进行身份验证的客户端证书文件(PEM编码)"),
		flagSet.StringVarP(&options.ClientKeyFile, "client-key", "ck", "", "用于对扫描的主机进行身份验证的客户端密钥文件(PEM编码)"),
		flagSet.StringVarP(&options.ClientCAFile, "client-ca", "ca", "", "用于对扫描的主机进行身份验证的客户端证书颁发机构文件(PEM编码)"),
		flagSet.BoolVarP(&options.ShowMatchLine, "show-match-line", "sml", false, "显示文件模板的匹配线，仅适用于提取器"),
		flagSet.BoolVar(&options.ZTLS, "ztls", false, "使用ztls库,自动回退到tls13的标准库"),
		flagSet.StringVar(&options.SNI, "sni", "", "要使用的tls sni主机名(默认值:输入域名)"),
		flagSet.BoolVar(&options.Sandbox, "sandbox", false, "用于安全模板执行的沙盒核心"),
		flagSet.StringVarP(&options.Interface, "interface", "i", "", "用于网络扫描的网络接口"),
		flagSet.StringVarP(&options.AttackType, "attack-type", "at", "", "要执行的有效载荷组合类型(batteringram,pitchfork,clusterbomb)"),
		flagSet.StringVarP(&options.SourceIP, "source-ip", "sip", "", "用于网络扫描的源ip地址"),
		flagSet.StringVar(&options.CustomConfigDir, "config-directory", "", "覆盖默认配置路径（$home/.config）"),
		flagSet.IntVarP(&options.ResponseReadSize, "response-size-read", "rsr", 10*1024*1024, "要读取的最大响应大小（字节）"),
		flagSet.IntVarP(&options.ResponseSaveSize, "response-size-save", "rss", 1*1024*1024, "要保存的最大响应大小（字节）"),
	)

	flagSet.CreateGroup("interactsh", "interactsh",
		flagSet.StringVarP(&options.InteractshURL, "interactsh-server", "iserver", "", fmt.Sprintf("设置自用的带外测试服务器的URL地址 (默认: %s)", client.DefaultOptions.ServerURL)),
		flagSet.StringVarP(&options.InteractshToken, "interactsh-token", "itoken", "", "带外测试服务器DNSlog的token"),
		flagSet.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "要保留在交互缓存中的请求数"),
		flagSet.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "从缓存中逐出请求之前等待的秒数"),
		flagSet.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "每个交互轮询请求之前等待的秒数"),
		flagSet.IntVar(&options.InteractionsCoolDownPeriod, "interactions-cooldown-period", 5, "退出前进行交互轮询的额外时间"),
		flagSet.BoolVarP(&options.NoInteractsh, "no-interactsh", "ni", false, "禁用用于OAST测试的InteractiveSH服务器，排除基于OAST的模板"),
	)

	flagSet.CreateGroup("fuzzing", "Fuzzing",
		flagSet.StringVarP(&options.FuzzingType, "fuzzing-type", "ft", "", "覆盖在模板中设置的模糊类型（替换、前缀、后缀、中缀）"),
		flagSet.StringVarP(&options.FuzzingMode, "fuzzing-mode", "fm", "", "覆盖在模板中设置的模糊模式（多个、单个）"),
	)

	flagSet.CreateGroup("uncover", "Uncover",
		flagSet.BoolVarP(&options.Uncover, "uncover", "uc", false, "启用打开引擎"),
		flagSet.StringSliceVarP(&options.UncoverQuery, "uncover-query", "uq", nil, "发现搜索查询", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.UncoverEngine, "uncover-engine", "ue", nil, fmt.Sprintf("打开搜索引擎 (%s) (默认 shodan)", uncover.GetUncoverSupportedAgents()), goflags.FileStringSliceOptions),
		flagSet.StringVarP(&options.UncoverField, "uncover-field", "uf", "ip:port", "显示要返回的字段（ip、端口、主机）"),
		flagSet.IntVarP(&options.UncoverLimit, "uncover-limit", "ul", 100, "发现要返回的结果"),
		flagSet.IntVarP(&options.UncoverDelay, "uncover-delay", "ucd", 1, "打开查询请求之间的延迟（秒）（0表示禁用）"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "每秒要发送的最大请求数"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "每分钟发送的最大请求数"),
		flagSet.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "每个模板要并行分析的最大主机数"),
		flagSet.IntVarP(&options.TemplateThreads, "concurrency", "c", 25, "并行执行的最大模板数"),
		flagSet.IntVarP(&options.HeadlessBulkSize, "headless-bulk-size", "hbs", 10, "每个模板并行分析的无头主机的最大数量"),
		flagSet.IntVarP(&options.HeadlessTemplateThreads, "headless-concurrency", "headc", 10, "并行执行的无头模板的最大数量"),
	)
	flagSet.CreateGroup("optimization", "Optimizations",
		flagSet.IntVar(&options.Timeout, "timeout", 5, "超时前等待的时间（秒）"),
		flagSet.IntVar(&options.Retries, "retries", 1, "重试失败请求的次数"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "保留默认HTTP/HTTPS端口 (eg. host:80,host:443"),
		flagSet.IntVarP(&options.MaxHostError, "max-host-error", "mhe", 30, "跳过扫描前主机的最大错误数"),
		flagSet.BoolVarP(&options.NoHostErrors, "no-mhe", "nmhe", false, "禁用基于错误跳过主机扫描"),
		flagSet.BoolVar(&options.Project, "project", false, "使用项目文件夹避免多次发送同一请求"),
		flagSet.StringVar(&options.ProjectPath, "project-path", os.TempDir(), "设置特定的项目路径"),
		flagSet.BoolVarP(&options.StopAtFirstMatch, "stop-at-first-match", "spm", false, "在第一次匹配后停止处理HTTP请求（可能会中断模板/工作流逻辑）"),
		flagSet.BoolVar(&options.Stream, "stream", false, "流模式-在不排序输入的情况下开始细化"),
		flagSet.EnumVarP(&options.ScanStrategy, "scan-strategy", "ss", goflags.EnumVariable(0), "扫描时使用的策略(auto/host-spray/template-spray)", goflags.AllowdTypes{
			scanstrategy.Auto.String():          goflags.EnumVariable(0),
			scanstrategy.HostSpray.String():     goflags.EnumVariable(1),
			scanstrategy.TemplateSpray.String(): goflags.EnumVariable(2),
		}),
		flagSet.DurationVarP(&options.InputReadTimeout, "input-read-timeout", "irt", time.Duration(3*time.Minute), "输入读取超时"),
		flagSet.BoolVarP(&options.DisableHTTPProbe, "no-httpx", "nh", false, "对非url输入禁用httpx探测"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "禁用Stdin处理"),
	)

	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVar(&options.Headless, "headless", false, "启用需要无头浏览器支持的模板（linux上的root用户将禁用沙盒）"),
		flagSet.IntVar(&options.PageTimeout, "page-timeout", 20, "在无标题模式下等待每页的秒数"),
		flagSet.BoolVarP(&options.ShowBrowser, "show-browser", "sb", false, "在无头模式下运行模板时，在屏幕上显示浏览器"),
		flagSet.BoolVarP(&options.UseInstalledChrome, "system-chrome", "sc", false, "使用本地安装的chrome浏览器，而不是Nuclei安装的浏览器"),
		flagSet.BoolVarP(&options.ShowActions, "list-headless-action", "lha", false, "可用无头操作列表"),
	)
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "显示所有请求和响应"),
		flagSet.BoolVarP(&options.DebugRequests, "debug-req", "dreq", false, "显示所有已发送的请求"),
		flagSet.BoolVarP(&options.DebugResponse, "debug-resp", "dresp", false, "显示所有收到的响应"),
		flagSet.StringSliceVarP(&options.Proxy, "proxy", "p", nil, "要使用的http/socks5代理列表（逗号分隔或文件输入）", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.ProxyInternal, "proxy-internal", "pi", false, "代理所有内部请求"),
		flagSet.BoolVarP(&options.ListDslSignatures, "list-dsl-function", "ldf", false, "列出所有支持的DSL函数签名"),
		flagSet.StringVarP(&options.TraceLogFile, "trace-log", "tlog", "", "用于写入已发送请求跟踪日志的文件"),
		flagSet.StringVarP(&options.ErrorLogFile, "error-log", "elog", "", "要写入已发送请求的文件错误日志"),
		flagSet.BoolVar(&options.Version, "version", false, "显示nuclei的版本"),
		flagSet.BoolVarP(&options.HangMonitor, "hang-monitor", "hm", false, "启用挂起监控"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "显示详细输出"),
		flagSet.StringVar(&memProfile, "profile-mem", "", "可选的Nucleus内存配置文件转储文件"),
		flagSet.BoolVar(&options.VerboseVerbose, "vv", false, "显示为扫描加载的模板"),
		flagSet.BoolVarP(&options.ShowVarDump, "show-var-dump", "svd", false, "显示用于调试的变量转储"),
		flagSet.BoolVarP(&options.EnablePprof, "enable-pprof", "ep", false, "启用pprof调试服务器"),
		flagSet.BoolVarP(&options.TemplatesVersion, "templates-version", "tv", false, "显示已安装的Nuclei模板的版本"),
		flagSet.BoolVarP(&options.HealthCheck, "health-check", "hc", false, "运行诊断检查"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVarP(&options.UpdateNuclei, "update", "un", false, "将Nuclei引擎更新至最新发布版本"),
		flagSet.BoolVarP(&options.UpdateTemplates, "update-templates", "ut", false, "将Nuclei规则模板更新至最新发布版本"),
		flagSet.StringVarP(&options.TemplatesDirectory, "update-template-dir", "ud", "", "覆盖默认目录以安装模板"),
		flagSet.BoolVarP(&options.NoUpdateTemplates, "disable-update-check", "duc", false, "禁用自动nuclei/模板更新检查"),
	)

	flagSet.CreateGroup("stats", "Statistics",
		flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "显示有关正在运行的扫描的统计信息"),
		flagSet.BoolVarP(&options.StatsJSON, "stats-json", "sj", false, "以JSONL（ines）格式将统计数据写入输出文件"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", 5, "显示统计信息更新之间等待的秒数"),
		flagSet.BoolVarP(&options.Metrics, "metrics", "m", false, "在端口上公开数据"),
		flagSet.IntVarP(&options.MetricsPort, "metrics-port", "mp", 9092, "展示nuclei的端口列表指标"),
	)

	flagSet.CreateGroup("cloud", "Cloud",
		flagSet.BoolVar(&options.Cloud, "cloud", false, "使用nuclei cloud进行扫描"),
		flagSet.StringVarP(&options.AddDatasource, "add-datasource", "ads", "", "添加指定的数据源（s3，github）"),
		flagSet.StringVarP(&options.AddTarget, "add-target", "atr", "", "将目标添加到云"),
		flagSet.StringVarP(&options.AddTemplate, "add-template", "atm", "", "将模板添加到云"),
		flagSet.BoolVarP(&options.ScanList, "list-scan", "lsn", false, "列出以前的云扫描"),
		flagSet.StringVarP(&options.ScanOutput, "list-output", "lso", "", "按扫描id列出扫描输出"),
		flagSet.BoolVarP(&options.ListTargets, "list-target", "ltr", false, "按id列出云目标"),
		flagSet.BoolVarP(&options.ListTemplates, "list-template", "ltm", false, "按id列出云模板"),
		flagSet.BoolVarP(&options.ListDatasources, "list-datasource", "lds", false, "按id列出云数据源"),
		flagSet.BoolVarP(&options.ListReportingSources, "list-reportsource", "lrs", false, "列出报告来源"),
		flagSet.StringVarP(&options.DeleteScan, "delete-scan", "dsn", "", "按id删除云扫描"),
		flagSet.StringVarP(&options.RemoveTarget, "delete-target", "dtr", "", "从云中删除目标"),
		flagSet.StringVarP(&options.RemoveTemplate, "delete-template", "dtm", "", "从云中删除模板"),
		flagSet.StringVarP(&options.RemoveDatasource, "delete-datasource", "dds", "", "删除指定的数据源"),
		flagSet.StringVarP(&options.DisableReportingSource, "disable-reportsource", "drs", "", "禁用指定的报告源"),
		flagSet.StringVarP(&options.EnableReportingSource, "enable-reportsource", "ers", "", "启用指定的报告源"),
		flagSet.StringVarP(&options.GetTarget, "get-target", "gtr", "", "通过id获取目标内容"),
		flagSet.StringVarP(&options.GetTemplate, "get-template", "gtm", "", "按id获取模板内容"),
		flagSet.BoolVarP(&options.NoStore, "no-store", "nos", false, "禁用云上的扫描/输出存储"),
		flagSet.BoolVar(&options.NoTables, "no-tables", false, "不显示漂亮的打印表格"),
		flagSet.IntVar(&options.OutputLimit, "limit", 100, "限制要显示的输出数量"),
	)

	_ = flagSet.Parse()

	gologger.DefaultLogger.SetTimestamp(options.Timestamp, levels.LevelDebug)

	if options.LeaveDefaultPorts {
		http.LeaveDefaultPorts = true
	}
	if options.CustomConfigDir != "" {
		originalIgnorePath := config.GetIgnoreFilePath()
		config.SetCustomConfigDirectory(options.CustomConfigDir)
		configPath := filepath.Join(options.CustomConfigDir, "config.yaml")
		ignoreFile := filepath.Join(options.CustomConfigDir, ".nuclei-ignore")
		if !fileutil.FileExists(ignoreFile) {
			if err := fileutil.CopyFile(originalIgnorePath, ignoreFile); err != nil {
				gologger.Error().Msgf("failed to copy .nuclei-ignore file in custom config directory got %v", err)
			}
		}
		readConfigFile := func() error {
			if err := flagSet.MergeConfigFile(configPath); err != nil && !errors.Is(err, io.EOF) {
				defaultConfigPath, _ := flagSet.GetConfigFilePath()
				err = fileutil.CopyFile(defaultConfigPath, configPath)
				if err != nil {
					return err
				}
				return errors.New("reload the config file")
			}
			return nil
		}
		if err := readConfigFile(); err != nil {
			_ = readConfigFile()
		}
	}
	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("不能读取配置: %s\n", err)
		}
		cfgFileFolder := filepath.Dir(cfgFile)
		if err := config.OverrideIgnoreFilePath(cfgFileFolder); err != nil {
			gologger.Warning().Msgf("无法从自定义路径读取忽略文件: %s\n", err)
		}
	}
	cleanupOldResumeFiles()
	return flagSet
}

func cleanupOldResumeFiles() {
	root, err := config.GetConfigDir()
	if err != nil {
		return
	}
	filter := fileutil.FileFilters{
		OlderThan: 24 * time.Hour * 10, // cleanup on the 10th day
		Prefix:    "resume-",
	}
	_ = fileutil.DeleteFilesOlderThan(root, filter)
}

func init() {
	// print stacktrace of errors in debug mode
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}
