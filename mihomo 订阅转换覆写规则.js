const proxyName = "代理模式";

const user_rules = [
  "DOMAIN-KEYWORD,bitwarden,手动选择",
  "DOMAIN-SUFFIX,vercel.app,手动选择",
  //"DOMAIN-SUFFIX,linux.do,手动选择",
  "DOMAIN-SUFFIX,oaifree.com,手动选择",
  "DOMAIN-SUFFIX,deepl.com,手动选择",
  "DOMAIN-SUFFIX,itisu.me,手动选择",
  "DOMAIN-SUFFIX,appinn.com,手动选择",
  "DOMAIN-SUFFIX,ping0.cc,DIRECT",
  "DOMAIN-SUFFIX,ifconfig.me,手动选择",
  "DOMAIN-SUFFIX,ipdata.co,手动选择",
  "DOMAIN-SUFFIX,perplexity.ai,手动选择",
  "DOMAIN-SUFFIX,docker.com,手动选择",
  "DOMAIN-SUFFIX,docker.io,手动选择",
  "DOMAIN-SUFFIX,diskanalyzer.com,手动选择",
  "DOMAIN-SUFFIX,us.kg,手动选择",
  "DOMAIN-SUFFIX,stripe.com,手动选择",
  "DOMAIN-SUFFIX,arc.net,手动选择",
  "DOMAIN-SUFFIX,sentry.io,手动选择",
  "DOMAIN-SUFFIX,segment.io,手动选择",
  "DOMAIN-SUFFIX,launchdarkly.com,手动选择",
  "DOMAIN-SUFFIX,smnet.io,手动选择",
  "DOMAIN-SUFFIX,cursor.sh,手动选择",
  "DOMAIN-SUFFIX,codeium.com,手动选择",
  "DOMAIN-SUFFIX,codeiumdata.com,手动选择",
  "DOMAIN-SUFFIX,spiritlhl.net,手动选择",
  "DOMAIN-SUFFIX,python.org,手动选择",
  "DOMAIN-SUFFIX,bolt.new,手动选择",
  "DOMAIN-SUFFIX,staticblitz.com,手动选择",
  "DOMAIN-SUFFIX,notion.so,手动选择",
  "DOMAIN-SUFFIX,follow.is,手动选择",
  "DOMAIN-SUFFIX,netflixgc.com,手动选择",
  "DOMAIN-SUFFIX,nodeloc.com,手动选择",
  "DOMAIN-SUFFIX,openai.com,手动选择",
  "DOMAIN-SUFFIX,rust-lang.org,手动选择",
  "DOMAIN-SUFFIX,crates.io,手动选择",
  "DOMAIN-SUFFIX,huggingface.co,手动选择",
  "DOMAIN-SUFFIX,lingche.icu,手动选择",
  "DOMAIN-SUFFIX,subconverters.com,手动选择",
  "DOMAIN-SUFFIX,spotify.com,手动选择",
  "DOMAIN-SUFFIX,gstatic.com,手动选择",
  "DOMAIN-SUFFIX,nodeseek.com,手动选择",
  "DOMAIN-SUFFIX,googleapis.com,手动选择",
  "DOMAIN-SUFFIX,google.com,手动选择",
  "DOMAIN-SUFFIX,gvt2.com,手动选择",
  "DOMAIN-SUFFIX,windowsupdate.com,手动选择",
  "DOMAIN-SUFFIX,recaptcha.net,手动选择",
  "DOMAIN-SUFFIX,sofast.xin,手动选择",
  "DOMAIN-SUFFIX,neodb.social,手动选择",
  "DOMAIN-SUFFIX,gvt1.com,手动选择",
  "DOMAIN-SUFFIX,javdb.com,手动选择",
]

function main(params) {
  if (!params.proxies) return params;
  // 删除所有名称中包含“日本”的节点
  params.proxies = params.proxies.filter(proxy => !proxy.name.includes("日本"));
  overwriteRules(params);
  overwriteProxyGroups(params);
  overwriteDns(params);
  return params;
}

const countryRegions = [
  { code: "HK", name: "香港", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg", regex: /(香港|HK|Hong Kong|🇭🇰)(?!.*(中国|CN|China|PRC|🇨🇳))/i },
  { code: "TW", name: "台湾", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg", regex: /(台湾|\bTW\b|Taiwan|🇹🇼)(?!.*(中国|CN|China|PRC|🇨🇳))(?!.*Networks)/i },
  { code: "SG", name: "新加坡", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg", regex: /(新加坡|狮城|SG|Singapore|🇸🇬)/i },
  { code: "JP", name: "日本", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/jp.svg", regex: /(日本|JP|Japan|🇯🇵)/i },
  { code: "US", name: "美国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg", regex: /^(?!.*(Plus|plus|custom)).*(美国|US|USA|United States|America|🇺🇸)/i },
  { code: "KR", name: "韩国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/kr.svg", regex: /(韩国|KR|Korea|South Korea|🇰🇷)/i },
  { code: "UK", name: "英国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/gb.svg", regex: /(英国|UK|United Kingdom|Britain|Great Britain|🇬🇧)/i },
  //{ code: "DE", name: "德国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/de.svg", regex: /^(?!.*shadowsocks).*(德国|DE|Germany|🇩🇪)/i },
  //{ code: "CA", name: "加拿大", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ca.svg", regex: /^(?!.*(Anycast|Datacamp)).*(加拿大|CA|Canada|🇨🇦)/i },
  //{ code: "AU", name: "澳大利亚", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/au.svg", regex: /(澳大利亚|AU|Australia|🇦🇺)/i },
  //{ code: "FR", name: "法国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/fr.svg", regex: /^(?!.*(free|Frontier|Frankfurt)).*(法国|FR|France|🇫🇷)/i },
  //{ code: "NL", name: "荷兰", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/nl.svg", regex: /^(?!.*(only|online|MNL)).*(荷兰|NL|Netherlands|🇳🇱)/i },
  //{ code: "RU", name: "俄罗斯", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ru.svg", regex: /(俄罗斯|RU|Russia|🇷🇺)/i },
  //{ code: "IN", name: "印度", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/in.svg", regex: /^(?!.*(Singapore|Argentina|Intel|Inc|ing|link|business|hinet|internet|印度尼西亚|main)).*(印度|IN|India|🇮🇳)/i },
  //{ code: "BR", name: "巴西", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/br.svg", regex: /(巴西|BR|Brazil|🇧🇷)/i },
  //{ code: "IT", name: "意大利", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/it.svg", regex: /^(?!.*(mitce|reality|digital|leiting|limited|it7|territories)).*(意大利|IT|Italy|🇮🇹)/i },
  //{ code: "CH", name: "瑞士", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ch.svg", regex: /^(?!.*(incheon|chunghwa|tech|psychz|channel|seychelles|chuncheon)).*(瑞士|CH|Switzerland|🇨🇭)/i },
  //{ code: "SE", name: "瑞典", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/se.svg", regex: /^(?!.*(sel2|sea1|server|selfhost|neonpulse|base|seoul|seychelles)).*(瑞典|SE|Sweden|🇸🇪)/i },
  //{ code: "NO", name: "挪威", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/no.svg", regex: /^(?!.*(none|node|annoy|cf_no1|technolog)).*(挪威|NO|Norway|🇳🇴)/i },
  //{ code: "CN", name: "中国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/cn.svg", regex: /^(?!.*(台湾|香港|TW|CN_d)).*(中国|CN|China|PRC|🇨🇳)/i },
  //{ code: "MY", name: "马来西亚", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/my.svg", regex: /^(?!.*(myshadow)).*(马来西亚|MY|Malaysia|🇲🇾)/i },
  //{ code: "VN", name: "越南", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/vn.svg", regex: /(越南|VN|Vietnam|🇻🇳)/i },
  //{ code: "PH", name: "菲律宾", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ph.svg", regex: /^(?!.*(phoenix|phx)).*(菲律宾|PH|Philippines|🇵🇭)/i },
  //{ code: "TH", name: "泰国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/th.svg", regex: /^(?!.*(GTHost|pathx)).*(泰国|TH|Thailand|🇹🇭)/i },
  //{ code: "ID", name: "印度尼西亚", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/id.svg", regex: /(印度尼西亚|ID|Indonesia|🇮🇩)/i },
  //{ code: "AR", name: "阿根廷", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ar.svg", regex: /^(?!.*(warp|arm|flare|star|shar|par|akihabara|bavaria)).*(阿根廷|AR|Argentina|🇦🇷)/i },
  //{ code: "NG", name: "尼日利亚", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ng.svg", regex: /^(?!.*(ong|ing|angeles|ang|ung)).*(尼日利亚|NG|Nigeria|🇳🇬)(?!.*(Hongkong|Singapore))/i },
  //{ code: "TR", name: "土耳其", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tr.svg", regex: /^(?!.*(trojan|str|central)).*(土耳其|TR|Turkey|🇹🇷)/i },
  //{ code: "ES", name: "西班牙", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/es.svg", regex: /^(?!.*(vless|angeles|vmess|seychelles|business|ies|reston)).*(西班牙|ES|Spain|🇪🇸)/i },
];

function getTestUrlForGroup(groupName) {
  switch (groupName) {
    case "Steam":
      return "https://store.steampowered.com/";
    case "Telegram":
      return "https://web.telegram.org/";
    case "ChatGPT":
      return "https://chat.openai.com/";
    case "Claude":
      return "https://claude.ai/";
    case "Spotify":
      return "https://www.spotify.com/";
    default:
      return "http://www.gstatic.com/generate_204";
  }
}

function getIconForGroup(groupName) {
  switch (groupName) {
    case "Steam":
      return "https://store.steampowered.com/favicon.ico";
    case "Telegram":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg";
    case "ChatGPT":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg";
    case "Claude":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/claude.svg";
    case "Spotify":
      return "https://storage.googleapis.com/spotifynewsroom-jp.appspot.com/1/2020/12/Spotify_Icon_CMYK_Green.png";
    case "漏网之鱼":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg";
    case "广告拦截":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/block.svg";
    default:
      return "";
  }
}

function overwriteRules(params) {
  const rules = [
    ...user_rules,
    "RULE-SET,steam,Steam",
    "RULE-SET,private,DIRECT",
    "RULE-SET,lancidr,DIRECT",
    "GEOIP,LAN,DIRECT,no-resolve",
    "RULE-SET,cncidr,DIRECT",
    "GEOIP,CN,DIRECT,no-resolve",
    "RULE-SET,direct,DIRECT",
    "RULE-SET,applications,DIRECT",
    "RULE-SET,openai,ChatGPT",
    "RULE-SET,claude,Claude",
    "RULE-SET,spotify,Spotify",
    "RULE-SET,telegramcidr,Telegram,no-resolve",
    "RULE-SET,apple," + proxyName,
    "RULE-SET,icloud," + proxyName,
    "RULE-SET,google," + proxyName,
    "RULE-SET,greatfire," + proxyName,
    "RULE-SET,reject,广告拦截",
    "RULE-SET,gfw," + proxyName,
    "RULE-SET,proxy," + proxyName,
    "RULE-SET,tld-not-cn," + proxyName,
    "MATCH,漏网之鱼",
  ];
  const ruleProviders = {
    steam: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/luzov/Mihomo-Rules/refs/heads/main/Steam.txt",
      path: "./ruleset/steam.yaml",
      interval: 86400,
    },
    reject: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
      path: "./ruleset/reject.yaml",
      interval: 86400,
    },
    icloud: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt",
      path: "./ruleset/icloud.yaml",
      interval: 86400,
    },
    apple: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
      path: "./ruleset/apple.yaml",
      interval: 86400,
    },
    google: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
      path: "./ruleset/google.yaml",
      interval: 86400,
    },
    proxy: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
      path: "./ruleset/proxy.yaml",
      interval: 86400,
    },
    openai: {
      type: "http",
      behavior: "classical",
      url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml",
      path: "./ruleset/custom/openai.yaml",
    },
    claude: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml",
      path: "./ruleset/custom/Claude.yaml",
    },
    spotify: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml",
      path: "./ruleset/custom/Spotify.yaml",
    },
    telegramcidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
      path: "./ruleset/custom/telegramcidr.yaml",
    },
    direct: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
      path: "./ruleset/direct.yaml",
      interval: 86400,
    },
    private: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
      path: "./ruleset/private.yaml",
      interval: 86400,
    },
    gfw: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
      path: "./ruleset/gfw.yaml",
      interval: 86400,
    },
    greatfire: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt",
      path: "./ruleset/greatfire.yaml",
      interval: 86400,
    },
    "tld-not-cn": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
      path: "./ruleset/tld-not-cn.yaml",
      interval: 86400,
    },
    telegramcidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
      path: "./ruleset/telegramcidr.yaml",
      interval: 86400,
    },
    cncidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      path: "./ruleset/cncidr.yaml",
      interval: 86400,
    },
    lancidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
      path: "./ruleset/lancidr.yaml",
      interval: 86400,
    },
    applications: {
      type: "http",
      behavior: "classical",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
      path: "./ruleset/applications.yaml",
      interval: 86400,
    },
  };

  params["rule-providers"] = ruleProviders;
  params["rules"] = rules;
}

function overwriteProxyGroups(params) {
  const allProxies = params["proxies"].map((e) => e.name);

  const availableCountryCodes = new Set();
  const otherProxies = [];
  for (const proxy of params["proxies"]) {
    let bestMatch = null;
    let longestMatchLength = 0;

    for (const region of countryRegions) {
      const match = proxy.name.match(region.regex);
      if (match) {
        if (match[0].length > longestMatchLength) {
          longestMatchLength = match[0].length;
          bestMatch = region.code;
        }
      }
    }

    if (bestMatch) {
      availableCountryCodes.add(bestMatch);
    } else {
      otherProxies.push(proxy.name);
    }
  }

  availableCountryCodes.add("CN");

  const autoProxyGroupRegexs = countryRegions
    .filter(region => availableCountryCodes.has(region.code))
    .map(region => ({
      name: `${region.code} - 自动选择`,
      regex: region.regex,
    }));

  const autoProxyGroups = autoProxyGroupRegexs
    .map((item) => ({
      name: item.name,
      type: "url-test",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      tolerance: 50,
      proxies: getProxiesByRegex(params, item.regex),
      hidden: true,
    }))
    .filter((item) => item.proxies.length > 0);

  const manualProxyGroupsConfig = countryRegions
    .filter(region => availableCountryCodes.has(region.code))
    .map(region => ({
      name: `${region.code} - 手动选择`,
      type: "select",
      proxies: getManualProxiesByRegex(params, region.regex),
      icon: region.icon,
      hidden: false,
    })).filter(item => item.proxies.length > 0);

  const groups = [
    {
      name: proxyName,
      type: "select",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg",
      proxies: ["自动选择", "手动选择", "负载均衡 (散列)", "负载均衡 (轮询)", "DIRECT"],
    },

    {
      name: "手动选择",
      type: "select",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg",
      proxies: allProxies.length > 0 ? allProxies : ["DIRECT"],
    },

    {
      name: "自动选择",
      type: "select",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/speed.svg",
      proxies: ["ALL - 自动选择", ...autoProxyGroups
        .filter(group => !["Shared Chat", "Steam", "Telegram", "ChatGPT", "Claude", "Spotify", "Linux Do"].includes(group.name))
        .map(group => group.name)],
    },

    {
      name: "负载均衡 (散列)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/balance.svg",
      interval: 300,
      "max-failed-times": 3,
      strategy: "consistent-hashing",
      lazy: true,
      proxies: allProxies.length > 0 ? allProxies : ["DIRECT"],
      hidden: true,
    },

    {
      name: "负载均衡 (轮询)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/merry_go.svg",
      interval: 300,
      "max-failed-times": 3,
      strategy: "round-robin",
      lazy: true,
      proxies: allProxies.length > 0 ? allProxies : ["DIRECT"],
      hidden: true,
    },

    {
      name: "ALL - 自动选择",
      type: "url-test",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      tolerance: 50,
      proxies: allProxies.length > 0 ? allProxies : ["DIRECT"],
      hidden: true,
    },

    ...[
      "Steam", 
      "Telegram", 
      "ChatGPT", 
      "Claude", 
      "Spotify"
      ].map(groupName => ({
      name: groupName,
      type: "select",
      url: getTestUrlForGroup(groupName),
      icon: getIconForGroup(groupName),
      proxies: [
        proxyName,
        "DIRECT",
        "其它 - 自动选择",
        ...countryRegions
          .filter(region => availableCountryCodes.has(region.code))
          .flatMap(region => [
            `${region.code} - 自动选择`,
            `${region.code} - 手动选择`,
          ]),
      ],
    })),

    {
      name: "漏网之鱼",
      type: "select",
      proxies: ["DIRECT", proxyName],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg",
    },

    {
      name: "广告拦截",
      type: "select",
      proxies: ["REJECT", "DIRECT", proxyName],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/block.svg",
    },
  ];

  autoProxyGroups.push({
    name: "其它 - 自动选择",
    type: "url-test",
    url: "http://www.gstatic.com/generate_204",
    interval: 300,
    tolerance: 50,
    proxies: otherProxies.length > 0 ? otherProxies : ["手动选择"],
    hidden: true,
  });

  groups.push(...autoProxyGroups);
  groups.push(...manualProxyGroupsConfig);
  params["proxy-groups"] = groups;
}

function overwriteDns(params) {
  const cnDnsList = ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"];
  const trustDnsList = ["https://dns.google/dns-query","quic://dns.cooluc.com", "https://1.0.0.1/dns-query", "https://1.1.1.1/dns-query"];
  const dnsOptions = {
    enable: true,
    "prefer-h3": true,
    "default-nameserver": cnDnsList,
    nameserver: trustDnsList,
    "nameserver-policy": {
      "geosite:cn": cnDnsList,
      "geosite:geolocation-!cn": trustDnsList,
      "domain:google.com,facebook.com,youtube.com,twitter.com,github.com,cloudflare.com,jsdelivr.net,hf.space": trustDnsList,
    },
    fallback: trustDnsList,
    "fallback-filter": { geoip: true, "geoip-code": "CN", ipcidr: ["240.0.0.0/4"] },
  };
  const githubPrefix = "https://fastgh.lainbo.com/";
  const rawGeoxURLs = {
    geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
    geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
  };
  const accelURLs = Object.fromEntries(Object.entries(rawGeoxURLs).map(([key, githubUrl]) => [key, `${githubPrefix}${githubUrl}`]));
  const otherOptions = {
    "unified-delay": false,
    "tcp-concurrent": true,
    profile: { "store-selected": true, "store-fake-ip": true },
    sniffer: { enable: true, sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, "8080-8880"], "override-destination": true } } },
    "geodata-mode": true,
    "geox-url": accelURLs,
  };
  params.dns = { ...params.dns, ...dnsOptions };
  Object.keys(otherOptions).forEach((key) => {
    params[key] = otherOptions[key];
  });
}

function getProxiesByRegex(params, regex) {
  const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
  return matchedProxies.length > 0 ? matchedProxies : ["手动选择"];
}

function getManualProxiesByRegex(params, regex) {
  const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
  return regex.test("CN")
    ? ["DIRECT", ...matchedProxies, "手动选择", proxyName]
    : matchedProxies.length > 0
      ? matchedProxies
      : ["DIRECT", "手动选择", proxyName];
}
