// 这个脚本两台机器共用（WebDAV 备份会打包 override/ 目录），按机器改这两行：
//   KEEP_JP_NODES  true = 日本节点与港新同等处理；false = 整段剔除（公司网络上日本节点入口被拦）
//   COMPANY_EGRESS 沙箱里取不到设备名/内网 IP（只有 fetch/yaml/console/Buffer），只能按公网出口 IP 判别；
//                  "off" 不探测、"log" 只写日志（override/<id>.log）、正则命中即视为公司电脑
const KEEP_JP_NODES = true;
const COMPANY_EGRESS = /36\.33\.26\.136/; // 公司出口；家里 36.161.232.5；探测失败则不动节点

const proxyName = "代理模式";

const user_rules = [
  "DOMAIN-SUFFIX,gofile.io,DIRECT",
  "DOMAIN-SUFFIX,ping0.cc,DIRECT",
  "DOMAIN-SUFFIX,google.com,Google",
  "DOMAIN-SUFFIX,googlevideo.com,Google",
  "DOMAIN-SUFFIX,google-analytics.com,Google",
  "DOMAIN-SUFFIX,googleapis.com,Google",
  "DOMAIN-SUFFIX,opencode.ai,OpenAI",
  "DOMAIN-SUFFIX,meta.ai,OpenAI",
  "DOMAIN-SUFFIX,facebook.com,OpenAI",
  "DOMAIN-SUFFIX,fbcdn.net,OpenAI",
  "DOMAIN-SUFFIX,facebook.net,OpenAI",
  "DOMAIN-SUFFIX,commandcode.ai,OpenAI",
  "DOMAIN-SUFFIX,teamorouter.com,OpenAI",
  "DOMAIN-SUFFIX,aihubmix.com,OpenAI",
  "DOMAIN-SUFFIX,tokenharbor.ai,OpenAI",
]

// 沙箱里没有 AbortSignal/setTimeout（只注入了 console/fetch/yaml/b64d/b64e/Buffer），超时只能靠 fetch 自己的；
// 两个探测源都失败时不动节点（保持 KEEP_JP_NODES），避免家里误判成公司机把日本节点删掉。
async function probeEgress() {
  for (const url of ["https://ipinfo.io/json", "https://www.cloudflare.com/cdn-cgi/trace"]) {
    try {
      const res = await fetch(url);
      if (res.ok) return (await res.text()).replace(/\s+/g, " ");
    } catch (e) {}
  }
  return null;
}

async function shouldKeepJpNodes() {
  if (COMPANY_EGRESS === "off") return KEEP_JP_NODES;
  const txt = await probeEgress();
  console.log("[egress] " + (txt ? txt.slice(0, 160) : "探测均失败 → 保持不动"));
  if (!txt) return KEEP_JP_NODES;
  if (COMPANY_EGRESS === "log") return KEEP_JP_NODES;
  return !COMPANY_EGRESS.test(txt);
}

async function main(params) {
  if (!params.proxies) return params;
  // KEEP_JP_NODES=false 时整段剔除日本节点（公司网络拦其入口）。
  // 其余 28 个节点入口同为 36.141.40.13（移动广东，同 IP 不同端口，单连接 ~1MB/s 的整形在那里）；
  // 日本Z05/Z06、免费-日本1~7 走 AWS 东京，不经该入口，所以家里下单流更快（别外推到公司线路）。
  const allowJp = await shouldKeepJpNodes();
  if (jpRegion && !allowJp) {
    params.proxies = params.proxies.filter((proxy) => !jpRegion.regex.test(proxy.name));
  }
  overwriteRules(params);
  overwriteProxyGroups(params);
  overwriteDns(params);
  return params;
}

const countryRegions = [
  { code: "HK", name: "香港", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg", regex: /(香港|HK|Hong Kong|🇭🇰)(?!.*(中国|China|PRC))/i },
  { code: "SG", name: "新加坡", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg", regex: /(新加坡|狮城|SG|Singapore|🇸🇬)/i },
  { code: "JP", name: "日本", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/jp.svg", regex: /(日本|JP|Japan|🇯🇵)/i },
  { code: "US", name: "美国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg", regex: /^(?!.*(Plus|plus|custom)).*(美国|US|USA|United States|America|🇺🇸)/i },
  { code: "UK", name: "英国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/gb.svg", regex: /(英国|UK|United Kingdom|Britain|Great Britain|🇬🇧)/i },
  //{ code: "TW", name: "台湾", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg", regex: /(台湾|\bTW\b|Taiwan|🇹🇼)(?!.*(中国|CN|China|PRC|🇨🇳))(?!.*Networks)/i },
  //{ code: "KR", name: "韩国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/kr.svg", regex: /(韩国|KR|Korea|South Korea|🇰🇷)/i },
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

// 分组与剔除共用这一份正则
const jpRegion = countryRegions.find((r) => r.code === "JP");

function getTestUrlForGroup(groupName) {
  switch (groupName) {
    case "Google":
      return "https://www.google.com/";
    case "Steam":
      return "https://store.steampowered.com/";
    case "Telegram":
      return "https://web.telegram.org/";
    case "OpenAI":
      return "https://chat.openai.com/";
    // case "Claude":
    //   return "https://claude.ai/";
    case "Spotify":
      return "https://www.spotify.com/";
    default:
      return "http://www.gstatic.com/generate_204";
  }
}

function getIconForGroup(groupName) {
  switch (groupName) {
    case "User Proxy":
      return "https://fastly.jsdelivr.net/gh/luzov/Clash-Rules@main/assets/icons/at.svg";
    case "Google":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/google.svg";
    case "Telegram":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg";
    case "OpenAI":
      return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg";
    // case "Claude":
    //   return "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/claude.svg";
    case "Spotify":
      return "https://storage.googleapis.com/spotifynewsroom-jp.appspot.com/1/2020/12/Spotify_Icon_CMYK_Green.png";
    case "Steam":
      return "https://store.steampowered.com/favicon.ico";
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
    // 冲突子域（拒识列表）先拦，再走你那份宽泛的 user_proxy_rules；
    // 要在 user_proxy_rules 下放行某个子域，把对应行从仓库 user_reject_rules.txt 删掉即可。
    "RULE-SET,user_reject_rules,广告拦截",
    "RULE-SET,user_proxy_rules,User Proxy",
    "RULE-SET,reject,广告拦截",
    "RULE-SET,google,Google",
    "RULE-SET,steam,Steam",
    "RULE-SET,private,DIRECT",
    "RULE-SET,direct,DIRECT",
    "RULE-SET,applications,DIRECT",
    "RULE-SET,openai,OpenAI",
    // Claude 规则集与分组都已下线（provider 一并删除），要恢复需同时加回 provider + 规则 + 分组。
    "RULE-SET,spotify,Spotify",
    "RULE-SET,telegramcidr,Telegram,no-resolve",
    "RULE-SET,apple," + proxyName,
    "RULE-SET,icloud," + proxyName,
    "RULE-SET,greatfire," + proxyName,
    "RULE-SET,gfw," + proxyName,
    "RULE-SET,proxy," + proxyName,
    "RULE-SET,tld-not-cn," + proxyName,
    // IP 类规则放最后：cncidr/lancidr 无 no-resolve，会触发真实解析；GEOIP,CN 带 no-resolve 在 fake-ip 下只剩字面 IP 命中
    "RULE-SET,lancidr,DIRECT",
    "GEOIP,LAN,DIRECT,no-resolve",
    "RULE-SET,cncidr,DIRECT",
    "GEOIP,CN,DIRECT,no-resolve",
    "MATCH,漏网之鱼",
  ];
  const ruleProviders = {
    user_proxy_rules: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/luzov/Clash-Rules/refs/heads/main/user_proxy_rules.txt",
      path: "./ruleset/user_proxy_rules.yaml",
      interval: 86400,
    },
    // 拒识列表：user_proxy_rules 与 reject 冲突的子域（仓库 user_reject_rules.txt），排在 user_proxy_rules 之前
    user_reject_rules: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/luzov/Clash-Rules/main/user_reject_rules.txt",
      path: "./ruleset/user_reject_rules.yaml",
      interval: 86400,
    },
    steam: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/luzov/Clash-Rules/refs/heads/main/Steam.txt",
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
      interval: 86400,
    },
    // claude provider 已删：无任何 RULE-SET 引用却每天下载一次；要启用需连带规则/分组一起加回
    spotify: {
      type: "http",
      behavior: "classical",
      url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Spotify/Spotify.yaml",
      path: "./ruleset/custom/Spotify.yaml",
      interval: 86400,
    },
    telegramcidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
      path: "./ruleset/custom/telegramcidr.yaml",
      interval: 86400,
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
      // 节点同属一个入海口，延时差小、抖动大，拉长探测间隔 + 只在选中时探测
      interval: 600,
      tolerance: 50,
      lazy: true,
      proxies: getProxiesByRegex(params, item.regex),
      hidden: true,
    }))
    .filter((item) => item.proxies.length > 0);

  const manualProxyGroupsConfig = countryRegions
    .filter(region => availableCountryCodes.has(region.code))
    .map(region => ({
      name: `${region.code} - 手动选择`,
      type: "select",
      proxies: getManualProxiesByRegex(params, region),
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
      proxies: ["ALL - 自动选择", ...autoProxyGroups.map(group => group.name)],
    },

    {
      name: "负载均衡 (散列)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/balance.svg",
      interval: 600,
      "max-failed-times": 3,
      strategy: "consistent-hashing",
      lazy: true,
      // 只散列 港/新/日：其余国家延时 500ms+，会把会话钉死在慢节点上
      proxies: getProxiesByRegex(params, /香港|HK|新加坡|SG|日本/i),
      hidden: true,
    },

    {
      name: "负载均衡 (轮询)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/merry_go.svg",
      interval: 600,
      "max-failed-times": 3,
      strategy: "round-robin",
      lazy: true,
      proxies: getProxiesByRegex(params, /香港|HK|新加坡|SG|下载专用/i),
      hidden: true,
    },

    {
      name: "ALL - 自动选择",
      type: "url-test",
      url: "http://www.gstatic.com/generate_204",
      interval: 600,
      tolerance: 50,
      proxies: allProxies.length > 0 ? allProxies : ["DIRECT"],
      hidden: true,
    },

    ...[
      "User Proxy",
      "Google",
      "Telegram",
      "OpenAI",
      // "Claude", 
      "Steam",
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
    interval: 600,
    tolerance: 50,
    lazy: true,
    proxies: otherProxies.length > 0 ? otherProxies : ["手动选择"],
    hidden: true,
  });

  groups.push(...autoProxyGroups);
  groups.push(...manualProxyGroupsConfig);
  params["proxy-groups"] = groups;
}

function overwriteDns(params) {
  const cnDnsList = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"];
  const dnsOptions = {
    enable: true,
    "prefer-h3": false,                                  // H3 走隧道更易卡，且与 respect-rules 不兼容
    "default-nameserver": ["tls://223.5.5.5"],            // 仅用于解析上面这些 DoH 的域名，必须是 IP
    nameserver: cnDnsList,
    "proxy-server-nameserver": cnDnsList,                 // 解析代理节点域名（*.qpon）
    "direct-nameserver": cnDnsList,                       // DIRECT 出口专用解析：直连域名不再受代理 DNS 影响
    // nameserver-policy 优先于 nameserver/fallback；直连只到得了国内 DoH，所以两类都钉国内 DoH
    // （改前 bing.com / *.tailscale.com 被上游不可达打到解析失败）。本客户端无 fallback/fallback-filter
    // 字段，写进覆写也会被生成流程剔掉；要让国外 DNS 走梯子得改 TUN + respect-rules。
    "nameserver-policy": {
      "geosite:cn": cnDnsList,
      "geosite:geolocation-!cn": cnDnsList,
    },
  };
  // sniffer/geox-url/geodata-mode/profile 等写在这里不生效（客户端表单会覆盖），要改去客户端「内核」设置
  params.dns = { ...params.dns, ...dnsOptions };
}

function getProxiesByRegex(params, regex) {
  const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
  return matchedProxies.length > 0 ? matchedProxies : ["手动选择"];
}

function getManualProxiesByRegex(params, region) {
  const matchedProxies = params.proxies.filter((e) => region.regex.test(e.name)).map((e) => e.name);
  if (region.code === "CN") return ["DIRECT", ...matchedProxies, "手动选择", proxyName];
  return matchedProxies.length > 0 ? matchedProxies : ["DIRECT", "手动选择", proxyName];
}