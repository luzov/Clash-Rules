function main(params) {
	addRejectIPRuleWithHighestPriority(params, "183.230.113.152");
	return params;
}

function addRejectIPRuleWithHighestPriority(params, ipAddress) {
	const lanRuleIndex = params.rules.findIndex(rule => rule.startsWith("GEOIP,LAN,DIRECT"));
	
	if (lanRuleIndex !== -1) {
		params.rules.splice(lanRuleIndex + 1, 0, `IP-CIDR,${ipAddress}/32,REJECT`);
		params.rules.splice(lanRuleIndex + 2, 0, `PROCESS-NAME,ywSMPAgent.exe,REJECT`);
		params.rules.splice(lanRuleIndex + 3, 0, `PROCESS-NAME,ywSMPASvr.exe,REJECT`);
	} else {
		params.rules.unshift(`IP-CIDR,${ipAddress}/32,REJECT`);
		params.rules.unshift(`PROCESS-NAME,ywSMPAgent.exe,REJECT`);
		params.rules.unshift(`PROCESS-NAME,ywSMPASvr.exe,REJECT`);
	}
}
