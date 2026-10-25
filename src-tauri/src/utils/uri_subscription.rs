use std::borrow::Cow;

use serde_yaml_ng::Mapping;

use super::yaml_emitter::to_mihomo_config_string;

/// Schemes of share links that can be converted into mihomo proxies.
const SUPPORTED_SCHEMES: &[&str] = &[
    "vless://", "vmess://", "ss://", "trojan://", "hysteria2://", "hy2://",
];

/// Normalizes raw subscription text into mihomo YAML.
///
/// Returns the original text when it is already a valid Clash config; otherwise
/// tries base64 decoding and share-link parsing (vless/vmess/ss/trojan/hysteria2)
/// and converts detected nodes into a `proxies:` YAML document.
pub fn normalize_subscription_text(data: &str) -> Cow<'_, str> {
    if is_valid_clash_config(data) {
        return Cow::Borrowed(data);
    }

    let candidate = decode_base64_body(data).unwrap_or_else(|| data.to_string());
    if is_valid_clash_config(&candidate) {
        return Cow::Owned(candidate);
    }

    match convert_uri_lines(&candidate) {
        Some(yaml) => Cow::Owned(yaml),
        None => Cow::Borrowed(data),
    }
}

fn is_valid_clash_config(text: &str) -> bool {
    serde_yaml_ng::from_str::<Mapping>(text)
        .ok()
        .is_some_and(|yaml| yaml.contains_key("proxies") || yaml.contains_key("proxy-providers"))
}

/// Decodes a base64-encoded subscription body (URL-safe or standard, padded or not).
fn decode_base64_body(data: &str) -> Option<std::string::String> {
    let cleaned: std::string::String = data.chars().filter(|c| !c.is_whitespace()).collect();
    // URLs and share-link lists are not base64; bail out early.
    if cleaned.is_empty() || cleaned.contains("://") {
        return None;
    }

    use base64::Engine as _;
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(cleaned.as_bytes())
            && let Ok(text) = std::string::String::from_utf8(bytes)
        {
            let text = text.trim_start_matches('\u{feff}').to_string();
            if text.starts_with('{') || SUPPORTED_SCHEMES.iter().any(|s| text.contains(s)) {
                return Some(text);
            }
        }
    }
    None
}

/// Converts every parseable share link into a `proxies:` YAML document.
fn convert_uri_lines(text: &str) -> Option<std::string::String> {
    let mut proxies: Vec<Mapping> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(proxy) = parse_proxy_uri(line) {
            proxies.push(proxy);
        }
    }
    if proxies.is_empty() {
        return None;
    }

    let mut config = Mapping::new();
    config.insert(
        "proxies".into(),
        serde_yaml_ng::Value::Sequence(proxies.into_iter().map(serde_yaml_ng::Value::Mapping).collect()),
    );
    to_mihomo_config_string(&config).ok()
}

/// Parses a single share link into a mihomo proxy mapping.
pub fn parse_proxy_uri(line: &str) -> Option<Mapping> {
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("vless://") {
        parse_vless(line)
    } else if lower.starts_with("vmess://") {
        parse_vmess(line)
    } else if lower.starts_with("ss://") {
        parse_ss(line)
    } else if lower.starts_with("trojan://") {
        parse_trojan(line)
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        parse_hysteria2(line)
    } else {
        None
    }
}

fn percent_decode(value: &str) -> std::string::String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.to_string())
        .unwrap_or_else(|_| value.to_string())
}

/// Minimal query-string parser (split on '&' then '=', percent-decoded).
fn parse_query(query: &str) -> std::collections::BTreeMap<std::string::String, std::string::String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            if k.is_empty() {
                None
            } else {
                Some((percent_decode(k).to_lowercase(), percent_decode(v)))
            }
        })
        .collect()
}

fn base_mapping(server: &str, port: u16, name: &str, proxy_type: &str) -> Mapping {
    let mut map = Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), proxy_type.into());
    map.insert("server".into(), server.into());
    map.insert("port".into(), port.into());
    map
}

fn insert_opt(map: &mut Mapping, key: &str, value: Option<std::string::String>) {
    if let Some(value) = value
        && !value.is_empty()
    {
        map.insert(key.into(), value.into());
    }
}

fn extract_fragment(rest: &str) -> (&str, Option<std::string::String>) {
    match rest.split_once('#') {
        Some((main, frag)) => (main, Some(percent_decode(frag))),
        None => (rest, None),
    }
}

/// `vless://uuid@host:port?params#name`
fn parse_vless(line: &str) -> Option<Mapping> {
    let rest = line.strip_prefix("vless://")?;
    let (main, frag) = extract_fragment(rest);
    let (addr, query_str) = match main.split_once('?') {
        Some((addr, q)) => (addr, q),
        None => (main, ""),
    };
    let (userinfo, hostport) = addr.split_once('@')?;
    let (host, port) = split_host_port(hostport)?;
    let query = parse_query(query_str);

    let mut map = base_mapping(&host, port, &frag.unwrap_or_else(|| host.clone()), "vless");
    map.insert("uuid".into(), percent_decode(userinfo).into());

    let security = query.get("security").map(|s| s.as_str()).unwrap_or("");
    match security {
        "reality" => {
            map.insert("tls".into(), true.into());
            insert_opt(&mut map,"servername", query.get("sni").cloned());
            insert_opt(&mut map,"public-key", query.get("pbk").cloned());
            insert_opt(&mut map,"short-id", query.get("sid").cloned());
            insert_opt(&mut map,"client-fingerprint", query.get("fp").cloned());
        }
        "tls" => {
            map.insert("tls".into(), true.into());
            insert_opt(&mut map,"servername", query.get("sni").cloned());
            insert_opt(&mut map,"client-fingerprint", query.get("fp").cloned());
            if query.get("allowinsecure").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
                map.insert("skip-cert-verify".into(), true.into());
            }
        }
        _ => {}
    }

    if let Some(flow) = query.get("flow").filter(|f| !f.is_empty()) {
        map.insert("flow".into(), flow.clone().into());
    }

    match query.get("type").map(|s| s.as_str()).unwrap_or("tcp") {
        "ws" => {
            let mut ws = Mapping::new();
            insert_opt(&mut ws,"path", query.get("path").cloned());
            let host_header = query.get("host").cloned();
            if let Some(host_header) = host_header {
                let mut headers = Mapping::new();
                headers.insert("Host".into(), host_header.into());
                ws.insert("headers".into(), headers.into());
            }
            map.insert("ws-opts".into(), ws.into());
        }
        "grpc" => {
            let mut grpc = Mapping::new();
            insert_opt(&mut grpc,"grpc-service-name", query.get("serviceName").cloned());
            map.insert("grpc-opts".into(), grpc.into());
        }
        _ => {}
    }

    Some(map)
}

/// `vmess://base64(json)`
fn parse_vmess(line: &str) -> Option<Mapping> {
    use base64::Engine as _;
    let raw = line.strip_prefix("vmess://")?;
    let decoded = percent_decode(raw);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(decoded.trim().as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(decoded.trim().as_bytes()))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    let server = json.get("add")?.as_str()?.to_string();
    let port = match json.get("port")? {
        serde_json::Value::Number(n) => n.as_u64()? as u16,
        serde_json::Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    let name = json
        .get("ps")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| server.clone());

    let mut map = base_mapping(&server, port, &name, "vmess");
    map.insert("uuid".into(), json.get("id")?.as_str()?.into());
    map.insert("alterId".into(), json.get("aid").and_then(|v| v.as_u64()).unwrap_or(0).into());
    map.insert("cipher".into(), json.get("scy").and_then(|v| v.as_str()).unwrap_or("auto").into());

    let tls_flag = json.get("tls").and_then(|v| v.as_str()).is_some_and(|v| v == "tls");
    if tls_flag {
        map.insert("tls".into(), true.into());
        insert_opt(&mut map,"servername", json.get("sni").and_then(|v| v.as_str()).map(|s| s.to_string()));
    }

    let net = json.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
    if net == "ws" {
        let mut ws = Mapping::new();
        insert_opt(&mut ws,"path", json.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()));
        let host_header = json.get("host").and_then(|v| v.as_str()).map(|s| s.to_string());
        if let Some(host_header) = host_header {
            let mut headers = Mapping::new();
            headers.insert("Host".into(), host_header.into());
            ws.insert("headers".into(), headers.into());
        }
        map.insert("ws-opts".into(), ws.into());
    } else if net == "grpc" {
        let mut grpc = Mapping::new();
        insert_opt(
            &mut grpc,
            "grpc-service-name",
            json.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
        );
        map.insert("grpc-opts".into(), grpc.into());
    }

    Some(map)
}

/// `ss://base64(method:password)@host:port#name` or `ss://base64(method:password@host:port)#name`
fn parse_ss(line: &str) -> Option<Mapping> {
    use base64::Engine as _;
    let rest = line.strip_prefix("ss://")?;
    let (main, frag) = extract_fragment(rest);
    let name = frag.unwrap_or_default();

    let (host, port, method, password);
    if let Some((encoded, hostport)) = main.rsplit_once('@') {
        // plugin part (after '?') is ignored for now
        let hostport = hostport.split('?').next().unwrap_or(hostport);
        let (h, p) = split_host_port(hostport)?;
        host = h;
        port = p;
        let encoded = encoded.trim_start_matches('/');
        let userinfo = percent_decode(encoded);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(userinfo.trim().as_bytes())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(userinfo.trim().as_bytes()))
            .ok()
            .and_then(|bytes| std::string::String::from_utf8(bytes).ok())
            .unwrap_or(userinfo);
        let (m, pwd) = decoded.split_once(':')?;
        method = m.to_string();
        password = pwd.to_string();
    } else {
        // fully encoded: ss://base64(method:password@host:port)#name
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(main.trim().as_bytes())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(main.trim().as_bytes()))
            .ok()
            .and_then(|bytes| std::string::String::from_utf8(bytes).ok())?;
        let decoded = percent_decode(&decoded);
        let (userinfo, hostport) = decoded.rsplit_once('@')?;
        let (h, p) = split_host_port(hostport)?;
        host = h;
        port = p;
        let (m, pwd) = userinfo.split_once(':')?;
        method = m.to_string();
        password = pwd.to_string();
    }

    let mut map = base_mapping(
        &host,
        port,
        &if name.is_empty() { host.clone() } else { name },
        "ss",
    );
    map.insert("cipher".into(), method.into());
    map.insert("password".into(), password.into());
    Some(map)
}

/// `trojan://password@host:port?sni=...#name`
fn parse_trojan(line: &str) -> Option<Mapping> {
    let rest = line.strip_prefix("trojan://")?;
    let (main, frag) = extract_fragment(rest);
    let (userinfo, hostport) = main.split_once('@')?;
    let hostport = hostport.split('?').next().unwrap_or(hostport);
    let (host, port) = split_host_port(hostport)?;
    let query = parse_query(main.split_once('?').map(|(_, q)| q).unwrap_or(""));

    let mut map = base_mapping(&host, port, &frag.unwrap_or_else(|| host.clone()), "trojan");
    map.insert("password".into(), percent_decode(userinfo).into());
    map.insert("udp".into(), true.into());
    insert_opt(&mut map,"sni", query.get("sni").cloned().or_else(|| query.get("peer").cloned()));
    if query.get("allowinsecure").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        map.insert("skip-cert-verify".into(), true.into());
    }
    Some(map)
}

/// `hysteria2://password@host:port?sni=...#name`
fn parse_hysteria2(line: &str) -> Option<Mapping> {
    let lower = line.to_ascii_lowercase();
    let rest = if lower.starts_with("hysteria2://") {
        &line["hysteria2://".len()..]
    } else {
        line.strip_prefix("hy2://")?
    };
    let (main, frag) = extract_fragment(rest);
    let (userinfo, hostport) = main.split_once('@')?;
    let hostport = hostport.split('?').next().unwrap_or(hostport);
    let (host, port) = split_host_port(hostport)?;
    let query = parse_query(main.split_once('?').map(|(_, q)| q).unwrap_or(""));

    let mut map = base_mapping(&host, port, &frag.unwrap_or_else(|| host.clone()), "hysteria2");
    map.insert("password".into(), percent_decode(userinfo).into());
    insert_opt(&mut map,"sni", query.get("sni").cloned());
    if query.get("insecure").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        map.insert("skip-cert-verify".into(), true.into());
    }
    if let Some(obfs) = query.get("obfs").filter(|o| !o.is_empty() && o.as_str() != "none") {
        let mut opts = Mapping::new();
        opts.insert("type".into(), obfs.clone().into());
        insert_opt(&mut opts,"password", query.get("obfs-password").cloned());
        map.insert("obfs".into(), opts.into());
    }
    Some(map)
}

fn split_host_port(hostport: &str) -> Option<(std::string::String, u16)> {
    let hostport = hostport.trim();
    if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal [::1]:443
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.trim().parse().ok()?));
    }
    let (host, port) = hostport.rsplit_once(':')?;
    Some((host.to_string(), port.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_config_passes_through() {
        let yaml = "proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 1\n";
        assert!(matches!(normalize_subscription_text(yaml), Cow::Borrowed(_)));
    }

    #[test]
    fn vless_link_is_converted() {
        let text = "vless://test-uuid@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=cdn.example.com&path=%2Fws#My%20Node";
        let out = normalize_subscription_text(text);
        assert!(out.contains("type: vless"), "got: {out}");
        assert!(out.contains("My Node"), "got: {out}");
        assert!(out.contains("ws-opts"), "got: {out}");
    }

    #[test]
    fn base64_vless_list_is_converted() {
        use base64::Engine as _;
        let body = "vless://uid@a.com:443?security=tls#A\nvless://uid@b.com:8443?security=reality&pbk=k#B\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        let out = normalize_subscription_text(&encoded);
        assert!(out.contains("a.com"), "got: {out}");
        assert!(out.contains("b.com"), "got: {out}");
        assert!(out.contains("public-key"), "got: {out}");
    }

    #[test]
    fn reality_fields_are_mapped() {
        let text = "vless://u@h.com:443?security=reality&sni=h.com&fp=chrome&pbk=PUBKEY&sid=abcd&flow=xtls-rprx-vision&type=tcp#R1";
        let proxy = parse_proxy_uri(text).unwrap();
        assert_eq!(proxy.get("public-key").and_then(|v| v.as_str()), Some("PUBKEY"));
        assert_eq!(proxy.get("flow").and_then(|v| v.as_str()), Some("xtls-rprx-vision"));
    }

    #[test]
    fn ss_plain_userinfo_is_converted() {
        let text = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#SSNode";
        let proxy = parse_proxy_uri(text).unwrap();
        assert_eq!(proxy.get("cipher").and_then(|v| v.as_str()), Some("aes-256-gcm"));
        assert_eq!(proxy.get("password").and_then(|v| v.as_str()), Some("password"));
    }

    #[test]
    fn trojan_link_is_converted() {
        let text = "trojan://pass@t.com:443?sni=t.com&allowinsecure=1#T1";
        let proxy = parse_proxy_uri(text).unwrap();
        assert_eq!(proxy.get("type").and_then(|v| v.as_str()), Some("trojan"));
        assert_eq!(proxy.get("skip-cert-verify").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn hysteria2_link_is_converted() {
        let text = "hy2://pass@h2.com:443?sni=h2.com&obfs=salamander&obfs-password=xyz#H2";
        let proxy = parse_proxy_uri(text).unwrap();
        assert_eq!(proxy.get("type").and_then(|v| v.as_str()), Some("hysteria2"));
        assert!(proxy.contains_key("obfs"));
    }
}
