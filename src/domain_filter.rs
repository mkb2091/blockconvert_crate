use crate::{Domain, DomainSetShardedDefault};

use fxhash::FxHashMap;
use fxhash::FxHashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
struct Filter<T: Default> {
    allow: T,
    disallow: T,
}

#[derive(Debug, Default)]
struct AdblockParseError {}

impl std::error::Error for AdblockParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for AdblockParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct AdblockFilter {
    is_exception: bool,
    match_start_domain: bool,
    match_start_address: bool,
    match_end_domain: bool,
    filter: String,
    is_badfilter: bool,
}

impl FromStr for AdblockFilter {
    type Err = AdblockParseError;
    fn from_str(original_rule: &str) -> Result<Self, Self::Err> {
        let mut rule = original_rule;
        if rule.starts_with('!') {
            // Remove comments
            return Err(AdblockParseError::default());
        }
        if rule.contains('#')
        // Element Hiding
        {
            return Err(AdblockParseError::default());
        }
        let mut is_badfilter = false;
        if let Some(position) = rule.find('$') {
            let (start, tags) = rule.split_at(position);
            let tags = tags
                .trim_start_matches('$')
                .split(',')
                .filter(|tag| !matches!(*tag, "3p" | "third-party"))
                .filter(|tag| {
                    if *tag == "badfilter" {
                        is_badfilter = true;
                        false
                    } else {
                        true
                    }
                })
                .collect::<Vec<&str>>();

            if !(tags.is_empty() || tags.contains(&"document") || tags.contains(&"all"))
                || tags.iter().any(|tag| tag.starts_with("domain="))
            {
                return Err(AdblockParseError::default());
            }
            rule = start;
        }
        let (rule, is_exception) = rule
            .strip_prefix("@@")
            .map(|rule| (rule, true))
            .unwrap_or((rule, false));

        let (rule, match_start_domain, match_start_address) =
            if let Some(rule) = rule.strip_prefix("||") {
                (rule, true, false)
            } else {
                let (rule, match_start_address) = rule
                    .strip_prefix('|')
                    .map(|rule| (rule, true))
                    .unwrap_or((rule, false));
                let (rule, match_start_address) = rule
                    .strip_prefix('*')
                    .or_else(|| rule.strip_prefix("http"))
                    .or_else(|| rule.strip_prefix("https"))
                    .unwrap_or(rule)
                    .strip_prefix("://")
                    .map(|rule| (rule, true))
                    .unwrap_or((rule, match_start_address));
                (rule, false, match_start_address)
            };
        let (rule, match_start_domain, match_start_address) = rule
            .strip_prefix('*')
            .unwrap_or(rule)
            .strip_prefix('.')
            .map(|rule| (rule, true, false))
            .unwrap_or((rule, match_start_domain, match_start_address));

        let (rule, match_end_domain) = rule
            .strip_suffix('|')
            .map(|rule| (rule, true))
            .unwrap_or((rule, false));
        let (rule, match_end_domain) = rule
            .strip_suffix(".php")
            .or_else(|| rule.strip_suffix(".htm"))
            .or_else(|| rule.strip_suffix(".html"))
            .or_else(|| rule.strip_suffix(".xhtml"))
            .unwrap_or(rule)
            .strip_suffix('*')
            .and_then(|rule| rule.strip_suffix('/').or(Some(rule)))
            .map(|rule| (rule, true))
            .unwrap_or((rule, match_end_domain));
        let (rule, match_end_domain) = rule
            .strip_suffix('^')
            .map(|rule| (rule, true))
            .unwrap_or((rule, match_end_domain));
        let (rule, match_end_domain) = rule
            .strip_suffix('.')
            .map(|rule| (rule, false))
            .unwrap_or((rule, match_end_domain));
        if rule.is_empty()
            || rule == "*"
            || !rule
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*'))
        {
            return Err(AdblockParseError::default());
        }
        Ok(Self {
            is_exception,
            match_start_domain,
            match_start_address,
            match_end_domain,
            filter: rule.to_string(),
            is_badfilter,
        })
    }
}

#[derive(Default, Clone)]
pub struct DomainFilterBuilder {
    domains: Filter<DomainSetShardedDefault>,
    subdomains: Filter<DomainSetShardedDefault>,
    ips: Arc<Mutex<Filter<FxHashSet<std::net::IpAddr>>>>,
    ip_nets: Arc<Mutex<Filter<FxHashSet<ipnet::IpNet>>>>,
    regexes: Arc<Mutex<Filter<FxHashSet<String>>>>,
    adblock: Arc<Mutex<FxHashSet<AdblockFilter>>>,
}

impl DomainFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_allow_domain(&self, domain: Domain) {
        if let Some(without_www) = domain
            .strip_prefix("www.")
            .and_then(|domain| domain.parse::<Domain>().ok())
        {
            self.domains.disallow.remove_str(&without_www);
            self.domains.allow.insert_str(&without_www);
        } else if let Ok(with_www) = format!("www.{}", &domain).parse::<Domain>() {
            self.domains.disallow.remove_str(&with_www);
            self.domains.allow.insert_str(&with_www);
        }
        self.domains.disallow.remove_str(&domain);
        self.domains.allow.insert_str(&domain);
    }
    pub fn add_disallow_domain(&self, domain: Domain) {
        if !self.domains.allow.contains_str(&domain)
            && !is_subdomain_of_list(&domain, &self.subdomains.allow)
        {
            self.domains.disallow.insert_str(&domain);
        }
    }
    pub fn add_allow_subdomain(&self, domain: Domain) {
        self.subdomains.disallow.remove_str(&domain);
        self.subdomains.allow.insert_str(&domain);
    }
    pub fn add_disallow_subdomain(&self, domain: Domain) {
        if !self.subdomains.allow.contains_str(&domain) {
            self.subdomains.disallow.insert_str(&domain);
        }
    }

    pub fn add_allow_ip_addr(&self, ip: std::net::IpAddr) {
        let mut ips = self.ips.lock().unwrap();
        let _ = ips.disallow.remove(&ip);
        ips.allow.insert(ip);
    }
    pub fn add_disallow_ip_addr(&self, ip: std::net::IpAddr) {
        let mut ips = self.ips.lock().unwrap();
        if !ips.allow.contains(&ip) {
            ips.disallow.insert(ip);
        }
    }

    pub fn add_allow_ip_subnet(&self, net: ipnet::IpNet) {
        let mut ip_nets = self.ip_nets.lock().unwrap();
        let _ = ip_nets.disallow.remove(&net);
        ip_nets.allow.insert(net);
    }

    pub fn add_disallow_ip_subnet(&self, ip: ipnet::IpNet) {
        let mut ip_nets = self.ip_nets.lock().unwrap();
        if !ip_nets.allow.contains(&ip) {
            ip_nets.disallow.insert(ip);
        }
    }

    pub fn add_adblock_rule(&self, rule: &str) {
        if let Ok(filter) = rule.parse::<AdblockFilter>() {
            self.adblock.lock().unwrap().insert(filter);
        }
    }

    pub fn add_allow_regex(&self, re: &str) {
        if !re.is_empty() && regex::Regex::new(re).is_ok() {
            let mut regexes = self.regexes.lock().unwrap();
            regexes.allow.insert(re.to_string());
        }
    }
    pub fn add_disallow_regex(&self, re: &str) {
        if !re.is_empty() && regex::Regex::new(re).is_ok() {
            let mut regexes = self.regexes.lock().unwrap();
            regexes.disallow.insert(re.to_string());
        }
    }

    pub fn to_domain_filter(mut self) -> DomainFilter {
        let mut adblock = std::mem::take(&mut *self.adblock.lock().unwrap());

        for filter in adblock.iter() {
            let mut bad_filter = filter.clone();
            bad_filter.is_badfilter = true;
            if adblock.contains(&bad_filter) {
                continue;
            }
            if (filter.match_start_domain || filter.match_start_address) && filter.match_end_domain
            {
                if let Ok(domain) = filter.filter.parse::<Domain>() {
                    if filter.is_exception {
                        self.add_allow_domain(domain.clone());
                        if filter.match_start_domain {
                            self.add_allow_subdomain(domain);
                        }
                    } else {
                        self.add_disallow_domain(domain.clone());
                        if filter.match_start_domain {
                            self.add_disallow_subdomain(domain);
                        }
                    }
                }
                if let Ok(ip) = filter.filter.parse::<std::net::IpAddr>() {
                    if !filter.is_exception {
                        // Currently no IP exception filters, so no benefit from implementing
                        self.add_disallow_ip_addr(ip);
                    }
                }
            }
        }

        let mut domains = self.domains;
        let mut subdomains = self.subdomains;
        let mut ips = std::mem::take(&mut *self.ips.lock().unwrap());
        let ip_nets = std::mem::take(&mut *self.ip_nets.lock().unwrap());
        let regexes = std::mem::take(&mut *self.regexes.lock().unwrap());

        domains.allow.shrink_to_fit();
        domains.disallow.shrink_to_fit();
        subdomains.allow.shrink_to_fit();
        subdomains.disallow.shrink_to_fit();
        ips.allow.shrink_to_fit();
        ips.disallow.shrink_to_fit();
        let ip_nets = Filter {
            allow: ip_nets.allow.into_iter().collect(),
            disallow: ip_nets.disallow.into_iter().collect(),
        };
        DomainFilter {
            domains,
            subdomains,
            ips,
            ip_nets: ip_nets,
            allow_regex: regex::RegexSet::new(&regexes.allow).unwrap(),
            disallow_regex: regex::RegexSet::new(&regexes.disallow).unwrap(),
        }
    }
}

fn is_subdomain_of_list(domain: &Domain, filter_list: &DomainSetShardedDefault) -> bool {
    domain
        .iter_parent_domains()
        .any(|part| filter_list.contains_str(&part))
}

pub struct DomainFilter {
    domains: Filter<DomainSetShardedDefault>,
    subdomains: Filter<DomainSetShardedDefault>,
    ips: Filter<FxHashSet<std::net::IpAddr>>,
    ip_nets: Filter<Vec<ipnet::IpNet>>,
    allow_regex: regex::RegexSet,
    disallow_regex: regex::RegexSet,
}

impl DomainFilter {
    fn is_allowed_by_adblock(&self, _location: &str) -> Option<bool> {
        None
    }

    pub fn allowed(
        &self,
        domain: &Domain,
        cnames: &[Domain],
        ips: &[std::net::IpAddr],
    ) -> Option<bool> {
        if let Some(result) = self.domain_is_allowed(domain) {
            Some(result)
        } else if cnames
            .iter()
            .any(|cname| self.domain_is_allowed(cname) == Some(false))
            || ips.iter().any(|ip| self.ip_is_allowed(ip) == Some(false))
        {
            Some(false)
        } else {
            None
        }
    }

    fn domain_is_allowed(&self, domain: &Domain) -> Option<bool> {
        if self.domains.allow.contains_str(&domain)
            || is_subdomain_of_list(&*domain, &self.subdomains.allow)
            || self.allow_regex.is_match(domain)
        {
            Some(true)
        } else if let Some(blocker_result) = self.is_allowed_by_adblock(&domain) {
            Some(blocker_result)
        } else if self.domains.disallow.contains_str(&domain)
            || is_subdomain_of_list(&*domain, &self.subdomains.disallow)
            || self.disallow_regex.is_match(domain)
        {
            Some(false)
        } else {
            None
        }
    }

    pub fn ip_is_allowed(&self, ip: &std::net::IpAddr) -> Option<bool> {
        if self.ips.allow.contains(ip) || self.ip_nets.allow.iter().any(|net| net.contains(ip)) {
            Some(true)
        } else if let Some(blocker_result) = self.is_allowed_by_adblock(&ip.to_string()) {
            Some(blocker_result)
        } else if self.ips.disallow.contains(ip)
            || self.ip_nets.disallow.iter().any(|net| net.contains(ip))
        {
            Some(false)
        } else {
            None
        }
    }
}

#[test]
fn default_unblocked() {
    assert_eq!(
        DomainFilterBuilder::new()
            .to_domain_filter()
            .domain_is_allowed(&"example.org".parse().unwrap()),
        None
    )
}

#[test]
fn regex_disallow_all_blocks_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.org".parse().unwrap()),
        Some(false)
    )
}
#[test]
fn regex_allow_overrules_regex_disallow() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_allow_regex(".");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.org".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn adblock_can_block_domain_and_subdomain() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(false)
    );
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        Some(false)
    )
}
#[test]
fn adblock_does_not_block_subdomain_for_exact() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("|example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(false)
    );
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        None
    )
}

#[test]
fn adblock_does_not_block_filter_that_has_badfilter() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||cedexis.net^$third-party");
    filter.add_adblock_rule("||cedexis.net^$third-party,badfilter");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"cedexis.net".parse().unwrap()),
        None
    );
}

#[test]
fn adblock_can_block_ip() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||177.33.90.14^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.ip_is_allowed(&"177.33.90.14".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn adblock_can_block_domain_document() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||ditwrite.com^$document");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"ditwrite.com".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn adblock_can_block_with_partial_domains() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("-ad.example.com");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"2-ad.example.com".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn adblock_can_whitelist_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_adblock_rule("@@||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(true)
    );
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn adblock_does_not_whitelist_domain_for_exact() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("@@|example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(true)
    );
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        None
    )
}

#[test]
fn adblock_third_party_does_block_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com^$third-party");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(false)
    );
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn subdomain_disallow_blocks() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn subdomain_allow_whitelists_domains() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_allow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example_subdomain.example.com".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn subdomain_disallow_does_not_block_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        None
    )
}

#[test]
fn blocked_cname_blocks_base() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_domain("tracker.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &["tracker.com".parse().unwrap()],
            &[]
        ),
        Some(false)
    )
}

#[test]
fn blocked_ip_blocks_base() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_ip_addr("8.8.8.8".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        Some(false)
    )
}

#[test]
fn blocked_ip_net_blocks_base() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_ip_subnet("8.8.8.0/24".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        Some(false)
    )
}

#[test]
fn ignores_allowed_ips() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_domain("example.com".parse().unwrap());
    filter.add_allow_ip_addr("8.8.8.8".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        Some(false)
    )
}

#[test]
fn unblocked_ips_do_not_allow() {
    let filter = DomainFilterBuilder::new();
    filter.add_allow_ip_addr("8.8.8.8".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        None
    )
}
