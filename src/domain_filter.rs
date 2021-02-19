use crate::{Domain, DomainSet};

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Filter<T: Default> {
    allow: T,
    disallow: T,
}

#[derive(Default, Clone)]
pub struct DomainFilterBuilder {
    domains: Arc<Mutex<Filter<DomainSet>>>,
    subdomains: Arc<Mutex<Filter<DomainSet>>>,
    ips: Arc<Mutex<Filter<HashSet<std::net::IpAddr>>>>,
    ip_nets: Arc<Mutex<Filter<HashSet<ipnet::IpNet>>>>,
    regexes: Arc<Mutex<Filter<HashSet<String>>>>,
    adblock_filters: Arc<Mutex<adblock::lists::FilterSet>>,
}

impl DomainFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_allow_domain(&self, domain: Domain) {
        let mut domains = self.domains.lock().unwrap();
        if let Some(without_www) = domain
            .strip_prefix("www.")
            .and_then(|domain| domain.parse::<Domain>().ok())
        {
            let _ = domains.disallow.remove(&without_www);
            domains.allow.insert(without_www);
        } else if let Ok(with_www) = format!("www.{}", &domain).parse::<Domain>() {
            let _ = domains.disallow.remove(&with_www);
            domains.allow.insert(with_www);
        }
        let _ = domains.disallow.remove(&domain);
        domains.allow.insert(domain);
    }
    pub fn add_disallow_domain(&self, domain: Domain) {
        let mut domains = self.domains.lock().unwrap();
        let subdomains = self.subdomains.lock().unwrap();
        if !domains.allow.contains(&domain) && !is_subdomain_of_list(&domain, &subdomains.allow) {
            domains.disallow.insert(domain);
        }
    }
    pub fn add_allow_subdomain(&self, domain: Domain) {
        let mut subdomains = self.subdomains.lock().unwrap();
        let _ = subdomains.disallow.remove(&domain);
        subdomains.allow.insert(domain);
    }
    pub fn add_disallow_subdomain(&self, domain: Domain) {
        let mut subdomains = self.subdomains.lock().unwrap();
        if !subdomains.allow.contains(&domain) {
            subdomains.disallow.insert(domain);
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

    pub fn add_adblock_rule(&self, mut rule: &str) {
        if rule.starts_with('!') {
            // Remove comments
            return;
        }
        if rule.contains("##")
            || rule.contains("#@#") // Cosmetic Exception
            || rule.contains("#$#") // CSS Selector
            || rule.contains("#@$#")// CSS Selector Exception
            || rule.contains("#?#")
        // Element Hiding
        {
            return;
        }
        if let Some(position) = rule.find('$') {
            let (start, tags) = rule.split_at(position);
            let tags = tags
                .trim_start_matches('$')
                .split(',')
                .collect::<Vec<&str>>();
            if !(tags.is_empty() || tags.contains(&"document") || tags.contains(&"all")) {
                return;
            }
            rule = start;
        }
        let (rule, is_exception) = rule
            .strip_prefix("@@")
            .map(|rule| (rule, true))
            .unwrap_or((rule, false));

        let (rule, match_start_domain, match_start_address) = rule
            .strip_prefix('|')
            .map(|rule| {
                rule.strip_prefix('|')
                    .map(|rule| (rule, true, false))
                    .unwrap_or((rule, false, true))
            })
            .unwrap_or((rule, false, false));
        let (rule, match_start_address) = rule
            .strip_prefix("://")
            .or_else(|| rule.strip_prefix("*://"))
            .or_else(|| rule.strip_prefix("http://"))
            .or_else(|| rule.strip_prefix("https://"))
            .map(|rule| (rule, true))
            .unwrap_or((rule, match_start_address));
        let (rule, match_start_domain, match_start_address) = rule
            .strip_prefix("*.")
            .map(|rule| (rule, true, false))
            .unwrap_or((rule, match_start_domain, match_start_address));

        let (rule, match_end_domain) = rule
            .strip_suffix('^')
            .map(|rule| (rule, true))
            .unwrap_or((rule, false));
        let (rule, match_end_domain) = rule
            .strip_suffix('|')
            .map(|rule| (rule, true))
            .unwrap_or((rule, match_end_domain));
        let (rule, match_end_domain) = rule
            .strip_suffix("/*")
            .map(|rule| (rule, true))
            .unwrap_or((rule, match_end_domain));

        if rule.is_empty() || (match_start_domain && match_start_address) || rule.contains('/') {
            return;
        }

        if (match_start_domain || match_start_address) && match_end_domain {
            if let Ok(domain) = rule.parse::<Domain>() {
                if !is_exception {
                    self.add_disallow_domain(domain.clone());
                    if match_start_domain {
                        self.add_disallow_subdomain(domain);
                    }
                }
                return;
            }
            if let Ok(ip) = rule.parse::<std::net::IpAddr>() {
                if !is_exception {
                    self.add_disallow_ip_addr(ip);
                }
                return;
            }
            //println!("Unknown filter: {:?}", rule);
            return;
        } else {
            //println!("Partial domain filter: {:?}", rule);
            return;
        }

        let mut adblock_filters = self.adblock_filters.lock().unwrap();
        let _ = adblock_filters.add_filter(rule, adblock::lists::FilterFormat::Standard);
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

    pub fn to_domain_filter(self) -> DomainFilter {
        let mut domains = std::mem::take(&mut *self.domains.lock().unwrap());
        let mut subdomains = std::mem::take(&mut *self.subdomains.lock().unwrap());
        let mut ips = std::mem::take(&mut *self.ips.lock().unwrap());
        let ip_nets = std::mem::take(&mut *self.ip_nets.lock().unwrap());
        let regexes = std::mem::take(&mut *self.regexes.lock().unwrap());
        let adblock_filters = std::mem::take(&mut *self.adblock_filters.lock().unwrap());

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
            adblock: adblock::engine::Engine::from_filter_set(adblock_filters, true),
            allow_regex: regex::RegexSet::new(&regexes.allow).unwrap(),
            disallow_regex: regex::RegexSet::new(&regexes.disallow).unwrap(),
        }
    }
}

fn is_subdomain_of_list(domain: &Domain, filter_list: &DomainSet) -> bool {
    domain
        .iter_parent_domains()
        .any(|part| filter_list.contains(&part))
}

pub struct DomainFilter {
    domains: Filter<DomainSet>,
    subdomains: Filter<DomainSet>,
    ips: Filter<HashSet<std::net::IpAddr>>,
    ip_nets: Filter<Vec<ipnet::IpNet>>,
    adblock: adblock::engine::Engine,
    allow_regex: regex::RegexSet,
    disallow_regex: regex::RegexSet,
}

impl DomainFilter {
    fn is_allowed_by_adblock(&self, location: &str) -> Option<bool> {
        return None;
        let url = format!("https://{}", location);
        let request = adblock::request::Request::from_urls(&url, &url, "").ok()?;
        let blocker_result = self
            .adblock
            .blocker
            .check_parameterised(&request, false, true);
        if blocker_result.exception.is_some() {
            Some(true)
        } else if blocker_result.matched {
            Some(false)
        } else {
            None
        }
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
        if self.domains.allow.contains(domain)
            || is_subdomain_of_list(&*domain, &self.subdomains.allow)
            || self.allow_regex.is_match(domain)
        {
            Some(true)
        } else if let Some(blocker_result) = self.is_allowed_by_adblock(&domain) {
            Some(blocker_result)
        } else if self.domains.disallow.contains(domain)
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
fn adblock_can_block_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(false)
    )
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
fn adblock_can_whitelist_blocked_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_adblock_rule("@@||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn subdomain_disallow_blocks() {
    let filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"www.example.com".parse().unwrap()),
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
        filter.domain_is_allowed(&"www.example.com".parse().unwrap()),
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

#[test]
fn adblock_third_party_does_not_block_domain() {
    let filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com$third-party");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        None
    );
    assert_eq!(
        filter.domain_is_allowed(&"www.example.com".parse().unwrap()),
        None
    )
}
