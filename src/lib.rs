#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

pub use ipnet;

mod domain;
pub use domain::Domain;

mod domain_set;
pub use domain_set::{DomainSet, DomainSetSharded, DomainSetShardedDefault};

mod domain_filter;
pub use domain_filter::{DomainFilter, DomainFilterBuilder};
