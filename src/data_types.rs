use std::convert::AsRef;
use std::borrow::Borrow;
use std::str::FromStr;
use std::fmt::{self, Display};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

use ascii::{IgnoreAsciiCaseStr, IgnoreAsciiCaseString};

/// represents a smtp extension/capability indicated through ehlo
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Capability(EsmtpKeyword);

impl Deref for Capability {
    type Target = EsmtpKeyword;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<IgnoreAsciiCaseStr> for Capability {

    fn borrow(&self) -> &IgnoreAsciiCaseStr {
        (self.0).0.as_ref()
    }
}

impl From<EsmtpKeyword> for Capability {
    fn from(keyword: EsmtpKeyword) -> Self {
        Capability(keyword)
    }
}

impl Into<EsmtpKeyword> for Capability {
    fn into(self) -> EsmtpKeyword {
        self.0
    }
}

/// represents an EsmtpKeyword (syntax construct in ehlo response)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EsmtpKeyword(IgnoreAsciiCaseString);

/// represents an EsmtpValue (syntax construct in ehlo response)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EsmtpValue(String);

/// represents an EhloParam (syntax construct in ehlo response)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EhloParam(String);

/// represents a `Domain`
///
/// Note that currently no parse is implemented for `Domain`,
/// i.e. validation has to be done by the user converting their
/// representation to out using `from_unchecked`.
///
/// Note that the domain is expected to be ascii non ascii
/// strings should be puny encoded.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Domain(IgnoreAsciiCaseString);

/// represents a `AddressLiteral`
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct AddressLiteral(IgnoreAsciiCaseString);

/// represents a forward path, most times this is just a mail address
///
/// Note that this type is not supposed to contain the surrounding `'<'` and `'>'`.
/// They will be added automatically.
///
/// Note that currently no parser is implemented and that the
/// allowed grammar of the forward path changes depending on
/// the `EsmtKeywords` in EHLO and on the parameters of the
/// _previously_ send `MAIL` command. This and the fact that
/// part of the grammar of forward paths are discouraged to
/// be used makes it a bit of a wast of time to implement the
/// grammar here. Through `send_mail` actually does know about
/// `SMTPUTF8` and keeps track of it.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ForwardPath(String);

/// represents a reverse path, most times this is just a mail address
///
/// Note that this type is not supposed to contain the surrounding `'<'` and `'>'`.
/// They will be added automatically.
///
/// Note that this can be an empty string, representing a empty reverse path
/// (donated in smtp with `<>`).
///
/// Note that currently no parser is implemented and that the
/// allowed grammar of the forward path changes depending on
/// the `EsmtKeywords` in EHLO and on the parameters of the
/// the `MAIL` command it's used in. This and the fact that
/// part of the grammar of reverse paths are discouraged to
/// be used makes it a bit of a wast of time to implement the
/// grammar here. Through `send_mail` actually does know about
/// `SMTPUTF8` and keeps track of it.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ReversePath(String);

macro_rules! impl_str_wrapper {
    ($($name:ident),*) => ($(

        impl $name {
            /// return the inner representation as `&str`
            pub fn as_str(&self) -> &str {
                self.0.as_ref()
            }

            /// create a new instance from a string without validating the input
            pub fn from_unchecked<I>(data: I) -> Self
                where I: Into<String>
            {
                let string = data.into();
                $name(string.into())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.0.as_ref()
            }
        }

        impl Into<String> for $name {
            fn into(self) -> String {
                self.0.into()
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl<'a> PartialEq<&'a str> for $name {
            fn eq(&self, other: &&'a str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                &self.0 == other
            }
        }

    )*);
}


impl_str_wrapper!(
    Domain, EhloParam, AddressLiteral, EsmtpKeyword, EsmtpValue,
    ForwardPath, ReversePath
);


impl ReversePath {

    /// creates an empty reverse path
    ///
    /// In a mail command this will lead to `"MAIL FROM:<>"`.
    /// Note that the `'<'`,`'>'` are not part of the content
    /// so the content is an empty string.
    ///
    /// ```
    /// use new_tokio_smtp::ReversePath;
    ///
    /// let rpath = ReversePath::empty();
    /// assert_eq!(rpath.as_str(), "");
    /// ```
    pub fn empty() -> Self {
        ReversePath("".to_owned())
    }
}

impl FromStr for EhloParam {
    type Err = SyntaxError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        let valid = inp.bytes().all(|bch| {
            33 <= bch && bch <= 126
        });

        if valid {
            Ok(EhloParam(inp.to_owned().into()))
        } else {
            Err(SyntaxError::Param)
        }
    }
}

impl EsmtpKeyword {

    /// create a new `EsmtpKeyword` from a string
    ///
    /// This validates the input, possible creating a
    /// syntax error. Alternatively `"string".parse()`
    /// can be used as `EsmtpKeyword` implements `FromStr`.
    pub fn new<I>(val: I) -> Result<Self, SyntaxError>
        where I: AsRef<str> + Into<String>
    {
        let valid = {
            let mut iter = val.as_ref().chars();
            iter.next()
                .map(|ch| ch.is_ascii_alphanumeric()).unwrap_or(false)
                && iter.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        };

        if valid {
            let mut sfyied: String = val.into();
            sfyied.make_ascii_uppercase();
            Ok(EsmtpKeyword(sfyied.into()))
        } else {
            Err(SyntaxError::EsmtpKeyword)
        }
    }
}

impl FromStr for EsmtpKeyword {
    type Err = SyntaxError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        EsmtpKeyword::new(inp)
    }
}

impl EsmtpValue {

     /// create a new `EsmtpValue` from a string
    ///
    /// This validates the input, possible creating a
    /// syntax error. Alternatively `"string".parse()`
    /// can be used as `EsmtpValue` implements `FromStr`.
    pub fn new<I>(val: I) -> Result<Self, SyntaxError>
        where I: AsRef<str> + Into<String>
    {
        let valid = val.as_ref().bytes().all(|bch| {
            33 <= bch && (bch <= 60 || (62 <= bch && bch <= 128))
        });

        if valid {
            let sfyied: String = val.into();
            Ok(EsmtpValue(sfyied.into()))
        } else {
            Err(SyntaxError::EsmtpKeyword)
        }
    }
}

impl FromStr for EsmtpValue {
    type Err = SyntaxError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        EsmtpValue::new(inp)
    }
}

impl FromStr for Capability {
    type Err = SyntaxError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        EsmtpKeyword::from_str(inp).map(Capability)
    }
}

impl Domain {

    /// creates a new domain without validating it's correctness
    pub fn new_unchecked(domain: String) -> Self {
        Domain(domain.into())
    }
}

impl FromStr for Domain {
    type Err = SyntaxError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        let valid = inp.split(".").all(validate_subdomain);

        if valid {
            Ok(Domain(inp.to_lowercase().into()))
        } else {
            Err(SyntaxError::Domain)
        }
    }
}

fn validate_subdomain(inp: &str) -> bool {
    let len = inp.len();
    let binp = inp.as_bytes();
    len > 1
        && binp[0].is_ascii_alphanumeric()
        && binp[1..len-1].iter().all(|bch| bch.is_ascii_alphanumeric() || *bch == b'-' )
        && binp[len - 1].is_ascii_alphanumeric()
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SyntaxError {
    Domain,
    Param,
    AddressLiteral,
    EsmtpValue,
    EsmtpKeyword,
}

impl Display for SyntaxError {

    fn fmt(&self, fter: &mut fmt::Formatter) -> fmt::Result {
        write!(fter, "{}", self.description())
    }
}

impl Error for SyntaxError {
    fn description(&self) -> &str {
        use self::SyntaxError::*;
        match *self {
            Domain => "syntax error parsing Domain from str",
            Param => "syntax error parsing Param str",
            EsmtpKeyword => "syntax error parsing esmtp-keyword from str",
            EsmtpValue => "syntax error parsing esmtp-value from str",
            AddressLiteral => "syntax error parsing address-literal from str",
        }
    }
}

impl AddressLiteral {

    /// Create a "general" AddressLiteral which is not IPv4/v6
    ///
    /// This is mainly for enabling other alternatives to IPv4/IPv6.
    /// Note that RFC 5321 limits it to **standarized** tags, i.e.
    /// tags registered with IANA.
    #[doc(hidden)]
    pub fn custom_literal<AS1, AS2>(standarized_tag: AS1, custom_part: AS2)
        -> Result<Self, SyntaxError>
        where AS1: AsRef<str>, AS2: AsRef<str>
    {
        let tag = standarized_tag.as_ref();
        let valid_tag = tag.as_bytes()
            .last().map(|bch| *bch != b'-').unwrap_or(false)
            && tag.bytes().all(|bch| bch.is_ascii_alphanumeric() || bch == b'-');

        if !valid_tag {
            return Err(SyntaxError::AddressLiteral);
        }

        let custom_part = custom_part.as_ref();
        let valid = custom_part.bytes().all(|bch| {
            (33 <= bch && bch <= 90) || (94 <= bch && bch <= 126)
        });

        if valid {
            Ok(AddressLiteral(format!("[{}:{}]", tag, custom_part).into()))
        } else {
            Err(SyntaxError::AddressLiteral)
        }
    }
}


impl From<IpAddr> for AddressLiteral {
    fn from(addr: IpAddr) -> Self {
        use self::IpAddr::*;
        match addr {
            V4(ref addr) => AddressLiteral::from(addr),
            V6(ref addr) => AddressLiteral::from(addr)
        }
    }
}

impl From<Ipv4Addr> for AddressLiteral {
    fn from(addr: Ipv4Addr) -> Self {
        AddressLiteral::from(&addr)
    }
}

impl From<Ipv6Addr> for AddressLiteral {
    fn from(addr: Ipv6Addr) -> Self {
        AddressLiteral::from(&addr)
    }
}

impl<'a> From<&'a Ipv4Addr> for AddressLiteral {
    fn from(addr: &'a Ipv4Addr) -> Self {
        AddressLiteral(format!("[{}]", addr).into())
    }
}

impl<'a> From<&'a Ipv6Addr> for AddressLiteral {
    fn from(addr: &'a Ipv6Addr) -> Self {
        AddressLiteral(format!("[IPv6:{}]", addr).into())
    }
}

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    mod EhloParams {
        use super::super::EhloParam;

        #[test]
        fn case_sensitive() {
            let a: EhloParam = "affen".parse().unwrap();
            let b: EhloParam = "AFFEN".parse().unwrap();
            assert_ne!(a, b);
            assert_ne!(a, "aFFen")
        }

        #[test]
        fn displayed_unchanged() {
            let a: EhloParam = "afFen".parse().unwrap();
            let s: String = a.into();
            assert_eq!(s, "afFen")
        }
    }

    mod EsmtpKeyword {
        use super::super::EsmtpKeyword;

        #[test]
        fn case_insensitive() {
            let a: EsmtpKeyword = "affen".parse().unwrap();
            let b: EsmtpKeyword = "AFFEN".parse().unwrap();
            let c: EsmtpKeyword = "AffEN".parse().unwrap();
            assert_eq!(a, b);
            assert_eq!(b, c);
            assert_eq!(a, "aFFen");
        }

        #[test]
        fn displayed_uppercase() {
            let a: EsmtpKeyword = "afFen".parse().unwrap();
            let s: String = a.into();
            assert_eq!(s, "AFFEN")
        }
    }

    mod EsmtpValue {
        use super::super::EsmtpValue;

        #[test]
        fn case_sensitive() {
            let a: EsmtpValue = "affen".parse().unwrap();
            let b: EsmtpValue = "AFFEN".parse().unwrap();
            assert_ne!(a, b);
            assert_ne!(a, "aFFen");
        }

        #[test]
        fn displayed_unchanged() {
            let a: EsmtpValue = "afFen".parse().unwrap();
            let s: String = a.into();
            assert_eq!(s, "afFen")
        }

    }

    mod Capability {
        use std::collections::HashMap;
        use ::ascii::IgnoreAsciiCaseStr;
        use super::super::Capability;

        #[test]
        fn has_to_work_with_hashmaps() {
            let mut map = HashMap::new();
            let cap: Capability = "smtputf8".parse().unwrap();
            let cap2: Capability = "SmtpUtf8".parse().unwrap();
            map.insert(cap, ());

            assert!(map.contains_key(&cap2))
        }

        #[test]
        fn has_to_work_with_hashmaps_and_str() {
            let mut map = HashMap::new();
            let cap: Capability = "smtputf8".parse().unwrap();
            map.insert(cap, ());

            let str_key = "smtPUTf8";
            let wrapped = <&IgnoreAsciiCaseStr>::from(str_key);
            assert!(map.contains_key(wrapped))
        }
    }

    mod Domain {
        use super::super::Domain;

        #[test]
        fn case_insensitive() {
            let a: Domain = "affen".parse().unwrap();
            let b: Domain = "AFFEN".parse().unwrap();
            let c: Domain = "AffEN".parse().unwrap();
            assert_eq!(a, b);
            assert_eq!(b, c);
            assert_eq!(a, "aFFen");
        }

        #[test]
        fn displayed_lowercase() {
            let a: Domain = "afFen".parse().unwrap();
            let s: String = a.into();
            assert_eq!(s, "affen")
        }

        #[test]
        fn from_unchecked() {
            let a = Domain::from_unchecked("hy");
            assert_eq!(a, "hy");
        }
    }
}
