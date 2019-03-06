use std::{io as std_io};
use std::collections::HashMap;
use std::str::FromStr;

use bytes::BufMut;
use futures::Future;

use ::data_types::Capability;
use ::error::MissingCapabilities;
use ::{
    Domain, EhloData, SyntaxError, EhloParam,
    Cmd, ExecFuture, Io, Response, ClientId
};


#[derive(Debug, Clone)]
pub struct Ehlo {
    identity: ClientId
}

impl Ehlo {

    pub fn new(identity: ClientId) -> Self {
        Ehlo { identity }
    }

    pub fn identity(&self) -> &ClientId {
        &self.identity
    }
}

impl From<ClientId> for Ehlo {
    fn from(identity: ClientId) -> Self {
        Ehlo { identity }
    }
}

impl Into<ClientId> for Ehlo {
    fn into(self) -> ClientId {
        self.identity
    }
}

impl Cmd for Ehlo {

    fn check_cmd_availability(&self, _caps: Option<&EhloData>)
        -> Result<(), MissingCapabilities>
    {
       Ok(())
    }

    fn exec(self, mut io: Io) -> ExecFuture {
        let str_me = match *self.identity() {
            ClientId::Domain(ref domain) => domain.as_str(),
            ClientId::AddressLiteral(ref addr_lit) => addr_lit.as_str()
        };

        {
            //7 == "EHLO ".len() + "\r\n".len()
            let out = io.out_buffer(7 + str_me.len());
            out.put("EHLO ");
            out.put(str_me);
            out.put("\r\n");
        }

        let fut = io
            .flush()
            .and_then(Io::parse_response)
            //TODO ctx_and_then
            .and_then(|(mut io, result)| match result {
                Err(response) => Ok((io, Err(response))),
                Ok(response) => {
                    let ehlo = parse_ehlo_response(&response)
                        .map_err(|err| std_io::Error::new(std_io::ErrorKind::Other, err))?;

                    io.set_ehlo_data(ehlo);
                    Ok((io, Ok(response)))
                }
            });

        Box::new(fut)
    }
}

fn parse_ehlo_response(response: &Response) -> Result<EhloData, SyntaxError> {
    let lines = response.msg();
    let first = lines.first().expect("response with 0 lines should not");
    //UNWRAP_SAFE: Split has at least one entry
    let domain: Domain = first.split(" ").next().unwrap().parse()?;
    let mut caps = HashMap::new();

    for line in lines[1..].iter() {
        let mut parts = line.split(" ");
        //UNWRAP_SAFE: Split has at least one entry
        let capability_candidate = parts.next().unwrap();
        let capability = match capability_candidate.parse::<Capability>() {
            e @ Err(SyntaxError::EsmtpKeyword) => {
                // Ignore broken duplicate AUTH capability which servers may declare to be compatible
                // with old Outlook clients. Postfix servers use this behavior with the
                // [broken_sasl_auth_clients](http://www.postfix.org/postconf.5.html#broken_sasl_auth_clients)
                // configuration option.
                if capability_candidate.split("=").next().map(Capability::from_str) == Some(Ok(Capability::from_str("AUTH").unwrap())) {
                    continue;
                } else {
                    e
                }
            },
            r @ _ => r,
        }?;
        let params = parts.map(|part| part.parse()).collect::<Result<Vec<EhloParam>, _>>()?;
        caps.insert(capability, params);
    }

    Ok(EhloData::new(domain, caps))
}


#[cfg(test)]
mod test {

    mod parse_ehlo_response {
        use ::Response;
        use ::response::codes::OK;
        use ::SyntaxError;
        use data_types::EhloParam;
        use super::super::parse_ehlo_response;

        #[test]
        fn simple_case() {
            let response = Response::new(OK, vec!["1aim.test".to_owned()]);
            let ehlo_data = parse_ehlo_response(&response).unwrap();

            assert_eq!(ehlo_data.domain(), "1aim.test");
            assert!(ehlo_data.capability_map().is_empty());
        }

        #[test]
        fn allow_greeting() {
            let response = Response::new(OK, vec!["1aim.test says hy".to_owned()]);
            let ehlo_data = parse_ehlo_response(&response).unwrap();

            assert_eq!(ehlo_data.domain(), "1aim.test");
            assert!(ehlo_data.capability_map().is_empty());
        }

        #[test]
        fn can_have_capabilities() {
            let response = Response::new(OK, vec![
                "1aim.test says hy".to_owned(),
                "SMTPUTF8".to_owned(),
                "MIME8".to_owned(),
            ]);
            let ehlo_data = parse_ehlo_response(&response).unwrap();

            assert_eq!(ehlo_data.domain(), "1aim.test");
            assert!(ehlo_data.has_capability("SMTPUTF8"));
            assert!(ehlo_data.get_capability_params("SMTPUTF8").unwrap().is_empty());
            assert!(ehlo_data.has_capability("MIME8"));
            assert!(ehlo_data.get_capability_params("MIME8").unwrap().is_empty());
            assert_eq!(ehlo_data.capability_map().len(), 2)
        }

        #[test]
        fn capabilities_can_have_parameter() {
            let response = Response::new(OK, vec![
                "1aim.test says hy".to_owned(),
                "X-NOT-A-ROBOT ENABLED".to_owned(),
            ]);
            let ehlo_data = parse_ehlo_response(&response).unwrap();

            assert_eq!(ehlo_data.domain(), "1aim.test");
            assert!(ehlo_data.has_capability("X-NOT-A-ROBOT"));
            let params = ehlo_data.get_capability_params("X-NOT-A-ROBOT").unwrap();
            assert_eq!(params.len(), 1);
            assert_eq!(params[0], "ENABLED");
        }

        #[test]
        fn malformed_auth_ignored() {
            let response = Response::new(OK, vec![
                "1aim.test says hy".to_owned(),
                "AUTH PLAIN LOGIN".to_owned(),
                "AUTH=PLAIN".to_owned(),
            ]);
            let ehlo_data = parse_ehlo_response(&response).unwrap();

            assert_eq!(ehlo_data.domain(), "1aim.test");
            assert!(ehlo_data.has_capability("AUTH"));
            assert_eq!(Some(["PLAIN".parse::<EhloParam>().unwrap(), "LOGIN".parse().unwrap()].as_ref()), ehlo_data.get_capability_params("AUTH"));
            assert_eq!(ehlo_data.capability_map().len(), 1)
        }

        #[test]
        fn malformed_non_auth_error() {
            let response = Response::new(OK, vec![
                "1aim.test says hy".to_owned(),
                "X-NOT-A-ROBOT ENABLED".to_owned(),
                "X-NOT-A-ROBOT=ENABLED".to_owned(),
            ]);
            assert_eq!(SyntaxError::EsmtpKeyword, parse_ehlo_response(&response).unwrap_err());
        }
    }
}