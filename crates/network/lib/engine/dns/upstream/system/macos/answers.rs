//! Turning `DNSServiceQueryRecord` replies into a DNS response.
//!
//! mDNSResponder reports NXDOMAIN, NODATA and a transient lack of DNS
//! servers alike, as `kDNSServiceErr_NoSuchRecord`. All become NOERROR
//! with no answers: NXDOMAIN for a name that only lacks the queried type,
//! or SERVFAIL for either address family, makes stub resolvers such as
//! musl fail the whole lookup.

use std::ffi::CString;
use std::io;

use hickory_net::proto::op::{Message, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_net::proto::serialize::binary::{BinDecoder, Restrict};

use super::dnssd::{
    DNSServiceErrorType, DNSServiceFlags, ERR_NO_ERROR, ERR_NO_SUCH_NAME, ERR_NO_SUCH_RECORD,
    FLAGS_ADD, FLAGS_MORE_COMING, service_error,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One `DNSServiceQueryRecordReply` callback.
pub(super) struct Reply<'a> {
    pub(super) flags: DNSServiceFlags,
    pub(super) error_code: DNSServiceErrorType,
    /// Record owner in `dns_sd` presentation format.
    pub(super) fullname: &'a [u8],
    pub(super) rrtype: u16,
    pub(super) rrclass: u16,
    /// Record data in wire format.
    pub(super) rdata: &'a [u8],
    pub(super) ttl: u32,
}

/// Collects the replies for one question until they answer it.
pub(super) struct Collector {
    query_type: RecordType,
    answers: Vec<Record>,
    /// A record of the queried type, or a negative answer, has arrived.
    answered: bool,
    /// The last reply said more replies follow in the same batch.
    more_coming: bool,
    failure: Option<io::Error>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Collector {
    pub(super) fn new(query_type: RecordType) -> Self {
        Self {
            query_type,
            answers: Vec::new(),
            answered: false,
            more_coming: false,
            failure: None,
        }
    }

    /// Record one reply. CNAMEs on the way to the queried type are kept as
    /// answers so the guest sees the whole chain.
    pub(super) fn accept(&mut self, reply: Reply<'_>) {
        if self.failure.is_some() {
            return;
        }
        self.more_coming = reply.flags & FLAGS_MORE_COMING != 0;
        match reply.error_code {
            ERR_NO_ERROR if reply.flags & FLAGS_ADD == 0 => {
                // A previously reported record was removed; this query only
                // wants the current answer.
            }
            ERR_NO_ERROR => match decode_record(&reply) {
                Ok(record) => {
                    self.answered |= self.query_type == RecordType::ANY
                        || record.record_type() == self.query_type;
                    self.answers.push(record);
                }
                Err(error) => self.failure = Some(error),
            },
            ERR_NO_SUCH_RECORD | ERR_NO_SUCH_NAME => self.answered = true,
            status => self.failure = Some(service_error(status)),
        }
    }

    /// End the query with `error`.
    pub(super) fn fail(&mut self, error: io::Error) {
        self.failure.get_or_insert(error);
    }

    /// The answers once the question is answered and its batch of replies
    /// is complete, or the failure; `None` while more replies are needed.
    /// mDNSResponder writes each reply separately, so a batch can span
    /// several socket reads.
    pub(super) fn finish(&mut self) -> Option<io::Result<Vec<Record>>> {
        if let Some(error) = self.failure.take() {
            return Some(Err(error));
        }
        (self.answered && !self.more_coming).then(|| Ok(std::mem::take(&mut self.answers)))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Encode `name` in `dns_sd` presentation format: labels joined by dots,
/// with `.` and `\` escaped by a backslash and other bytes outside
/// printable ASCII written as decimal `\DDD`.
pub(super) fn encode_name(name: &Name) -> io::Result<CString> {
    let mut encoded = Vec::with_capacity(name.len() + 1);
    for label in name.iter() {
        for &byte in label {
            match byte {
                b'.' | b'\\' => encoded.extend_from_slice(&[b'\\', byte]),
                0x21..=0x7e => encoded.push(byte),
                _ => encoded.extend_from_slice(format!("\\{byte:03}").as_bytes()),
            }
        }
        encoded.push(b'.');
    }
    if encoded.is_empty() {
        encoded.push(b'.');
    }
    CString::new(encoded).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

/// Decode a `dns_sd` presentation-format name. mDNSResponder escapes `.`
/// and `\` with a backslash and control bytes as decimal `\DDD`, and
/// passes other bytes through unescaped.
pub(super) fn decode_name(encoded: &[u8]) -> io::Result<Name> {
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "macOS DNS service returned an invalid name {:?}: {reason}",
                String::from_utf8_lossy(encoded)
            ),
        )
    };
    if encoded == b"." {
        return Ok(Name::root());
    }

    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut rest = encoded;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        match byte {
            b'\\' => match rest {
                [a, b, c, tail @ ..] if [a, b, c].iter().all(|digit| digit.is_ascii_digit()) => {
                    let value =
                        u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
                    label.push(u8::try_from(value).map_err(|_| invalid("escape above 255"))?);
                    rest = tail;
                }
                [escaped, tail @ ..] => {
                    label.push(*escaped);
                    rest = tail;
                }
                [] => return Err(invalid("trailing backslash")),
            },
            b'.' if label.is_empty() => return Err(invalid("empty label")),
            b'.' => labels.push(std::mem::take(&mut label)),
            byte => label.push(byte),
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    Name::from_labels(labels).map_err(|error| invalid(&error.to_string()))
}

/// Build the NOERROR response to `query` from the collected answers.
pub(super) fn build_response(query: &Message, answers: Vec<Record>) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    for question in &query.queries {
        response.add_query(question.clone());
    }
    response.add_answers(answers);
    response
}

/// Decode one reply's record.
fn decode_record(reply: &Reply<'_>) -> io::Result<Record> {
    let name = decode_name(reply.fullname)?;
    let record_type = RecordType::from(reply.rrtype);
    let length = u16::try_from(reply.rdata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "record data is too long"))?;
    let mut decoder = BinDecoder::new(reply.rdata);
    let rdata = RData::read(&mut decoder, record_type, Restrict::new(length)).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("macOS DNS service returned invalid {record_type} data: {error}"),
        )
    })?;
    let mut record = Record::from_rdata(name, reply.ttl, rdata);
    record.dns_class = DNSClass::from(reply.rrclass);
    Ok(record)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_net::proto::op::{MessageType, OpCode, Query};
    use hickory_net::proto::rr::rdata::{A, CNAME};
    use hickory_net::proto::serialize::binary::BinEncodable;

    use super::*;

    fn reply<'a>(fullname: &'a [u8], rrtype: RecordType, rdata: &'a [u8]) -> Reply<'a> {
        Reply {
            flags: FLAGS_ADD,
            error_code: ERR_NO_ERROR,
            fullname,
            rrtype: u16::from(rrtype),
            rrclass: u16::from(DNSClass::IN),
            rdata,
            ttl: 60,
        }
    }

    fn negative(fullname: &[u8], rrtype: RecordType) -> Reply<'_> {
        Reply {
            error_code: ERR_NO_SUCH_RECORD,
            ..reply(fullname, rrtype, &[])
        }
    }

    fn cname_rdata(target: &str) -> Vec<u8> {
        RData::CNAME(CNAME(Name::from_ascii(target).unwrap()))
            .to_bytes()
            .unwrap()
    }

    #[test]
    fn encodes_names_in_dns_sd_presentation_format() {
        let name = Name::from_labels([&b"a.b"[..], b"c\\d", b"\x00\x7f\xc3\xa6", b"com"]).unwrap();
        assert_eq!(
            encode_name(&name).unwrap().as_bytes(),
            b"a\\.b.c\\\\d.\\000\\127\\195\\166.com."
        );
        assert_eq!(encode_name(&Name::root()).unwrap().as_bytes(), b".");
    }

    #[test]
    fn decodes_what_mdnsresponder_returns() {
        let name = decode_name(b"a\\.b.c\\\\d.\\000\\127\xc3\xa6.com.").unwrap();
        let labels: Vec<&[u8]> = name.iter().collect();
        assert_eq!(labels, [&b"a.b"[..], b"c\\d", b"\x00\x7f\xc3\xa6", b"com"]);
        assert!(name.is_fqdn());
        assert_eq!(decode_name(b".").unwrap(), Name::root());
    }

    #[test]
    fn encoded_names_round_trip() {
        let name = Name::from_labels([&b"x\\.y"[..], b"\x01\xff", b"example"]).unwrap();
        let encoded = encode_name(&name).unwrap();
        assert_eq!(decode_name(encoded.as_bytes()).unwrap(), name);
    }

    #[test]
    fn rejects_malformed_names() {
        for encoded in [&b"a..b."[..], b"a\\", b"a\\256.com.", b".a."] {
            assert_eq!(
                decode_name(encoded).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn address_answers_complete_the_question() {
        let mut collector = Collector::new(RecordType::A);
        collector.accept(reply(b"example.com.", RecordType::A, &[192, 0, 2, 1]));
        collector.accept(reply(b"example.com.", RecordType::A, &[192, 0, 2, 2]));

        let answers = collector.finish().unwrap().unwrap();
        let addresses: Vec<RData> = answers.into_iter().map(|record| record.data).collect();
        assert_eq!(
            addresses,
            [
                RData::A(A::from(Ipv4Addr::new(192, 0, 2, 1))),
                RData::A(A::from(Ipv4Addr::new(192, 0, 2, 2))),
            ]
        );
    }

    /// With intermediates enabled, a CNAME arrives before its target's
    /// records; the question is not answered until they do.
    #[test]
    fn cname_chain_waits_for_the_queried_type() {
        let mut collector = Collector::new(RecordType::A);
        let rdata = cname_rdata("target.example.");
        collector.accept(reply(b"www.example.com.", RecordType::CNAME, &rdata));
        assert!(collector.finish().is_none());

        collector.accept(reply(b"target.example.", RecordType::A, &[192, 0, 2, 3]));
        let answers = collector.finish().unwrap().unwrap();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].record_type(), RecordType::CNAME);
        assert_eq!(
            answers[0].name,
            Name::from_ascii("www.example.com.").unwrap()
        );
        assert_eq!(
            answers[1].name,
            Name::from_ascii("target.example.").unwrap()
        );
    }

    #[test]
    fn cname_queries_are_answered_by_the_cname() {
        let mut collector = Collector::new(RecordType::CNAME);
        let rdata = cname_rdata("target.example.");
        collector.accept(reply(b"www.example.com.", RecordType::CNAME, &rdata));
        assert_eq!(collector.finish().unwrap().unwrap().len(), 1);
    }

    /// mDNSResponder does not say whether the name exists, so a negative
    /// answer is NODATA, keeping any CNAMEs that led to it.
    #[test]
    fn negative_answers_are_nodata() {
        let mut collector = Collector::new(RecordType::AAAA);
        collector.accept(negative(b"example.com.", RecordType::AAAA));
        assert!(collector.finish().unwrap().unwrap().is_empty());

        let mut collector = Collector::new(RecordType::AAAA);
        let rdata = cname_rdata("target.example.");
        collector.accept(reply(b"www.example.com.", RecordType::CNAME, &rdata));
        collector.accept(negative(b"target.example.", RecordType::AAAA));
        assert_eq!(collector.finish().unwrap().unwrap().len(), 1);
    }

    /// The reviewed bug: finishing at the first address returned one of a
    /// name's addresses when the rest of the batch had not been read yet.
    #[test]
    fn waits_for_the_rest_of_the_batch() {
        let mut collector = Collector::new(RecordType::A);
        collector.accept(Reply {
            flags: FLAGS_ADD | FLAGS_MORE_COMING,
            ..reply(b"example.com.", RecordType::A, &[192, 0, 2, 1])
        });
        assert!(collector.finish().is_none());

        collector.accept(reply(b"example.com.", RecordType::A, &[192, 0, 2, 2]));
        assert_eq!(collector.finish().unwrap().unwrap().len(), 2);
    }

    #[test]
    fn a_failure_ends_the_query_even_mid_batch() {
        let mut collector = Collector::new(RecordType::A);
        collector.accept(Reply {
            flags: FLAGS_ADD | FLAGS_MORE_COMING,
            ..reply(b"example.com.", RecordType::A, &[192, 0, 2, 1])
        });
        collector.fail(io::Error::other("boom"));
        assert_eq!(collector.finish().unwrap().unwrap_err().to_string(), "boom");
    }

    #[test]
    fn removals_are_ignored() {
        let mut collector = Collector::new(RecordType::A);
        collector.accept(Reply {
            flags: 0,
            ..reply(b"example.com.", RecordType::A, &[192, 0, 2, 1])
        });
        assert!(collector.finish().is_none());
    }

    #[test]
    fn service_errors_and_bad_records_fail_the_query() {
        let mut collector = Collector::new(RecordType::A);
        collector.accept(Reply {
            error_code: -65563,
            ..reply(b"example.com.", RecordType::A, &[])
        });
        assert_eq!(
            collector.finish().unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );

        let mut collector = Collector::new(RecordType::A);
        collector.accept(reply(b"example.com.", RecordType::A, &[192, 0, 2]));
        assert_eq!(
            collector.finish().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn responses_echo_the_question_and_carry_the_answers() {
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let answer = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::from(Ipv4Addr::new(192, 0, 2, 1))),
        );

        let response = build_response(&query, vec![answer.clone()]);

        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert!(response.metadata.recursion_desired);
        assert!(response.metadata.recursion_available);
        assert_eq!(response.queries, query.queries);
        assert_eq!(response.answers, [answer]);
    }
}
