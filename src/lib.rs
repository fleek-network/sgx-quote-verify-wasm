use anyhow::Result;
use chrono::DateTime;
use ra_verify::types::qe_identity::QuotingEnclaveIdentityAndSignature;
use ra_verify::types::tcb_info::TcbInfoAndSignature;
use std::time::SystemTime;
use wasm_bindgen::prelude::*;
use x509_cert::certificate::{CertificateInner, Rfc5280};
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::Certificate;

extern crate console_error_panic_hook;
use std::panic;

use ra_verify::types::{collateral::SgxCollateral, quote::SgxQuote};
use ra_verify::verify_remote_attestation;

fn parse_root_ca_crl(root_ca_crl: String) -> Result<CertificateList> {
    let bytes = hex::decode(&root_ca_crl)?;
    Ok(CertificateList::from_der(&bytes)?)
}

fn parse_pck_crl(
    issuer_chain: String,
    crl_hex: String,
) -> Result<(CertificateList, Vec<Certificate>)> {
    let issuer_chain_bytes = urlencoding::decode_binary(issuer_chain.as_bytes());
    let issuer_chain = CertificateInner::<Rfc5280>::load_pem_chain(&issuer_chain_bytes)?;
    let bytes = hex::decode(&crl_hex)?;
    Ok((CertificateList::from_der(&bytes)?, issuer_chain))
}

fn parse_tcb(
    issuer_chain: String,
    tcb_info: String,
) -> Result<(TcbInfoAndSignature, Vec<Certificate>)> {
    let issuer_chain_bytes = urlencoding::decode_binary(issuer_chain.as_bytes());
    let issuer_chain = CertificateInner::<Rfc5280>::load_pem_chain(&issuer_chain_bytes)?;
    let tcb_info: TcbInfoAndSignature = serde_json::from_str(&tcb_info)?;
    Ok((tcb_info, issuer_chain))
}

fn parse_qe_identity(
    issuer_chain: String,
    qe_ident: String,
) -> Result<(QuotingEnclaveIdentityAndSignature, Vec<Certificate>)> {
    let issuer_chain_bytes = urlencoding::decode_binary(issuer_chain.as_bytes());
    let issuer_chain = CertificateInner::<Rfc5280>::load_pem_chain(&issuer_chain_bytes)?;
    let qe_ident: QuotingEnclaveIdentityAndSignature = serde_json::from_str(&qe_ident)?;
    Ok((qe_ident, issuer_chain))
}

/// This function takes the quote as bytes, parses it, and returns the fmspc that is needed to
/// retrieve the collateral.
#[wasm_bindgen]
pub fn get_fmspc_from_quote(quote: Vec<u8>) -> Result<String, JsError> {
    let mut quote_bytes: &[u8] = &quote;
    let quote = SgxQuote::read(&mut quote_bytes).unwrap();
    Ok(hex::encode_upper(quote.support.pck_extension.fmspc))
}

/// This function takes in the quote, collateral, and timestamp, and performs a remote attestation.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn verify(
    quote: Vec<u8>,
    expected_mrenclave: Vec<u8>,
    root_ca_crl: String,
    pck_chain: String,
    pck_crl: String,
    tch_chain: String,
    tcb_info: String,
    qe_chain: String,
    qe_ident: String,
    timestamp: String,
) -> Result<bool, JsError> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let expected_mrenclave: [u8; 32] = expected_mrenclave
        .try_into()
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let root_ca_crl = parse_root_ca_crl(root_ca_crl).map_err(|e| JsError::new(&format!("{e}")))?;
    let (pck_crl, pck_chain) =
        parse_pck_crl(pck_chain, pck_crl).map_err(|e| JsError::new(&format!("{e}")))?;
    let (tcb_info, tcb_chain) =
        parse_tcb(tch_chain, tcb_info).map_err(|e| JsError::new(&format!("{e}")))?;
    let (qe_ident, qe_chain) =
        parse_qe_identity(qe_chain, qe_ident).map_err(|e| JsError::new(&format!("{e}")))?;

    let collateral = SgxCollateral {
        version: 3,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain: tcb_chain,
        pck_crl_issuer_chain: pck_chain,
        qe_identity_issuer_chain: qe_chain,
        tcb_info,
        qe_identity: qe_ident,
    };

    let mut quote_bytes: &[u8] = &quote;
    let quote = SgxQuote::read(&mut quote_bytes).unwrap();

    // SystemTime::now() doesn't work with wasm, so we pass unix millis from JS land and parse them
    // here
    let system_time: SystemTime = DateTime::from_timestamp_millis(timestamp.parse::<i64>()?)
        .ok_or(JsError::new("failed to parse timestamp"))?
        .into();

    verify_remote_attestation(system_time, collateral, quote, &expected_mrenclave)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(true)
}
