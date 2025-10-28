use crate::certificates::Certificate;
use crate::{acme_challenge_path, acme_path, cert_path};
use std::fs;
use std::path::{PathBuf};
use acme_v2::{create_p384_key, Directory, DirectoryUrl, Error};
use acme_v2::persist::FilePersist;
use tracing::{debug, error, info};
use x509_parser::der_parser::oid;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

pub async fn import_from_letsencrypt_path(input_dir: &String) {
  let input_dir_path = PathBuf::from(input_dir);
  info!("Import dir: [{:?}]",input_dir);
  if !input_dir_path.exists() {
    eprintln!("Input directory does not exist");
    return;
  }

  let input_dir_live = input_dir_path.join("live");

  let dir = match fs::read_dir(input_dir_live.to_str().unwrap()) {
    Ok(dir) => dir,
    Err(e) => {
      error!("Error reading input directory : {}", e);
      return;
    }
  };

  let mut certs: Vec<Certificate> = Vec::new();
  for entry in dir {
    let path = entry.unwrap().path();
    if path.is_dir() {
      info!("Found dir: [{:?}]",path);
      let cert = open_and_parse_cert(path);
      certs.push(cert.clone());
    }
  }
  info!("Found certs: [{:?}]",certs);

  certs.iter().for_each(|cert| {
    info!("Processing cert: {}",cert.get_host_name());
    let cert_dest_path = PathBuf::from(cert_path()).join(cert.get_host_name());
    if !cert_dest_path.exists() {
      fs::create_dir(&cert_dest_path).unwrap();
    }
    let cert_dest_file_path = cert_dest_path.join("cert.json");
    if cert_dest_file_path.exists() {
      let buf = fs::read_to_string(&cert_dest_file_path);
      let existing_cert: Certificate = serde_json::from_str(buf.unwrap().as_str()).unwrap();
      let existing_cert_obj = Certificate::from_struct(existing_cert);
      if existing_cert_obj.get_valid_until_unix_timestamp().unwrap() > cert.get_valid_until_unix_timestamp().unwrap() {
        fs::write(&cert_dest_file_path, serde_json::to_string_pretty(cert).unwrap()).unwrap();
        let is_expired = cert.is_expired().unwrap();
        if is_expired {
          info!("Cert is expired: {}",cert.get_host_name());
        }
      } else {
        info!("Not updating cert: {}",cert.get_host_name());
      }
    } else {
      info!("Writing cert: {}",cert.get_host_name());
      fs::write(&cert_dest_file_path, serde_json::to_string_pretty(cert).unwrap()).unwrap();
    }
  });

}

fn open_and_parse_cert(path: PathBuf) -> Certificate {
  let mut return_cert = Certificate::new("host".to_string());
  let dir = match fs::read_dir(path){
    Ok(dir) => dir,
    Err(e) => {
      error!("Error reading directory : {}", e);
      return return_cert;
    }
  };

  for entry in dir {
    let path = entry.unwrap().path();
    if path.is_file() {
      let file_name = path.file_name();
      if let Some(file_name) = file_name {
        if let Some(file_name_str) = file_name.to_str() {
          if file_name_str.ends_with("fullchain.pem"){
            return_cert.set_full_chain(fs::read_to_string(&path).unwrap());
          }
          if file_name_str.eq("privkey.pem") {
            return_cert.set_private_key(fs::read_to_string(&path).unwrap());
          }
          if file_name_str.eq("cert.pem") {
            info!("File: [{:?}]",path);
            let buf = fs::read_to_string(path).unwrap();
            debug!("Found cert.pem: [{:?}]",buf);
            let res = parse_x509_pem(buf.as_bytes());
            match res {
              Ok((_res, pem)) => {
                debug!("Label: [{:?}]",pem.label);
                if pem.label.eq("CERTIFICATE"){
                  let cert = parse_x509_certificate(&pem.contents);
                  match cert {
                    Ok((_cert, parsed_cert)) => {
                      info!("Subject: {}",parsed_cert.subject());
                      return_cert.set_host_name(parse_hostname(&parsed_cert.subject().to_string()));
                      return_cert.set_certificate(buf);
                      // Subject Alternative Name:
                      let oid = oid!(2.5.29.17);
                      let ext = match parsed_cert.get_extension_unique(&oid).unwrap(){
                        Some(ext) => ext,
                        None => {
                          error!("No extension for CERTIFICATE");
                          return return_cert;
                        }
                      };
                      let sub_ext = ext.parsed_extension();
                      match sub_ext {
                        ParsedExtension::SubjectAlternativeName(sub) => {
                          let mut host_names: Vec<String> = Vec::new();
                          for name in sub.general_names.clone() {
                            match name {
                              GeneralName::DNSName(name) => {
                                info!("Name: {}", name);
                                host_names.push(name.to_string());
                              },
                              _ => {

                              }
                            }
                          }
                          return_cert.set_host_names(host_names);
                        },
                        _ => {

                        }
                      };
                    },
                    Err(e) => {
                      error!("Error parsing cert.pem: {}", e);
                    }
                  }
                }
              },
              Err(e) => {
                error!("Error parsing cert.pem: {}", e);
              }
            };
          }
        }
      }
    }
  }
  return_cert
}

fn parse_hostname(in_str: &str) -> String {
 // CN=hostname
  let mut host_name = String::new();
  let mut parts = in_str.split("=");
  if let Some(part) = parts.next() {
    if part.eq("CN") {
      if let Some(part) = parts.next() {
        host_name = part.to_string();
      }
    }
  }
  host_name
}


// Renew is actually requesting a new certificate
// but we get the info from the certificate object itself
pub fn renew_certificate(domain: &String, email: &String, staging: bool){
  if let Some(cert) = find_certificate(domain.clone()) {
    let mut aliases: Vec<String> = Vec::new();
    if cert.host_names.is_some() {
      aliases = cert.host_names.unwrap();
    }
    match request_certificate(domain, email, &aliases, staging){
      Ok(_) => {
        println!("Certificate renewed: {}", domain);
      },
      Err(e) => {
        println!("Error renewing certificate: {}", e);
      }
    }
  } else {
    println!("No such certificate : {}", domain);
  }
}

pub fn request_certificate(domain: &String, email: &String, aliases: &Vec<String>, staging: bool) -> Result<(),Error> {

  let url = if staging {
    DirectoryUrl::LetsEncryptStaging
  } else {
    DirectoryUrl::LetsEncrypt
  };

  let persist = FilePersist::new(acme_path());

  let dir = Directory::from_url(persist, url)?;

  let acc = dir.account(&email)?;
  let v = aliases.iter().map(|s| &s[..]).collect::<Vec<&str>>();
  let mut order_new = acc.new_order(&domain, v.as_slice())?;

  let order_csr = loop {
    if let Some(order_csr) = order_new.confirm_validations(){
      break order_csr;
    }
    let auths = order_new.authorizations()?;
    // For each domain + each aliases we get separate challenge proofs
    for auth in auths {
      let challenge = auth.http_challenge();
      let token = challenge.http_token();
      let proof = challenge.http_proof();
      // write proof to acme-challenge directory
      let acme_challenge_path = acme_challenge_path();
      let proof_path = PathBuf::from(acme_challenge_path).join(token);
      fs::write(&proof_path, proof)?;
      challenge.validate(5000)?;
    }
    order_new.refresh()?;
  };

  let pkey_pri = create_p384_key();

  let order_cert = order_csr.finalize_pkey(pkey_pri,5000)?;

  let cert = order_cert.download_and_save_cert()?;

  le_cert_to_cert_store(cert, domain, aliases);

  Ok(())
}

// Takes Letsencrypt Certificate and stores it in the cert store
fn le_cert_to_cert_store(le_cert: acme_v2::Certificate, domain: &String, aliases: &Vec<String>){
  const BEGIN_MARKER: &str = "-----BEGIN CERTIFICATE-----";
  const END_MARKER: &str = "-----END CERTIFICATE-----";
  let mut certificates = Vec::new();
  let mut start_index = 0;
  let data:String = le_cert.certificate().into();
  while let Some(begin_index) = data[start_index..].find(BEGIN_MARKER) {
    let begin_index = start_index + begin_index;
    if let Some(end_index) = data[begin_index..].find(END_MARKER) {
      let end_index = begin_index + end_index + END_MARKER.len();
      let cert_block = &data[begin_index..end_index];
      certificates.push(cert_block.trim().to_string());
      start_index = end_index;
    } else {
      break;
    }
  }

  let mut new_cert = Certificate::new(domain.clone());
  new_cert.set_private_key(le_cert.private_key().to_string());
  new_cert.set_certificate(certificates[0].clone());
  new_cert.set_full_chain(le_cert.certificate().parse().unwrap());
  new_cert.set_host_names(aliases.clone());

  let cert_dest_path = PathBuf::from(cert_path()).join(new_cert.get_host_name());
  if !cert_dest_path.exists() {
    fs::create_dir(&cert_dest_path).unwrap();
  }
  let cert_dest_file_path = cert_dest_path.join("cert.json");
  fs::write(&cert_dest_file_path, serde_json::to_string_pretty(&new_cert).unwrap()).unwrap();
}


pub fn find_certificate(domain: String) -> Option<Certificate> {
  let cert_path = PathBuf::from(cert_path()).join(domain).join("cert.json");
  if cert_path.exists() {
    let cert = Certificate::from_path(cert_path);
    return Some(cert);
  }
  None
}
