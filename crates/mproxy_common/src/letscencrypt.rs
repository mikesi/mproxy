use crate::certificates::Certificate;
use crate::{cert_path};
use std::fs;
use std::path::{PathBuf};
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
