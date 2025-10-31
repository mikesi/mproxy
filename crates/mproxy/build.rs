use chrono;

fn main() {
      println!("cargo:rustc-env=BUILD_DATE={}", chrono::Utc::now().to_rfc3339());
}

