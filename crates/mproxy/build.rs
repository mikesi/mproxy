use chrono;

fn main() {
      let profile = std::env::var("PROFILE").unwrap();
      println!("cargo:rustc-env=BUILD_DATE={}", chrono::Utc::now().to_rfc3339());
      println!("cargo:rustc-env=PROFILE={profile}");
}

