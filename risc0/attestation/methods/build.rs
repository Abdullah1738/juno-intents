fn main() {
    // RISC Zero's default (non-docker) guest build uses the `+risc0` toolchain,
    // which may not run on older Linux distros (e.g. Amazon Linux 2 / glibc 2.26).
    // Allow opting into a Dockerized guest build for CI / AWS runners.
    if std::env::var("JUNO_RISC0_USE_DOCKER").is_ok() {
        use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};
        use std::collections::HashMap;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let root_dir = manifest_dir.join("../../..");
        let docker = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .build()
            .expect("docker options");
        let guest = GuestOptionsBuilder::default()
            .use_docker(docker)
            .build()
            .expect("guest options");

        let mut opts = HashMap::new();
        opts.insert("juno-attestation-guest", guest);
        risc0_build::embed_methods_with_options(opts);
    } else {
        risc0_build::embed_methods();
    }
}
