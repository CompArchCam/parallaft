use std::{fs, path::PathBuf};

use itertools::Itertools;

use crate::{error::Result, types::perf_counter::EVENT_SOURCE_DEVICES_ROOT};

pub struct Pmu {
    pub name: PathBuf,
    pub cpus: Vec<usize>,
}

pub fn list_pmus() -> Result<Vec<Pmu>> {
    let mut pmus = Vec::new();

    for dir in fs::read_dir(EVENT_SOURCE_DEVICES_ROOT)? {
        if let Ok(dir) = dir {
            let path = dir.path();
            let cpus_path = path.join("cpus");
            if path.is_dir() && cpus_path.is_file() {
                let name = dir.file_name().into();
                let contents = fs::read_to_string(cpus_path)?;
                let mut cpus: Vec<usize> = contents
                    .trim_end()
                    .split("-")
                    .map(|x| {
                        x.parse::<usize>()
                            .map_err(|_| std::io::Error::other("Failed to parse cpu list"))
                    })
                    .try_collect()?;

                assert!(cpus.len() == 1 || cpus.len() == 2);

                if cpus.len() == 2 {
                    let start = cpus[0];
                    let end = cpus[1];
                    cpus = (start..=end).collect();
                }

                pmus.push(Pmu { name, cpus });
            }
        }
    }

    Ok(pmus)
}
