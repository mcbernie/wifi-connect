use std::env;
use log::{Level, LevelFilter, Record};

use std::io::Write;
use env_logger::{self, fmt::Formatter};

pub fn init() {
    let mut builder = env_logger::builder();

    if env::var("RUST_LOG").is_ok() {
        builder.parse_env(&env::var("RUST_LOG").unwrap());
    } else {
        let format = |mut buf: &mut Formatter, record: &Record| {
            if record.level() == Level::Info {
                writeln!(buf, "{}", record.args())
            } else {
                writeln!(buf, 
                    "[{}:{}] {}",
                    record.module_path().unwrap_or_default(),
                    record.level(),
                    record.args()
                )
            }
        };

        builder.format(format).filter(None, LevelFilter::Info);

        builder.parse_filters("wifi-connect=info,iron::iron=off");
    }

    builder.init();
}
