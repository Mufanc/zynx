use log::LevelFilter;

mod injector;
mod zygote;

fn init_logger() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(if cfg!(debug_assertions) {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            })
            .with_tag("zynx::bridge"),
    );
}
