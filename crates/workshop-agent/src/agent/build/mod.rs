#[cfg(all(feature = "exe", feature = "http_winhttp"))]
pub mod exe;

#[cfg(all(feature = "dll", feature = "exe", feature = "http_winhttp"))]
pub mod dll;
