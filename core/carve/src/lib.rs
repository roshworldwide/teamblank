pub mod report;
pub mod bifragment;
pub mod carve;
pub mod confidence;
pub mod signature;
pub mod structure;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Jpeg,
    Png,
    Pdf,
    Zip,
    Sqlite,
    Mp4,
    Gzip,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Jpeg => "JPEG",
            Kind::Png => "PNG",
            Kind::Pdf => "PDF",
            Kind::Zip => "ZIP",
            Kind::Sqlite => "SQLITE",
            Kind::Mp4 => "MP4",
            Kind::Gzip => "GZIP",
        }
    }
}

impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
