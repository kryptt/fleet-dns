#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kube error: {0}")]
    Kube(#[source] kube::Error),

    #[error("reqwest error: {0}")]
    Reqwest(#[source] reqwest::Error),

    #[error("serde_json error: {0}")]
    SerdeJson(#[source] serde_json::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("opnsense error: {0}")]
    OpnSense(String),

    #[error("cloudflare error: {0}")]
    Cloudflare(String),
}

impl Error {
    /// Short label suitable for Prometheus metric labels.
    #[must_use]
    pub fn metric_label(&self) -> &str {
        match self {
            Error::Kube(_) => "kube",
            Error::Reqwest(_) => "reqwest",
            Error::SerdeJson(_) => "serde_json",
            Error::Config(_) => "config",
            Error::OpnSense(_) => "opnsense",
            Error::Cloudflare(_) => "cloudflare",
        }
    }
}

impl From<kube::Error> for Error {
    fn from(e: kube::Error) -> Self {
        Error::Kube(e)
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::SerdeJson(e)
    }
}
