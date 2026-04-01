use crate::error::HlsError;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub enum Text {
    Css,
    Html,
    Plain,
    JavaScript,
    EventStream,
    Xml,
    XComponent,
    Json,
}

impl Text {
    pub fn spec(&self) -> &str {
        match self {
            Text::Css => "text/css",
            Text::Html => "text/html",
            Text::Plain => "text/plain",
            Text::JavaScript => "text/javascript",
            Text::EventStream => "text/event-stream",
            Text::Xml => "text/xml",
            Text::XComponent => "text/x-component",
            Text::Json => "text/json"
        }
    }
}

impl Display for Text {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}

impl TryFrom<&str> for Text {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "plain" => Ok(Text::Plain),
            "html" => Ok(Text::Html),
            "css" => Ok(Text::Css),
            "javascript" => Ok(Text::JavaScript),
            "event-stream" => Ok(Text::EventStream),
            "xml" => Ok(Text::Xml),
            "x-component" => Ok(Text::XComponent),
            "json" => Ok(Text::Json),
            _ => Err(format!("invalid text type {} ", value).into()),
        }
    }
}