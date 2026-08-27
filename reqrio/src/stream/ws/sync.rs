use std::pin::Pin;
use std::task::{Context, Poll};
use crate::error::HlsResult;
use crate::ext::ReqPriExt;
use crate::{AcReq, ScReq};
use crate::stream::Stream;

pub struct WebSocketS {
    stream: Stream,
}


impl WebSocketS {
    pub fn from_req(req: ScReq) -> HlsResult<WebSocketS> {
        Ok(WebSocketS {
            stream: req.into_stream()?
        })
    }

    pub fn connect(url: &str) -> WebSocketConnecting {
        WebSocketConnecting {
            url,
            req: async { 
                
            },
        }
    }
}

pub struct WebSocketConnecting<'a, F>
where
    F: Future,
{
    url: &'a str,
    req: F,
}

impl<'a> WebSocketConnecting<'a> {
    pub fn wait(self) -> HlsResult<WebSocketS> {
        let mut req = ScReq::new();
        let resp = req.get(self.url, None)?;
        Ok(WebSocketS {
            stream: req.into_stream()?
        })
    }
}

impl<'a> Future for WebSocketConnecting<'a> {
    type Output = HlsResult<WebSocketS>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {}
}