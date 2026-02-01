use crate::error::HlsError;
use std::fmt::Display;

#[derive(Clone, PartialEq)]
pub struct HttpStatus(u16);


#[allow(non_upper_case_globals)]
impl HttpStatus {
    pub const None: HttpStatus = HttpStatus(0);
    pub const Continue: HttpStatus = HttpStatus(100);
    pub const SwitchingProtocols: HttpStatus = HttpStatus(101);
    pub const OK: HttpStatus = HttpStatus(200);
    pub const Created: HttpStatus = HttpStatus(201);
    pub const Accepted: HttpStatus = HttpStatus(202);
    pub const NoContent: HttpStatus = HttpStatus(204);
    pub const PartialContent: HttpStatus = HttpStatus(206);
    pub const Move: HttpStatus = HttpStatus(301);
    pub const Found: HttpStatus = HttpStatus(302);
    pub const NotModified: HttpStatus = HttpStatus(304);
    pub const TemporaryRedirect: HttpStatus = HttpStatus(307);
    pub const PermanentRedirect: HttpStatus = HttpStatus(308);
    pub const BadRequest: HttpStatus = HttpStatus(400);
    pub const Unauthorized: HttpStatus = HttpStatus(401);
    pub const Forbidden: HttpStatus = HttpStatus(403);
    pub const NotFound: HttpStatus = HttpStatus(404);
    pub const PreconditionFailed: HttpStatus = HttpStatus(412);
    pub const ReqTooLarge: HttpStatus = HttpStatus(413);
    pub const Teapot: HttpStatus = HttpStatus(418);
    pub const TooManyRequests: HttpStatus = HttpStatus(429);
    pub const ServerError: HttpStatus = HttpStatus(500);
    pub const BadGateway: HttpStatus = HttpStatus(502);
    pub const ServiceUnavailable: HttpStatus = HttpStatus(503);
    pub const GatewayTimeOut: HttpStatus = HttpStatus(504);
    pub const ReceiveTimeOut: HttpStatus = HttpStatus(524);
}

impl HttpStatus {
    pub fn code(&self) -> u16 { self.0 }

    pub fn spec(&self) -> &'static str {
        match self.0 {
            0 => "None",
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "Ok",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            206 => "Partial Content",
            301 => "Move",
            302 => "Found",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            412 => "Precondition Failed",
            413 => "Req Too Large",
            418 => "Teapot",
            429 => "Too Many Requests",
            500 => "Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Time Out",
            524 => "Receive Time Out",
            _ => "Unknown"
        }
    }
}

impl TryFrom<i32> for HttpStatus {
    type Error = HlsError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(HttpStatus::Continue),
            101 => Ok(HttpStatus::SwitchingProtocols),
            200 => Ok(HttpStatus::OK),
            201 => Ok(HttpStatus::Created),
            202 => Ok(HttpStatus::Accepted),
            204 => Ok(HttpStatus::NoContent),
            206 => Ok(HttpStatus::PartialContent),
            301 => Ok(HttpStatus::Move),
            302 => Ok(HttpStatus::Found),
            304 => Ok(HttpStatus::NotModified),
            307 => Ok(HttpStatus::TemporaryRedirect),
            308 => Ok(HttpStatus::PermanentRedirect),
            400 => Ok(HttpStatus::BadRequest),
            401 => Ok(HttpStatus::Unauthorized),
            403 => Ok(HttpStatus::Forbidden),
            404 => Ok(HttpStatus::NotFound),
            412 => Ok(HttpStatus::PreconditionFailed),
            413 => Ok(HttpStatus::ReqTooLarge),
            418 => Ok(HttpStatus::Teapot),
            429 => Ok(HttpStatus::TooManyRequests),
            500 => Ok(HttpStatus::ServerError),
            502 => Ok(HttpStatus::BadGateway),
            504 => Ok(HttpStatus::GatewayTimeOut),
            503 => Ok(HttpStatus::ServiceUnavailable),
            524 => Ok(HttpStatus::ReceiveTimeOut),
            _ => Err(format!("Invalid HTTP status: {}", value).into()),
        }
    }
}

impl Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.spec(), self.code())
    }
}