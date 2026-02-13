### reqrio is an HTTP request library designed for fast, simple, and convenient HTTP request usage.

* Features: Low copy, high concurrency, low overhead

* Supports TLS fingerprinting, which can be configured via hexadecimal, Ja3, or Ja4 TLS handshake settings (*
  *subscription only**).

* Ensures **request header order** (see [Request Header Order Table](#request-header-order-table)), consistent with
  browsers.

* Uses **BoringSSL** to implement TLS, consistent with browsers like Chrome and Edge.

**Note:** std and cls cannot exist simultaneously, while sync and async can exist simultaneously.

### Request Header Order Table

| No. | HTTP/2.0                    | HTTP/1.1                  |
|:----|:----------------------------|:--------------------------|
| 1   | cache-control               | Host                      |
| 2   | sec-ch-ua                   | Connection                |
| 3   | sec-ch-ua-mobile            | Content-Length            |
| 4   | sec-ch-ua-full-version      | Authorization             |
| 5   | sec-ch-ua-arch              | Content-Type              |
| 6   | sec-ch-ua-platform          | Cache-Control             |
| 7   | sec-ch-ua-platform-version  | sec-ch-ua                 |
| 8   | sec-ch-ua-model             | sec-ch-ua-mobile          |
| 9   | sec-ch-ua-bitness           | sec-ch-ua-platform        |
| 10  | sec-ch-ua-full-version-list | Upgrade-Insecure-Requests |
| 11  | upgrade-insecure-requests   | User-Agent                |
| 12  | user-agent                  | Accept                    |
| 13  | accept                      | Sec-Fetch-Site            |
| 14  | sec-fetch-site              | Sec-Fetch-Mode            |
| 15  | sec-fetch-mode              | Sec-Fetch-User            |
| 16  | sec-fetch-user              | Sec-Fetch-Dest            |
| 17  | sec-fetch-dest              | Sec-Fetch-Storage-Access  |
| 18  | sec-fetch-storage-access    | Referer                   |
| 19  | referer                     | Accept-Encoding           |
| 20  | accept-encoding             | Accept-Language           |
| 21  | accept-language             | Cookie                    |
| 22  | cookie                      | Origin                    |
| 23  | priority                    |                           |
|     | //unknown                   |                           |
| 24  | origin                      |                           |
| 25  | content-encoding            |                           |
| 26  | content-type                |                           |
| 27  | authorization               |                           |
| 28  | content-type                |                           |

### Usage examples:

* Java example

```java
import com.google.gson.Gson;
import org.xllgl2017.*;

void main() throws Exception {
    //Initialization allows you to set the version.
    Reqrio reqrio = new Reqrio(ALPN.HTTP11);
    //Initialize header
    Headers headers = new Headers();
    headers.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    headers.addHeader("Accept-Encoding", "gzip, deflate, br, zstd");
    headers.addHeader("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6");
    headers.addHeader("Cache-Control", "no-cache");
    headers.addHeader("Connection", "keep-alive");
    headers.addHeader("Host", "m.so.com");
    headers.addHeader("Pragma", "no-cache");
    headers.addHeader("Sec-Fetch-Dest", "document");
    headers.addHeader("Sec-Fetch-Mode", "navigate");
    headers.addHeader("Sec-Fetch-Site", "none");
    headers.addHeader("Sec-Fetch-User", "?1");
    headers.addHeader("Upgrade-Insecure-Requests", "1");
    headers.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0");
    headers.addHeader("sec-ch-ua", "\"Microsoft Edge\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"");
    headers.addHeader("sec-ch-ua-mobile", "?0");
    headers.addHeader("sec-ch-ua-platform", "\"Windows\"");
    //You can also add cookies using reqrio.setCookie.
    headers.setCookies("__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1");
    //Set header
    reqrio.setHeaders(headers);
    //Set timeout
    Timeout timeout = new Timeout();
    reqrio.setTimeout(timeout);
    //ask
    Response response = reqrio.get("https://m.so.com");
    IO.println(response.length());
    Headers resp_hdr = response.getHeader();
    Gson gson = new Gson();
    IO.println(gson.toJson(resp_hdr));
}
```