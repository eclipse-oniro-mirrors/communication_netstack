/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Asynchronous HTTP client example.

use ylong_http_client::async_impl::{Client, Downloader, Uploader};
use ylong_http_client::{Method, Proxy, Redirect, Request, Timeout, TlsVersion};

#[tokio::main]
async fn main() {
    // Customizes your HTTP client.
    let client = Client::builder()
        .http1_only()
        .request_timeout(Timeout::from_secs(9))
        .connect_timeout(Timeout::from_secs(9))
        .max_tls_version(TlsVersion::TLS_1_2)
        .min_tls_version(TlsVersion::TLS_1_2)
        .redirect(Redirect::none())
        .proxy(Proxy::none())
        .build()
        .unwrap();

    // Uses `Uploader` to upload the request body.
    let uploader = Uploader::console("HelloWorld".as_bytes());

    // Customizes your HTTP request.
    let request = Request::builder()
        .method(Method::GET)
        .url("http://www.example.com")
        .header("transfer-encoding", "chunked")
        .build(uploader)
        .unwrap();

    // Sends your HTTP request through the client.
    let response = client.request(request).await.unwrap();

    // Uses `Downloader` to download the response body.
    let _ = Downloader::console(response).download().await;
}