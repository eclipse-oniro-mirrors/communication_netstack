// Copyright (C) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub enum Data<'local> {
    S(String),
    ArrayBuffer(&'local [u8]),
}

#[ani_rs::ani(path = "L@ohos/net/networkSecurity/networkSecurity/CertType")]
pub enum CertType {
    CertTypePem = 0,

    CertTypeDer = 1,
}

#[ani_rs::ani(path = "L@ohos/net/networkSecurity/networkSecurity/CertBlob")]
pub struct CertBlob<'local> {
    pub type_: CertType,
    #[serde(borrow)]
    pub data: Data<'local>,
}
