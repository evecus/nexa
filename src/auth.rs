//! 简单的用户名/密码 + JWT token 认证。

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use subtle::ConstantTimeEq;

const CRED_FILE: &str = "/etc/nexa/cred.json";
const TOKEN_TTL_SECONDS: i64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credentials {
    username: String,
    hash: String, // bcrypt
    #[serde(default)]
    auth_disabled: bool, // true 时跳过登录校验，允许无验证访问
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub struct Auth {
    cred: Mutex<Credentials>,
}

impl Auth {
    pub fn new() -> Self {
        let auth = Auth {
            cred: Mutex::new(Credentials {
                username: String::new(),
                hash: String::new(),
                auth_disabled: false,
            }),
        };
        auth.load();
        auth
    }

    fn load(&self) {
        let mut cred = self.cred.lock().unwrap();
        match fs::read(CRED_FILE) {
            Ok(data) => {
                if let Ok(c) = serde_json::from_slice::<Credentials>(&data) {
                    *cred = c;
                    return;
                }
            }
            Err(_) => {
                // 首次：默认 admin/admin
                let hash =
                    bcrypt::hash("admin", bcrypt::DEFAULT_COST).unwrap_or_default();
                *cred = Credentials {
                    username: "admin".to_string(),
                    hash,
                    auth_disabled: false,
                };
                self.save_locked(&cred);
            }
        }
    }

    fn save_locked(&self, cred: &Credentials) {
        if let Ok(data) = serde_json::to_vec(cred) {
            let _ = fs::write(CRED_FILE, data);
            // 设置文件权限 0600
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(CRED_FILE, fs::Permissions::from_mode(0o600));
            }
        }
    }

    /// Login 校验用户名密码，返回 JWT。
    pub fn login(&self, user: &str, pass: &str) -> Result<String> {
        let cred = self.cred.lock().unwrap().clone();
        // 常量时间比较用户名
        let user_ok = user.as_bytes().ct_eq(cred.username.as_bytes()).unwrap_u8();
        if user_ok == 0 {
            return Err(anyhow!("invalid credentials"));
        }
        if bcrypt::verify(pass, &cred.hash).unwrap_or(false) {
            let exp = (Utc::now() + Duration::seconds(TOKEN_TTL_SECONDS)).timestamp() as usize;
            let claims = Claims {
                sub: user.to_string(),
                exp,
            };
            let token = encode(&Header::default(), &claims, &encoding_key())?;
            Ok(token)
        } else {
            Err(anyhow!("invalid credentials"))
        }
    }

    /// Verify 校验 token。
    pub fn verify(token_str: &str) -> bool {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        match decode::<Claims>(token_str, &decoding_key(), &validation) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// ChangePassword 修改用户名/密码。
    pub fn change_password(&self, user: &str, pass: &str) -> Result<()> {
        let hash = bcrypt::hash(pass, bcrypt::DEFAULT_COST)?;
        let mut cred = self.cred.lock().unwrap();
        cred.username = user.to_string();
        cred.hash = hash;
        self.save_locked(&cred);
        Ok(())
    }

    /// SetAuthDisabled 打开/关闭"无验证访问"总开关，持久化到凭据文件。
    pub fn set_auth_disabled(&self, disabled: bool) {
        let mut cred = self.cred.lock().unwrap();
        cred.auth_disabled = disabled;
        self.save_locked(&cred);
    }

    /// IsAuthDisabled 返回当前是否处于"无验证访问"状态。
    pub fn is_auth_disabled(&self) -> bool {
        self.cred.lock().unwrap().auth_disabled
    }
}

fn encoding_key() -> EncodingKey {
    EncodingKey::from_secret(sign_key().as_bytes())
}

fn decoding_key() -> DecodingKey {
    DecodingKey::from_secret(sign_key().as_bytes())
}

fn sign_key() -> &'static str {
    "nexa-default-secret-change-me"
}

/// 校验 Authorization: Bearer <token>。返回是否放行。
pub fn extract_and_verify(authz: Option<&str>) -> bool {
    if let Some(v) = authz {
        if let Some(rest) = v.strip_prefix("Bearer ") {
            return Auth::verify(rest);
        }
    }
    false
}
