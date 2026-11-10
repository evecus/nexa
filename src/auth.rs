//! 用户名/密码 + JWT token 认证，对齐 Go 版 internal/auth。
//! 凭据与「无验证访问」开关持久化在数据库 auth 表（对齐 Go bbolt bucketAuth）。

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::store::{Credentials, Store};

const JWT_SECRET: &[u8] = b"nexa-default-secret-change-me";
/// token 有效期 24 小时（对齐 Go 版 tokenTTL）。
const TOKEN_TTL_SECS: usize = 24 * 3600;
const DEFAULT_USER: &str = "admin";
const DEFAULT_PASS: &str = "admin";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub struct AuthState {
    store: Arc<Store>,
    inner: RwLock<Credentials>,
}

impl AuthState {
    pub fn new(store: Arc<Store>) -> anyhow::Result<Self> {
        // 对齐 Go Auth.load：
        //  - 数据库无凭据（首次运行）：默认 admin/admin 并写入数据库；
        //  - 读取失败：使用默认凭据但「不回写」，避免覆盖已存数据，且不阻止启动。
        let auth = match store.load_auth() {
            Ok(Some(c)) => c,
            Ok(None) => {
                let c = default_auth()?;
                if let Err(e) = store.save_auth(&c) {
                    tracing::warn!("auth: 凭据写入数据库失败：{}", e);
                }
                c
            }
            Err(e) => {
                tracing::warn!("auth: 读取凭据失败：{}，本次使用默认凭据", e);
                default_auth()?
            }
        };
        Ok(Self {
            store,
            inner: RwLock::new(auth),
        })
    }

    fn persist(&self) -> anyhow::Result<()> {
        let c = self.inner.read().clone();
        self.store.save_auth(&c)
    }

    pub fn login(&self, username: &str, password: &str) -> anyhow::Result<String> {
        {
            let a = self.inner.read();
            if a.username != username {
                anyhow::bail!("invalid credentials");
            }
            if !bcrypt::verify(password, &a.hash)? {
                anyhow::bail!("invalid credentials");
            }
        }
        self.issue_token(username)
    }

    pub fn issue_token(&self, username: &str) -> anyhow::Result<String> {
        let exp = now_secs() + TOKEN_TTL_SECS;
        let claims = Claims {
            sub: username.to_string(),
            exp,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET),
        )?;
        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> anyhow::Result<Claims> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        )?;
        Ok(data.claims)
    }

    pub fn is_auth_disabled(&self) -> bool {
        self.inner.read().auth_disabled
    }

    pub fn set_auth_disabled(&self, v: bool) -> anyhow::Result<()> {
        self.inner.write().auth_disabled = v;
        self.persist()
    }

    pub fn username(&self) -> String {
        self.inner.read().username.clone()
    }

    /// 修改用户名/密码（对齐 Go 版 ChangePassword：用户名与密码一起覆盖）。
    pub fn change_password(&self, user: &str, new_pass: &str) -> anyhow::Result<()> {
        if user.is_empty() || new_pass.is_empty() {
            anyhow::bail!("用户名和密码不能为空");
        }
        let hash = bcrypt::hash(new_pass, bcrypt::DEFAULT_COST)?;
        {
            let mut a = self.inner.write();
            a.username = user.to_string();
            a.hash = hash;
        }
        self.persist()
    }
}

fn default_auth() -> anyhow::Result<Credentials> {
    let hash = bcrypt::hash(DEFAULT_PASS, bcrypt::DEFAULT_COST)?;
    Ok(Credentials {
        username: DEFAULT_USER.to_string(),
        hash,
        auth_disabled: false,
    })
}

fn now_secs() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize
}
