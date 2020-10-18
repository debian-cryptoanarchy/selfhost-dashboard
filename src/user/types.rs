str_char_whitelist_newtype!(UserName, UserNameError, "user name", |c| c != '_' && c != '-' && (c < 'a' || c > 'z'));

impl UserName {
    pub const ADMIN: UserName<&'static str> = UserName("admin");
}

pub use authenticated::AuthenticatedUser;

mod authenticated {
    pub struct AuthenticatedUser {
        name: super::UserName,
    }

    impl AuthenticatedUser {
        /// Must only be called if it was checked that the user is logged in
        pub fn user_logged_in(name: super::UserName) -> Self {
            AuthenticatedUser {
                name,
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn is_admin(&self) -> bool {
            self.name.as_ref() == crate::user::Name::ADMIN
        }

        pub async fn logout<Db: crate::user::Db>(&self, database: &mut Db) -> Result<(), Db::SetCookieError> {
            let name = self.name.as_ref().into_owned();
            database
                .set_cookie(name, None)
                .await
        }
    }
}

token_newtype!(Salt, 16, SaltError);

impl Salt {
    pub const EMPTY: Salt = Salt([0; 16]);
}

token_newtype!(HardenedPassword, 32, HardenedPasswordError);

impl HardenedPassword {
    pub fn harden(password: &str, salt: &Salt) -> Self {
        let params = scrypt::ScryptParams::recommended();
        let mut output = HardenedPassword([0; 32]);
        scrypt::scrypt(password.as_ref(), &salt.0, &params, &mut output.0)
            // The only possible error is input error, which is impossible
            // because we pass in a constant
            .expect("Failed to run scrypt");

        output
    }
}

// cookie
token_newtype!(AuthToken, 16, AuthTokenError);

#[cfg(test)]
mod tests {
    use super::UserName;

    test_str_val_ok!(simple_user_name, UserName, "foo");
    test_str_val_ok!(admin_user_name, UserName, "admin");
    test_str_val_ok!(underscore_user_name, UserName, "foo_bar");
    test_str_val_ok!(dash_user_name, UserName, "foo-bar");
    test_str_val_err!(space_user_name, UserName, "foo bar");
    test_str_val_err!(space_user_name_begin, UserName, " foo");
    test_str_val_err!(space_user_name_end, UserName, "foo ");
    test_str_val_err!(dot_user_name, UserName, "foo.bar");
    test_str_val_err!(at_user_name, UserName, "foo@bar");
    test_str_val_err!(slash_user_name, UserName, "foo/bar");
}
